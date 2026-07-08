"""G3 real-infrastructure fidelity for the NETWORK-ISOLATION side of
s1_rbac_secret_lateral on a real kind+Cilium cluster.

This is the third real-infrastructure fidelity domain (after real AWS IAM/serverless
and real-K8s RBAC control plane). It validates the `missing_networkpolicy` /
`t_lateral` transition as an *end-to-end attack chain* through the data path, not just
an enforcement microbenchmark: an attacker foothold pod performs a lateral TCP hop to a
synthetic datastore pod and exfiltrates over HTTP, and a default-deny NetworkPolicy is
shown to break that chain on real infrastructure exactly where the emulator breaks it
when `missing_networkpolicy` is remediated.

  transition-level agreement : the emulator's lateral+exfil milestones fire as real
                               pod-to-pod network steps on the cluster
  reachability gap           : |emulator stage-reachability - real stage-reachability|
  defense fidelity           : applying the default-deny NetworkPolicy breaks the real
                               chain at the lateral hop, matching the emulator with
                               `missing_networkpolicy` disabled
  enforcement verified       : the block is real CNI enforcement (the same body is
                               reachable before the policy and unreachable after)

Real chain (run by exec-ing into the foothold pod):
  1. lateral : TCP+HTTP reach datastore-svc:8080 (no NetworkPolicy) -> reachable
  2. exfil   : HTTP GET returns the synthetic billing body           -> goal

Safety: synthetic data only, read-only HTTP exfil, ephemeral kind cluster, teardown at
end. Requires kubectl pointed at a THROWAWAY kind+Cilium cluster.
Usage:
    python k8s/fidelity/measure_netpol_fidelity.py --cluster "kind v1.36" --cni "cilium 1.16.3"
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))
HERE = Path(__file__).resolve().parent
MANIFESTS = HERE / "netpol_manifests.yaml"
DENY = HERE / "netpol_deny.yaml"
SVC = "http://datastore-svc.cnab-net-data:8080"


def _kubectl(*args, check: bool = False, timeout: int = 60):
    return subprocess.run(["kubectl", *args], text=True, capture_output=True,
                          check=check, timeout=timeout)


def _exec_foothold(shell_cmd: str, timeout: int = 20) -> subprocess.CompletedProcess:
    """Run a shell command inside the attacker foothold pod."""
    return _kubectl("exec", "-n", "cnab-net-app", "foothold", "--",
                    "sh", "-c", shell_cmd, timeout=timeout)


def _classify_failure(rc: int, err: str) -> str:
    s = err.lower()
    if "timed out" in s or "timeout" in s or rc == 124:
        return "Timeout(NetworkPolicy)"
    if "refused" in s:
        return "ConnRefused"
    if "bad address" in s or "no such host" in s or "resolve" in s:
        return "DNSFail"
    return "Blocked" if rc != 0 else "None"


def run_chain() -> dict:
    """Execute the real 2-step network chain from the foothold pod."""
    steps = []

    # 1. lateral: does a TCP+HTTP HEAD to the datastore succeed? (missing_networkpolicy)
    r1 = _exec_foothold(f"wget -q -T 4 --spider {SVC}")
    lateral_ok = r1.returncode == 0
    steps.append({"milestone": "lateral", "fired": lateral_ok,
                  "observation": "datastore reachable over pod network" if lateral_ok else "",
                  "failure": None if lateral_ok else _classify_failure(r1.returncode, r1.stderr)})

    # 2. exfil: HTTP GET the synthetic billing body over that same hop (goal)
    exfil_ok = False
    body = ""
    if lateral_ok:
        r2 = _exec_foothold(f"wget -q -T 4 -O - {SVC}")
        body = r2.stdout.strip()
        exfil_ok = body.startswith("SYNTHETIC-CNAB-FIXTURE")
    steps.append({"milestone": "exfil", "fired": exfil_ok,
                  "observation": "synthetic billing data read" if exfil_ok else "",
                  "failure": None if exfil_ok else "PrecededByBlockedLateral"})
    return {"steps": steps, "reached": sum(1 for s in steps if s["fired"]),
            "total": len(steps), "goal": steps[-1]["fired"]}


def emulator_baseline() -> dict:
    """Emulator s1 with and without the missing_networkpolicy misconfig."""
    from cnab.agents import make_reference_agent
    from cnab.runner import run_single
    from cnab import scenario as scenario_mod
    sc = scenario_mod.load_file(str(REPO / "scenarios" / "s1_rbac_secret_lateral.yaml"))
    base = run_single(sc, make_reference_agent("C2", seed=0), budget=32, seed=0)
    defended = run_single(sc, make_reference_agent("C2", seed=0), budget=32, seed=0,
                          disabled_misconfigs=frozenset({"missing_networkpolicy"}))
    return {"stage_reachability": base.record.stage_reachability,
            "goal": base.record.goal_reached,
            "defended_goal": defended.record.goal_reached,
            "milestones": len(sc.milestones)}


def _wait_pods_ready() -> None:
    for ns, pod in (("cnab-net-data", "datastore"), ("cnab-net-app", "foothold")):
        r = _kubectl("wait", "-n", ns, f"pod/{pod}", "--for=condition=Ready",
                     "--timeout=120s")
        if r.returncode != 0:
            _teardown()
            sys.exit(f"pod {ns}/{pod} not Ready: {r.stderr.strip()}")


def _teardown() -> None:
    _kubectl("delete", "-f", str(DENY), "--ignore-not-found", "--wait=false")
    _kubectl("delete", "-f", str(MANIFESTS), "--ignore-not-found", "--wait=false")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cluster", default="unspecified", help="provenance note")
    ap.add_argument("--cni", default="cilium", help="CNI provenance note")
    ap.add_argument("--out", default=str(REPO / "results" / "k8s_netpol_fidelity_s1.json"))
    args = ap.parse_args()

    try:
        _kubectl("version", "-o", "json", check=True)
    except Exception as exc:  # noqa
        sys.exit(f"kubectl cannot reach the cluster: {exc}")

    # Emulator reference is cluster-free; compute before apply to fail fast.
    emu = emulator_baseline()

    print("[apply] netpol fidelity fixture ...")
    _kubectl("apply", "-f", str(MANIFESTS), check=True)
    try:
        _wait_pods_ready()

        # --- attack succeeds with missing_networkpolicy (no default-deny) ---
        attack = run_chain()

        # --- defense fidelity + enforcement proof: apply default-deny, re-run ---
        print("[apply] default-deny NetworkPolicy ...")
        _kubectl("apply", "-f", str(DENY), check=True)
        time.sleep(6)   # let the CNI program the policy
        defended = run_chain()
    finally:
        _teardown()

    real_reach = attack["reached"] / attack["total"]
    reach_gap = round(abs(emu["stage_reachability"] - real_reach), 4)
    transition_agreement = round(
        sum(1 for s in attack["steps"] if s["fired"]) / attack["total"], 4)
    defense_breaks = not defended["goal"]
    break_point = next((s["milestone"] for s in defended["steps"] if not s["fired"]), None)
    # enforcement is real iff the identical GET was reachable before and blocked after
    enforcement_verified = attack["goal"] and not defended["goal"] and \
        defended["steps"][0]["fired"] is False

    report = {
        "scenario": "s1_rbac_secret_lateral",
        "aspect": "network_isolation (missing_networkpolicy / t_lateral)",
        "cluster": args.cluster,
        "cni": args.cni,
        "emulator": {"stage_reachability": emu["stage_reachability"],
                     "goal": emu["goal"],
                     "goal_with_networkpolicy": emu["defended_goal"]},
        "real": {"stage_reachability": round(real_reach, 4),
                 "goal": attack["goal"], "steps": attack["steps"]},
        "transition_level_agreement": transition_agreement,
        "reach_gap": reach_gap,
        "failure_mode_taxonomy": [{"milestone": s["milestone"], "mode": s["failure"]}
                                  for s in attack["steps"] if s["failure"]] or "none (full chain fired)",
        "defense_fidelity": {
            "remediation": "default-deny ingress NetworkPolicy (missing_networkpolicy)",
            "real_goal_after_policy": defended["goal"],
            "chain_breaks_like_emulator": defense_breaks and (emu["defended_goal"] is False),
            "break_point": break_point,
            "break_mode": next((s["failure"] for s in defended["steps"] if not s["fired"]), None),
        },
        "enforcement_verified": bool(enforcement_verified),
    }
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n[saved] {args.out}")


if __name__ == "__main__":
    main()

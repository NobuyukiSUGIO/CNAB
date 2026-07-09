"""Multi-family real-LLM ladder (design-doc 5.3: multi-generation/multi-family real LLM).

Sweeps local LLMs across FAMILIES at matched active-parameter points, over a hard
scenario subset, at T=0 and T>0 with K reps, and reports the metrics the review asked
for: pass@k, pass-all@k, stage reachability (mean/std), ASR, tool-call error rate,
wasted actions, and tokens.

Scope (honest): this is a multi-FAMILY, open-weights, quantized comparison run on one
machine, not a multi-VENDOR frontier (Claude/GPT/Gemini) study, which needs API access
and is future work. Results are logged with the resolved model id, prompt_digest, and
run date, and are NOT part of `make repro` (provider/runtime nondeterminism); the
deterministic reference agents remain the reproducible yardstick.

Config: ladder_models.json -> {"models": [{"key","family","active_b","total_b","gen","arch"}, ...]}
Example:
  python run_multifamily_ladder.py --config ladder_models.json \
      --scaffold minimal --budget 20 --seeds 0,1,2,3,4 --temps 0.0,0.7 \
      --scenarios s1_rbac_secret_lateral,s2_imds_iam_pivot,s4_privpod_node_escape,\
s14_privinit_node_escape,s16_gcp_sa_impersonation,s10_hostnet_imds_pivot
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import time
from pathlib import Path

from cnab import scenario as scenario_mod
from cnab.agents.lmstudio import LMStudioAgent, resolve_model, prompt_digest
from cnab.runner import health_check, run_single

ROOT = Path(__file__).resolve().parent
SCENARIO_DIR = ROOT / "scenarios"
# 判別力のある hard サブセット（多段 L3/L4 連鎖）。s2 は最難（double-pivot）。
DEFAULT_HARD = [
    "s1_rbac_secret_lateral", "s2_imds_iam_pivot", "s4_privpod_node_escape",
    "s10_hostnet_imds_pivot", "s14_privinit_node_escape", "s16_gcp_sa_impersonation",
]


def _mean(xs):
    return round(statistics.fmean(xs), 4) if xs else 0.0


def _std(xs):
    return round(statistics.pstdev(xs), 4) if len(xs) > 1 else 0.0


def _lms(*args: str, timeout: int = 1200) -> subprocess.CompletedProcess:
    return subprocess.run(["lms", *args], capture_output=True, text=True, timeout=timeout)


def load_model(key: str, ctx: int, gpu: str = "max", parallel: int = 1) -> None:
    _lms("unload", "--all", timeout=120)
    cp = _lms("load", key, "--gpu", gpu, "-c", str(ctx), "--parallel", str(parallel), "-y")
    if cp.returncode != 0:
        raise RuntimeError(f"load failed {key}: {cp.stderr[-600:] or cp.stdout[-600:]}")


def eval_model(meta: dict, scenarios, *, scaffold, budget, seeds, temps, base_url) -> list[dict]:
    """1 モデルを (temp × scenario × seed) で評価し、temp ごとの集計行を返す。"""
    model_id = resolve_model(base_url)
    rows = []
    for temp in temps:
        per_scn = []
        for s in scenarios:
            goals, reaches, steps, toks, wasted, tcer = [], [], [], [], [], []
            for seed in seeds:
                ag = LMStudioAgent(model=model_id, base_url=base_url, seed=seed,
                                   temperature=temp, scaffold=scaffold)
                res = run_single(s, ag, budget=budget, seed=seed)
                r = res.record
                goals.append(1.0 if r.goal_reached else 0.0)
                reaches.append(r.stage_reachability)
                steps.append(r.steps_used)
                toks.append(r.tokens_used)
                wasted.append(r.wasted_actions)
                tcer.append(ag.tool_call_error_rate)
            per_scn.append({
                "scenario": s.id,
                "pass_at_k": 1.0 if any(g > 0 for g in goals) else 0.0,
                "pass_all_at_k": 1.0 if all(g > 0 for g in goals) else 0.0,
                "asr_mean": _mean(goals),
                "reach_mean": _mean(reaches), "reach_std": _std(reaches),
                "steps_mean": _mean(steps), "tokens_mean": _mean(toks),
                "wasted_mean": _mean(wasted), "tool_call_error_rate": _mean(tcer),
                "goals_per_seed": goals,
            })
        agg = {
            **meta, "temperature": temp, "model_id": model_id, "scaffold": scaffold,
            "k_seeds": len(seeds), "n_scenarios": len(scenarios),
            "pass_at_k": _mean([p["pass_at_k"] for p in per_scn]),
            "pass_all_at_k": _mean([p["pass_all_at_k"] for p in per_scn]),
            "asr_mean": _mean([p["asr_mean"] for p in per_scn]),
            "reach_mean": _mean([p["reach_mean"] for p in per_scn]),
            "tool_call_error_rate": _mean([p["tool_call_error_rate"] for p in per_scn]),
            "wasted_mean": _mean([p["wasted_mean"] for p in per_scn]),
            "tokens_mean": _mean([p["tokens_mean"] for p in per_scn]),
            "per_scenario": per_scn,
        }
        rows.append(agg)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "ladder_models.json"))
    ap.add_argument("--scaffold", default="minimal", choices=["full", "interface", "minimal"])
    ap.add_argument("--budget", type=int, default=20)
    ap.add_argument("--seeds", default="0,1,2,3,4")
    ap.add_argument("--temps", default="0.0,0.7")
    ap.add_argument("--scenarios", default=",".join(DEFAULT_HARD),
                    help="hard サブセット（既定: 多段 L3/L4）")
    ap.add_argument("--ctx", type=int, default=16384)
    ap.add_argument("--gpu", default="max")
    ap.add_argument("--base-url", default="http://localhost:1234/v1")
    ap.add_argument("--date", default="unspecified", help="実行日（来歴記録用, 例 2026-07-09）")
    ap.add_argument("--out", default=str(ROOT / "results" / "multifamily_ladder.json"))
    args = ap.parse_args()

    seeds = [int(x) for x in args.seeds.split(",") if x.strip()]
    temps = [float(x) for x in args.temps.split(",") if x.strip()]
    want = [x.strip() for x in args.scenarios.split(",") if x.strip()]
    all_scn = {s.id: s for s in scenario_mod.load_dir(str(SCENARIO_DIR))}
    missing = [x for x in want if x not in all_scn]
    if missing:
        raise SystemExit(f"unknown scenarios: {missing}")
    scenarios = [all_scn[x] for x in want]
    for s in scenarios:
        problems = health_check(s)
        if problems:
            raise SystemExit(f"scenario unhealthy {s.id}: {problems}")

    cfg = json.loads(Path(args.config).read_text())
    models = cfg["models"]

    all_rows = []
    for meta in models:
        key = meta["key"]
        print(f"\n=== loading {key} (active={meta.get('active_b')}B/{meta.get('total_b')}B "
              f"{meta.get('family')} {meta.get('arch')}) ===", flush=True)
        load_model(key, ctx=args.ctx, gpu=args.gpu)
        t0 = time.time()
        rows = eval_model(meta, scenarios, scaffold=args.scaffold, budget=args.budget,
                          seeds=seeds, temps=temps, base_url=args.base_url)
        all_rows.extend(rows)
        for row in rows:
            print("  T=%.1f  pass@k=%.2f pass-all@k=%.2f reach=%.3f ASR=%.2f "
                  "tool-err=%.3f wasted=%.1f tok=%.0f  (%.0fs)" % (
                      row["temperature"], row["pass_at_k"], row["pass_all_at_k"],
                      row["reach_mean"], row["asr_mean"], row["tool_call_error_rate"],
                      row["wasted_mean"], row["tokens_mean"], time.time() - t0), flush=True)

    report = {
        "provenance": {
            "kind": "multi-family local open-weights (NOT multi-vendor frontier)",
            "runtime": "LM Studio (llama.cpp)", "date": args.date,
            "scaffold": args.scaffold, "budget": args.budget,
            "seeds": seeds, "temperatures": temps,
            "scenarios": want, "prompt_digest": prompt_digest(args.scaffold),
            "note": "not part of make repro; deterministic reference agents are the reproducible yardstick",
        },
        "rows": all_rows,
    }
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2))

    # 昇順 active-param の階段テーブル（temp ごと）
    for temp in temps:
        print(f"\n===== MULTI-FAMILY LADDER  T={temp}  scaffold={args.scaffold} "
              f"budget={args.budget} K={len(seeds)} =====")
        print("%-22s %-6s %-5s %-4s %-8s %-11s %-6s %-8s %-7s" % (
            "model", "family", "act", "gen", "pass@k", "pass-all@k", "reach",
            "tool-err", "wasted"))
        rows_t = sorted([r for r in all_rows if r["temperature"] == temp],
                        key=lambda r: (r.get("active_b", 0), r.get("total_b", 0)))
        for r in rows_t:
            print("%-22s %-6s %-5s %-4s %-8.2f %-11.2f %-6.3f %-8.3f %-7.1f" % (
                r["key"].split("/")[-1], r.get("family", "?"),
                f"{r.get('active_b','?')}B", r.get("gen", "?"),
                r["pass_at_k"], r["pass_all_at_k"], r["reach_mean"],
                r["tool_call_error_rate"], r["wasted_mean"]))
    print(f"\n[saved] {args.out}")


if __name__ == "__main__":
    main()

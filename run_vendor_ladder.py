"""Multi-vendor frontier real-LLM ladder (review concern 2/6: Claude / GPT / Gemini).

Evaluates hosted frontier models through the *identical* interface and metrics as the
local open-weights ladder (run_multifamily_ladder.py). Because GPT, Gemini, and Claude
all expose OpenAI-compatible chat.completions endpoints, every vendor runs on the same
LMStudioAgent code path (same token accounting, tool-call-error classification,
transcript, and scaffold) via cnab.agents.vendors.build_vendor_agent -- so vendor
results are directly comparable to the local ladder and to each other.

Security / reproducibility:
  - API keys are read from env vars only (OPENAI_API_KEY / ANTHROPIC_API_KEY /
    GEMINI_API_KEY). No secrets on disk. Models whose key is unset are skipped.
  - The CNAB environment is fully offline, synthetic, opaque-token; the only external
    call is the LLM asking for the next action. No real exploit or I/O.
  - Results are NOT part of `make repro` (provider/runtime nondeterminism); the
    deterministic reference agents remain the reproducible yardstick.

Config: vendor_models.json -> {"models":[{"provider","model","key","family","label"}, ...]}
Example:
  export ANTHROPIC_API_KEY=...   # and/or OPENAI_API_KEY / GEMINI_API_KEY
  python run_vendor_ladder.py --config vendor_models.json \
      --scaffold minimal --budget 20 --seeds 0,1,2,3,4 --temps 0.0,0.7 \
      --date 2026-07-15 --out results/VENDOR_LADDER.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from cnab import scenario as scenario_mod
from cnab.agents.lmstudio import prompt_digest
from cnab.agents.vendors import PROVIDERS, build_vendor_agent, has_api_key
from cnab.runner import health_check, run_single

ROOT = Path(__file__).resolve().parent
SCENARIO_DIR = ROOT / "scenarios"
DEFAULT_HARD = [
    "s1_rbac_secret_lateral", "s2_imds_iam_pivot", "s4_privpod_node_escape",
    "s10_hostnet_imds_pivot", "s14_privinit_node_escape", "s16_gcp_sa_impersonation",
]


def _mean(xs):
    return round(statistics.fmean(xs), 4) if xs else 0.0


def _std(xs):
    return round(statistics.pstdev(xs), 4) if len(xs) > 1 else 0.0


def eval_vendor_model(meta: dict, scenarios, *, scaffold, budget, seeds, temps,
                      max_tokens: int, dump_sink: list | None = None) -> list[dict]:
    """1 ベンダ・モデルを (temp × scenario × seed) で評価し temp ごとの集計行を返す。

    dump_sink を渡すと、最初の (temp, scenario, seed) の生 transcript（観測→応答→
    選んだ行動→トークン）を1件だけ追記する（reach=0 等の切り分け用）。
    """
    provider, model = meta["provider"], meta["model"]
    rows = []
    for temp in temps:
        per_scn = []
        for s in scenarios:
            goals, reaches, steps, toks, wasted, tcer = [], [], [], [], [], []
            for seed in seeds:
                ag = build_vendor_agent(provider, model, seed=seed, temperature=temp,
                                        scaffold=scaffold, max_tokens=max_tokens,
                                        config_id=f"LLM-{provider}")
                res = run_single(s, ag, budget=budget, seed=seed)
                if dump_sink is not None and not dump_sink:
                    dump_sink.append({
                        "provider": provider, "model": model, "scenario": s.id,
                        "temperature": temp, "seed": seed, "scaffold": scaffold,
                        "goal_reached": res.record.goal_reached,
                        "stage_reachability": res.record.stage_reachability,
                        "transcript": ag.transcript,
                    })
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
        rows.append({
            **{k: meta.get(k) for k in ("provider", "model", "key", "family", "label")},
            "temperature": temp, "scaffold": scaffold,
            "k_seeds": len(seeds), "n_scenarios": len(scenarios),
            "pass_at_k": _mean([p["pass_at_k"] for p in per_scn]),
            "pass_all_at_k": _mean([p["pass_all_at_k"] for p in per_scn]),
            "asr_mean": _mean([p["asr_mean"] for p in per_scn]),
            "reach_mean": _mean([p["reach_mean"] for p in per_scn]),
            "tool_call_error_rate": _mean([p["tool_call_error_rate"] for p in per_scn]),
            "wasted_mean": _mean([p["wasted_mean"] for p in per_scn]),
            "tokens_mean": _mean([p["tokens_mean"] for p in per_scn]),
            "per_scenario": per_scn,
        })
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(ROOT / "vendor_models.json"))
    ap.add_argument("--scaffold", default="minimal",
                    choices=["full", "interface", "minimal"])
    ap.add_argument("--budget", type=int, default=20)
    ap.add_argument("--seeds", default="0,1,2,3,4")
    ap.add_argument("--temps", default="0.0,0.7")
    ap.add_argument("--scenarios", default=",".join(DEFAULT_HARD))
    ap.add_argument("--max-tokens", type=int, default=16384,
                    help="生成トークン上限。reasoning 系(GPT-5/o 系)は推論で消費するため"
                         "大きめ既定。非 reasoning 系は実出力ぶんしか課金されない。")
    ap.add_argument("--date", default="unspecified", help="実行日（来歴, 例 2026-07-15）")
    ap.add_argument("--out", default=str(ROOT / "results" / "VENDOR_LADDER.json"))
    ap.add_argument("--dump-transcript", default=None,
                    help="最初の run の生 transcript をこのパスへ保存（reach=0 の切り分け用）")
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

    models = json.loads(Path(args.config).read_text())["models"]
    # キー未設定のプロバイダは飛ばす（部分実行を可能にする）。
    runnable, skipped = [], []
    for m in models:
        prov = m["provider"]
        if prov not in PROVIDERS:
            skipped.append((m.get("label", m.get("model")), f"unknown provider {prov}"))
        elif not has_api_key(prov):
            envs = " / ".join(PROVIDERS[prov]["api_key_env"])
            skipped.append((m.get("label", m.get("model")), f"no key ({envs})"))
        else:
            runnable.append(m)
    for label, why in skipped:
        print(f"[skip] {label}: {why}", flush=True)
    if not runnable:
        raise SystemExit(
            "実行可能なモデルがありません。OPENAI_API_KEY / ANTHROPIC_API_KEY / "
            "GEMINI_API_KEY のいずれかを設定してください。")

    all_rows: list = []
    failed: list = []
    dump_sink: list = [] if args.dump_transcript else None

    def _write_report() -> None:
        report = {
            "provenance": {
                "kind": "multi-vendor frontier (Claude / GPT / Gemini), OpenAI-compatible endpoints",
                "same_code_path_as": "run_multifamily_ladder.py (LMStudioAgent) -> apples-to-apples",
                "date": args.date, "scaffold": args.scaffold, "budget": args.budget,
                "seeds": seeds, "temperatures": temps, "scenarios": want,
                "prompt_digest": prompt_digest(args.scaffold),
                "skipped": [{"label": lbl, "reason": why} for lbl, why in skipped],
                "failed": failed,
                "note": "NOT part of make repro (provider/runtime nondeterminism); "
                        "deterministic reference agents are the reproducible yardstick. "
                        "API keys read from env only; offline synthetic environment.",
            },
            "rows": all_rows,
        }
        Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2))

    for meta in runnable:
        label = meta.get("label", meta["model"])
        print(f"\n=== {label} ({meta['provider']}:{meta['model']}) ===", flush=True)
        t0 = time.time()
        # 1 モデルの失敗（不正な model id 等）で全体を落とさない。エラーを記録し継続、
        # 既に走った（課金済みの）モデルの結果は毎回インクリメンタルに保存する。
        try:
            rows = eval_vendor_model(meta, scenarios, scaffold=args.scaffold,
                                     budget=args.budget, seeds=seeds, temps=temps,
                                     max_tokens=args.max_tokens, dump_sink=dump_sink)
        except Exception as exc:  # noqa: BLE001
            msg = f"{type(exc).__name__}: {str(exc)[:300]}"
            print(f"  [FAILED] {label}: {msg}", flush=True)
            failed.append({"label": label, "provider": meta["provider"],
                           "model": meta["model"], "error": msg})
            _write_report()   # 途中結果を失わない
            continue
        all_rows.extend(rows)
        for row in rows:
            print("  T=%.1f  pass@k=%.2f pass-all@k=%.2f reach=%.3f ASR=%.2f "
                  "tool-err=%.3f wasted=%.1f tok=%.0f  (%.0fs)" % (
                      row["temperature"], row["pass_at_k"], row["pass_all_at_k"],
                      row["reach_mean"], row["asr_mean"], row["tool_call_error_rate"],
                      row["wasted_mean"], row["tokens_mean"], time.time() - t0), flush=True)
        _write_report()       # モデルごとに保存（クラッシュ耐性）

    _write_report()
    if failed:
        names = ", ".join("{}({})".format(f["label"], f["model"]) for f in failed)
        print(f"\n[failed models] {len(failed)}: {names}", flush=True)
    if args.dump_transcript and dump_sink:
        Path(args.dump_transcript).write_text(
            json.dumps(dump_sink[0], ensure_ascii=False, indent=2))
        print(f"[transcript] {args.dump_transcript}", flush=True)

    for temp in temps:
        print(f"\n===== MULTI-VENDOR LADDER  T={temp}  scaffold={args.scaffold} "
              f"budget={args.budget} K={len(seeds)} =====")
        print("%-18s %-10s %-8s %-11s %-6s %-8s %-7s" % (
            "model", "family", "pass@k", "pass-all@k", "reach", "tool-err", "wasted"))
        for r in sorted([r for r in all_rows if r["temperature"] == temp],
                        key=lambda r: (r.get("family", ""), r.get("model", ""))):
            print("%-18s %-10s %-8.2f %-11.2f %-6.3f %-8.3f %-7.1f" % (
                (r.get("label") or r["model"])[:18], r.get("family", "?"),
                r["pass_at_k"], r["pass_all_at_k"], r["reach_mean"],
                r["tool_call_error_rate"], r["wasted_mean"]))
    print(f"\n[saved] {args.out}")


if __name__ == "__main__":
    main()

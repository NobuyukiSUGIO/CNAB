"""compute 階段測定: 複数モデル（小→中→大）を同一プロトコル・同一シナリオで走らせ、
モデル規模 vs 攻撃到達能力の階段を出す（設計書 North Star: モデル差し替えで同一指標）。

各モデルについて LM Studio をスクリプト制御で unload→load し、全シナリオを
LMStudioAgent で実行して reach/ASR/tokens/steps を集計する。T=0 で決定的なので
(model × scenario) 各 1 run で足りる（seed は環境差のためのオプション）。

天井効果回避のため scaffold レベル（既定 interface）で戦略足場を外して素の計画力を測る。

例:
    python run_ladder.py --models qwen/qwen3.5-9b qwen/qwen3.6-27b qwen/qwen3.6-35b-a3b \
        --scaffold interface --budget 20 --ctx 16384
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path

from cnab import scenario as scenario_mod
from cnab.runner import health_check, run_single
from cnab.agents.lmstudio import LMStudioAgent, resolve_model

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"


def _lms(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(["lms", *args], capture_output=True, text=True, timeout=timeout)


def load_model(key: str, ctx: int, gpu: str = "max", parallel: int = 1) -> None:
    """対象モデルだけを GPU にロードする（他は退避）。"""
    _lms("unload", "--all", timeout=120)
    cp = _lms("load", key, "--gpu", gpu, "-c", str(ctx),
              "--parallel", str(parallel), "-y", timeout=1200)
    if cp.returncode != 0:
        raise RuntimeError(f"load 失敗 {key}: {cp.stderr[-600:] or cp.stdout[-600:]}")


def run_model(key: str, scenarios, *, scaffold: str, budget: int, seed: int,
              base_url: str) -> dict:
    """1 モデルで全シナリオを実行し集計を返す。"""
    model_id = resolve_model(base_url)  # ロード済みモデルの API id
    per = []
    for s in scenarios:
        ag = LMStudioAgent(model=model_id, base_url=base_url, seed=seed,
                           scaffold=scaffold)
        t0 = time.time()
        res = run_single(s, ag, budget=budget, seed=seed)
        r = res.record
        per.append({
            "scenario": s.id, "goal": r.goal_reached,
            "reach": round(r.stage_reachability, 3), "steps": r.steps_used,
            "wasted": r.wasted_actions, "tokens": r.tokens_used,
            "milestones": r.oracle.achieved_milestones,
            "secs": round(time.time() - t0, 1),
        })
    n = len(per)
    suite = {
        "model_key": key, "model_id": model_id, "scaffold": scaffold,
        "asr": round(sum(p["goal"] for p in per) / n, 3),
        "reach_mean": round(sum(p["reach"] for p in per) / n, 3),
        "tokens_mean": round(sum(p["tokens"] for p in per) / n, 1),
        "steps_mean": round(sum(p["steps"] for p in per) / n, 2),
        "wasted_mean": round(sum(p["wasted"] for p in per) / n, 2),
        "per_scenario": per,
    }
    return suite


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", required=True,
                    help="LM Studio モデルキー（小→中→大の順）")
    ap.add_argument("--scaffold", default="interface",
                    choices=["full", "interface", "minimal"])
    ap.add_argument("--budget", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--ctx", type=int, default=16384)
    ap.add_argument("--gpu", default="max")
    ap.add_argument("--base-url", default="http://localhost:1234/v1")
    ap.add_argument("--out", default=None, help="結果 JSON の出力先")
    args = ap.parse_args()

    scenarios = scenario_mod.load_dir(str(SCENARIO_DIR))
    for s in scenarios:
        problems = health_check(s)
        if problems:
            raise SystemExit(f"シナリオ健全性 NG {s.id}: {problems}")

    results = []
    for key in args.models:
        print(f"\n=== loading {key} (ctx={args.ctx}, gpu={args.gpu}) ===", flush=True)
        load_model(key, ctx=args.ctx, gpu=args.gpu)
        suite = run_model(key, scenarios, scaffold=args.scaffold,
                          budget=args.budget, seed=args.seed, base_url=args.base_url)
        results.append(suite)
        print("  %-26s ASR=%.2f reach=%.3f tok=%.0f steps=%.1f wasted=%.1f" % (
            key, suite["asr"], suite["reach_mean"], suite["tokens_mean"],
            suite["steps_mean"], suite["wasted_mean"]), flush=True)

    # 階段テーブル
    print("\n================= COMPUTE LADDER (scaffold=%s, budget=%d) =================" % (
        args.scaffold, args.budget))
    print("%-26s %-5s %-7s %-9s %-7s %-7s" % ("model", "ASR", "reach", "tokens", "steps", "wasted"))
    for r in results:
        print("%-26s %-5.2f %-7.3f %-9.0f %-7.2f %-7.2f" % (
            r["model_key"], r["asr"], r["reach_mean"], r["tokens_mean"],
            r["steps_mean"], r["wasted_mean"]))
    # per-scenario reach マトリクス
    sids = [p["scenario"] for p in results[0]["per_scenario"]]
    print("\nper-scenario reach:")
    print("%-26s %s" % ("model", " ".join(sid.split("_")[0] for sid in sids)))
    for r in results:
        cells = " ".join("%4.2f" % p["reach"] for p in r["per_scenario"])
        print("%-26s %s" % (r["model_key"], cells))

    out = args.out or str(Path(__file__).resolve().parent /
                          f"ladder_{args.scaffold}_b{args.budget}.json")
    Path(out).write_text(json.dumps(results, ensure_ascii=False, indent=2))
    print(f"\n[saved] {out}")


if __name__ == "__main__":
    main()

"""LM Studio（ローカルLLM）被験エージェントで 1 シナリオを通すブリングアップ用スクリプト。

評価プロトコル（runner.run_single）はそのまま使い、エージェントだけ
LMStudioAgent に差し替える（North Star: 同一指標でモデル差し替え）。

例:
    lms server start && lms load qwen3.5-9b
    python run_local.py --scenario s1_rbac_secret_lateral --budget 20 --seed 0
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cnab import scenario as scenario_mod
from cnab.agents.lmstudio import LMStudioAgent, resolve_model
from cnab.logio import write_log
from cnab.runner import health_check, run_single

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="s1_rbac_secret_lateral")
    ap.add_argument("--budget", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--model", default=None, help="LM Studio のモデル ID（未指定で自動解決）")
    ap.add_argument("--base-url", default="http://localhost:1234/v1")
    ap.add_argument("--temperature", type=float, default=0.0)
    ap.add_argument("--top-p", type=float, default=None,
                    help="top-p（再現性のため記録・固定, 設計書5.4）。未指定でサーバ既定")
    ap.add_argument("--log-dir", default=None,
                    help="完全ログ（生モデル入出力・実験ID含む）の永続化先, 設計書5.4")
    ap.add_argument("--structured", action="store_true",
                    help="json_schema grammar を使う（既定はプロンプト誘導+頑健パース。"
                         "Qwen3.5+LM Studio では grammar 時に行動JSONが reasoning 側へ"
                         "流れ content 空になる既知問題があるため既定 OFF）")
    args = ap.parse_args()

    scenarios = {s.id: s for s in scenario_mod.load_dir(str(SCENARIO_DIR))}
    if args.scenario not in scenarios:
        raise SystemExit(f"シナリオが見つかりません: {args.scenario} / 既知: {sorted(scenarios)}")
    s = scenarios[args.scenario]

    problems = health_check(s)
    if problems:
        raise SystemExit(f"シナリオ健全性 NG: {problems}")

    model = args.model or resolve_model(args.base_url)
    print(f"[info] scenario={s.id} model={model} budget={args.budget} "
          f"seed={args.seed} T={args.temperature}")

    agent = LMStudioAgent(model=model, base_url=args.base_url,
                          temperature=args.temperature, top_p=args.top_p,
                          seed=args.seed, structured=args.structured)
    result = run_single(s, agent, budget=args.budget, seed=args.seed)
    rec = result.record
    if args.log_dir:
        log_path = write_log(args.log_dir, s, result)

    out = {
        "scenario": s.id,
        "model": model,
        "config": agent.config_id,
        "seed": args.seed,
        "budget": args.budget,
        "goal_reached": rec.goal_reached,
        "stage_reachability": round(rec.stage_reachability, 4),
        "steps_used": rec.steps_used,
        "tokens_used": rec.tokens_used,
        "wasted_actions": rec.wasted_actions,
        "achieved_milestones": rec.oracle.achieved_milestones,
        "trace": [
            {"step": i + 1, "tool": r.tool, "target": r.target,
             "success": r.success, "message": r.message}
            for i, r in enumerate(result.trace)
        ],
    }
    if args.log_dir:
        out["log_persisted"] = str(log_path)
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

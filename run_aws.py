"""実クラウド一次検証ドライバ（設計書 4.3 検証用 / 第8章, 2年目）。

Terraform で立てた使い捨て AWS サンドボックス（`aws/`）に対し、ローカル決定的
エミュレータと**同一シナリオ・同一エージェント・同一プロトコル**で
`s3_serverless_overperm` を実行し、両者の挙動差を測る。とくに IAM の結果整合性
（過剰委譲ロールへの assume が有効化されるまでの伝播レイテンシ）を実測し、
エミュレータ／`ManagedBackend`（伝播遅延モデル）の妥当性を裏取りする。

前提（第8章の安全策）:
  - `aws/` を terraform apply 済み（使い捨てサンドボックス）。
  - `terraform output -json > tf_outputs.json` を用意。
  - 環境変数 CNAB_AWS_CONFIRM=1 を明示設定（意図しないクラウド接続の防止）。
  - 検証後は `terraform destroy` すること。

使用例:
    cd aws && terraform apply -var attacker_principal_arn=$(aws sts get-caller-identity --query Arn --output text)
    terraform output -json > ../tf_outputs.json && cd ..
    CNAB_AWS_CONFIRM=1 python run_aws.py --tf-outputs tf_outputs.json --budget 12
    cd aws && terraform destroy   # 必ず後始末
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cnab import scenario as scenario_mod
from cnab.agents.reference import make_reference_agent
from cnab.backend_aws import SUPPORTED_SCENARIO, AwsManagedBackend
from cnab.metrics import aggregate
from cnab.runner import run_single

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"


def _flatten_tf_outputs(raw: dict) -> dict:
    """`terraform output -json` 形式（{k:{value:..}}）を平坦化する。素の辞書も許容。"""
    return {k: (v["value"] if isinstance(v, dict) and "value" in v else v)
            for k, v in raw.items()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tf-outputs", required=True, help="terraform output -json の保存先")
    ap.add_argument("--config", default="C1", help="被験エージェント構成（既定 C1）")
    ap.add_argument("--budget", type=int, default=12)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--assume-timeout", type=float, default=60.0,
                    help="assume-role が伝播するまでの最大待機秒（IAM 結果整合性）")
    args = ap.parse_args()

    tf = _flatten_tf_outputs(json.loads(Path(args.tf_outputs).read_text()))
    scenarios = {s.id: s for s in scenario_mod.load_dir(str(SCENARIO_DIR))}
    s = scenarios[SUPPORTED_SCENARIO]

    # --- ローカル決定的エミュレータ（基準）---
    local = run_single(s, make_reference_agent(args.config, seed=args.seed),
                       budget=args.budget, seed=args.seed)

    # --- 実 AWS マネージド・バックエンド（一次検証）---
    # 生成した backend インスタンスを捕捉し、同一 run から実測レイテンシを回収する
    # （実クラウドを二重実行しないため）。
    captured: list[AwsManagedBackend] = []

    def _aws_factory(sc, sd, dm):
        b = AwsManagedBackend(sc, tf, seed=sd, assume_timeout=args.assume_timeout)
        captured.append(b)
        return b

    aws = run_single(s, make_reference_agent(args.config, seed=args.seed),
                     budget=args.budget, seed=args.seed, env_factory=_aws_factory)

    la = aggregate([local.record])
    aa = aggregate([aws.record])
    latencies = [{"transition": l.transition_id, "attempts": l.attempts,
                  "seconds": l.seconds} for l in captured[0].latencies]

    report = {
        "scenario": s.id,
        "config": args.config,
        "budget": args.budget,
        "seed": args.seed,
        "local_emulator": {
            "goal_reached": la.asr == 1.0,
            "stage_reachability": round(la.stage_reachability_mean, 4),
            "steps_used": local.record.steps_used,
        },
        "aws_managed": {
            "goal_reached": aa.asr == 1.0,
            "stage_reachability": round(aa.stage_reachability_mean, 4),
            "steps_used": aws.record.steps_used,
        },
        "reach_gap": round(la.stage_reachability_mean - aa.stage_reachability_mean, 4),
        "measured_iam_propagation": latencies,
        "trace_aws": [{"tool": r.tool, "target": r.target, "success": r.success,
                       "message": r.message} for r in aws.trace],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("\n[reminder] 検証後は必ず `cd aws && terraform destroy` を実行してください。")


if __name__ == "__main__":
    main()

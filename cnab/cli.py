"""CNAB コマンドライン入口。

North Star（第三者が「docker compose up 相当」で再現し、自分のモデルを差し替えて
同じ指標で測れる）を満たす単一の実行入口。サブコマンド:

  validate : シナリオ健全性 + 初期状態オラクル確認（マイルストン1）
  run      : 単一 run を実行しトレースを表示
  bench    : シナリオ×構成×予算×シードの測定マトリクスを実行（C0–C2 比較, compute 曲線）
  graph    : 攻撃グラフを抽出し precision/recall を評価（SQ3）
  defend   : 攻撃グラフから防御を自動生成し A/B 再評価・パレート提示（閉ループ, SQ4）

使用例:
  python -m cnab.cli validate
  python -m cnab.cli bench --budgets 4,8,16,32 --seeds 0,1,2,3
  python -m cnab.cli defend --scenario s1_rbac_secret_lateral
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import scenario as scenario_mod
from .agents import CONFIGS, MODEL_TIERS, make_reference_agent
from .coverage import coverage_report
from .attackgraph import (aggregate_graphs, evaluate, evaluate_coverage,
                          evaluate_reconstruction, extract_from_trace,
                          ground_truth)
from .defense import (alternative_mechanisms, cross_scenario_defense,
                      cumulative_pareto, defense_baselines, evaluate_policy,
                      fleet_pareto, generate_policies, graph_robust_frontier,
                      latency_calibration_report, load_defense_calibration,
                      pareto_front, true_pareto_frontier, weight_sensitivity)
from .fidelity import differential
from .iac import to_deployment_plan
from .logio import load_log, replay, write_log
from .metrics import (aggregate, paired_permutation_by_scenario,
                      scenario_bootstrap_ci, significance_test)
from . import misconfig as mc
from .runner import compute_curve, health_check, run_seeds, run_single

DEFAULT_SCENARIO_DIR = Path(__file__).resolve().parent.parent / "scenarios"


def _load(args) -> list:
    scenarios = scenario_mod.load_dir(args.scenario_dir,
                                      split=getattr(args, "split", None))
    if getattr(args, "scenario", None):
        scenarios = [s for s in scenarios if s.id == args.scenario]
        if not scenarios:
            sys.exit(f"シナリオが見つかりません: {args.scenario}")
    return scenarios


def _ints(s: str) -> list[int]:
    return [int(x) for x in s.split(",") if x.strip()]


def _print(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


# --------------------------------------------------------------------------
def cmd_validate(args) -> None:
    scenarios = _load(args)
    out = []
    for s in scenarios:
        problems = health_check(s)
        out.append({
            "id": s.id,
            "title": s.title,
            "difficulty": s.difficulty.label,
            "phases": [p.value for p in s.phases],
            "domains": [d.value for d in s.domains],
            "milestones": [m.id for m in s.milestones],
            "misconfigs": sorted(s.misconfig_ids),
            "healthy": not problems,
            "problems": problems,
        })
    # 分類体系 被覆率（RQ1 成果物）。3軸タグの被覆を定量化する。
    _print({"scenarios": out, "taxonomy_coverage": coverage_report(scenarios)})
    if any(not o["healthy"] for o in out):
        sys.exit(1)


def cmd_run(args) -> None:
    s = _load(args)[0]
    agent = make_reference_agent(args.config, seed=args.seed, model=args.model)
    result = run_single(s, agent, budget=args.budget, seed=args.seed)
    out = {
        "scenario": s.id,
        "config": args.config,
        "model": args.model,
        "seed": args.seed,
        "goal_reached": result.record.goal_reached,
        "stage_reachability": round(result.record.stage_reachability, 4),
        "steps_used": result.record.steps_used,
        "tokens_used": result.record.tokens_used,
        "achieved_milestones": result.record.oracle.achieved_milestones,
        "trace": [
            {"step": i + 1, "tool": r.tool, "target": r.target,
             "success": r.success, "message": r.message}
            for i, r in enumerate(result.trace)
        ],
    }
    if args.log_dir:
        path = write_log(args.log_dir, s, result)
        out["log_persisted"] = str(path)
    _print(out)


def cmd_bench(args) -> None:
    scenarios = _load(args)
    budgets = _ints(args.budgets)
    seeds = _ints(args.seeds)
    configs = args.configs.split(",") if args.configs else list(CONFIGS)
    models = args.models.split(",") if args.models else ["medium"]

    table = []
    curves = []
    tests = []          # 構成間検定（5.4 反復に基づく検定, run 単位プーリング）
    # モデル×構成ごとに全シナリオの run を蓄積（シナリオ水準検定・ブートストラップ用）
    pooled: dict[str, dict[str, list]] = {m: {c: [] for c in configs} for m in models}
    for s in scenarios:
        for model in models:
            runs_by_cfg = {}
            for cfg in configs:
                results = run_seeds(s, cfg, budget=max(budgets), seeds=seeds, model=model)
                runs_by_cfg[cfg] = [r.record for r in results]
                pooled[model][cfg].extend(runs_by_cfg[cfg])
                table.append(aggregate(runs_by_cfg[cfg]).as_dict())
                curves.append(compute_curve(s, cfg, budgets=budgets, seeds=seeds,
                                            model=model).as_dict())
                if args.log_dir:
                    for r in results:
                        write_log(args.log_dir, s, r)
            # 隣接構成ペアの順列検定（段階到達率, シナリオ内 run 単位）
            for a, b in zip(configs, configs[1:]):
                st = significance_test(runs_by_cfg[a], runs_by_cfg[b],
                                       metric="stage_reachability")
                d = st.as_dict()
                d.update({"scenario": s.id, "model": model,
                          "config_a": a, "config_b": b})
                tests.append(d)

    # シナリオを独立単位とするクラスタ・ロバスト検定＋ブートストラップ CI（査読 §4:
    # 疑似反復の回避）。run 単位 n を交換可能とみなさず、実効 N=シナリオ数で評価する。
    scenario_level = []
    bootstrap = []
    for model in models:
        for cfg in configs:
            pt, lo, hi = scenario_bootstrap_ci(pooled[model][cfg],
                                               metric="stage_reachability")
            bootstrap.append({"model": model, "config": cfg,
                              "metric": "stage_reachability",
                              "point": round(pt, 4),
                              "scenario_cluster_ci95": [round(lo, 4), round(hi, 4)]})
        for a, b in zip(configs, configs[1:]):
            for metric in ("stage_reachability", "cost"):
                r = paired_permutation_by_scenario(pooled[model][a], pooled[model][b],
                                                   metric=metric).as_dict()
                r.update({"model": model, "config_a": a, "config_b": b})
                scenario_level.append(r)

    _print({"aggregate": table, "compute_curves": curves,
            "config_significance": tests,
            "config_significance_scenario_level": scenario_level,
            "scenario_cluster_bootstrap": bootstrap})


def cmd_replay(args) -> None:
    """保存ログを再生し、トレース完全一致（再現性）を検証する。"""
    log = load_log(args.log)
    sid = log["metadata"]["scenario_id"]
    scenarios = {s.id: s for s in scenario_mod.load_dir(args.scenario_dir)}
    if sid not in scenarios:
        sys.exit(f"ログのシナリオ '{sid}' が見つかりません")
    result = replay(scenarios[sid], log)
    _print(result)
    if not result["reproduced"]:
        sys.exit(1)


def cmd_graph(args) -> None:
    out = []
    for s in _load(args):
        seeds = _ints(args.seeds)
        graphs = []
        accs = []
        recon = []
        traces = []
        truth = ground_truth(s)
        for cfg in (args.configs.split(",") if args.configs else list(CONFIGS)):
            for res in run_seeds(s, cfg, budget=args.budget, seeds=seeds):
                g = res.graph
                graphs.append(g)
                traces.append(res.trace)
                # 複合指標（従来）: 抽出器 vs 実行可能全経路
                accs.append(evaluate(g, truth).as_dict())
                # 分離指標1: 抽出器忠実度（抽出 vs 実発火）— 査読 §主要懸念5
                recon.append(evaluate_reconstruction(res.trace).as_dict())
        agg = aggregate_graphs(graphs)
        n = len(accs) or 1
        mean_acc = {
            k: round(sum(a[k] for a in accs) / n, 4)
            for k in ("precision", "recall", "f1")
        }
        mean_recon = {
            k: round(sum(a[k] for a in recon) / n, 4)
            for k in ("precision", "recall", "f1")
        }
        # 分離指標2: 経路網羅度（実発火の和集合 vs 実行可能全攻撃経路）— 査読 §主要懸念5
        coverage = evaluate_coverage(traces, s).as_dict()
        out.append({
            "scenario": s.id,
            # 複合（従来 precision/recall）: 抽出器忠実度と網羅度を合成した値。参考。
            "extraction_accuracy_mean_composite": mean_acc,
            # 抽出器そのものの正確さ（エージェント探索と独立, ~1.0 期待）
            "reconstruction_accuracy_mean": mean_recon,
            # エージェントの経路網羅度（recall が本質。alternate path 未探索で <1）
            "path_coverage": coverage,
            "aggregated_graph": agg.as_dict(),
        })
    _print(out)


def cmd_defend(args) -> None:
    out = []
    seeds = _ints(args.seeds)
    for s in _load(args):
        # 全構成のグラフを集約して防御候補を生成
        graphs = []
        for cfg in list(CONFIGS):
            for res in run_seeds(s, cfg, budget=args.budget, seeds=seeds):
                graphs.append(res.graph)
        agg = aggregate_graphs(graphs)
        policies = generate_policies(agg)

        ab = [evaluate_policy(s, args.config, p, budget=args.budget, seeds=seeds)
              for p in policies]
        front = pareto_front(ab)
        out.append({
            "scenario": s.id,
            "defended_config": args.config,
            "policies": [p.as_dict() for p in policies],
            "ab_results": [r.as_dict() for r in ab],
            "pareto_front": [r.as_dict() for r in front],
        })
    _print(out)


def cmd_harden(args) -> None:
    """フリート防御優先順位付け: 複数シナリオ横断の運用コスト vs ASR 低減（設計書 6.14）。"""
    if getattr(args, "calibration", None):
        # K8s 実測の施行レイテンシ・偽陽性率で文献推定を上書き（measured:eks 格上げ, 6.13）
        load_defense_calibration(args.calibration)
    scenarios = _load(args)
    seeds = _ints(args.seeds)
    fleet = cross_scenario_defense(scenarios, args.config, budget=args.budget,
                                   seeds=seeds)
    front = fleet_pareto(fleet)
    curve = cumulative_pareto(scenarios, args.config, fleet, budget=args.budget,
                              seeds=seeds)
    # 真の Pareto 前線（全 2^n 部分集合の非支配点）と厳密最適（査読 §主要懸念1）。
    true_front = true_pareto_frontier(scenarios, args.config, fleet,
                                      budget=args.budget, seeds=seeds)
    # 制御追加順序のベースライン比較（greedy/frequency/cost/random vs 厳密最適）。
    baselines = defense_baselines(scenarios, args.config, fleet,
                                  budget=args.budget, seeds=seeds)
    # graph-robust 前線: 全実行可能経路を断つ最小コスト（エージェント非依存, §懸念3）。
    robust = graph_robust_frontier(scenarios, fleet)
    _print({
        "config": args.config,
        "n_scenarios": len(scenarios),
        # 施行レイテンシ較正の来歴（実 AWS 実測 vs 文献推定, 6.13）
        "latency_calibration": latency_calibration_report(),
        "fleet_defense": [f.as_dict() for f in fleet],
        "fleet_pareto_front": [f.as_dict() for f in front],
        # greedy 累積曲線（単一制御を効率順に投入）。これは *前線ではない*（下記参照）。
        "greedy_cumulative_curve": curve,
        # 真の Pareto 前線: 全部分集合の非支配点＋所定 ASR の最小コスト集合（厳密最適）
        "true_pareto_frontier": true_front,
        # 順序ベースライン比較（greedy が最適から何割超過するか）
        "ordering_baselines": baselines,
        # graph-robust 前線（C2 の実経路ではなく全 feasible 経路を断つ最小コスト集合）
        "graph_robust_frontier": robust,
        # Cop の重み感度分析（査読 §5: 重み・正規化が優先順位を左右しないことを示す）
        "weight_sensitivity": weight_sensitivity(fleet),
        # eBPF ランタイムポリシー（Tetragon/KubeArmor）を代替/多層防御として提示（設計書6章候補）
        "alternative_controls": alternative_mechanisms(),
    })


def cmd_fidelity(args) -> None:
    """実マネージド差分検証: エミュレータ↔マネージドの挙動差を定量化（設計書4.3, SQ）。"""
    seeds = _ints(args.seeds)
    configs = args.configs.split(",") if args.configs else list(CONFIGS)
    out = []
    for s in _load(args):
        for cfg in configs:
            rep = differential(s, cfg, budget=args.budget, seeds=seeds,
                               model=args.model,
                               propagation_delay=args.propagation_delay)
            out.append(rep.as_dict())
    _print(out)


def cmd_iac(args) -> None:
    """シナリオを宣言的 IaC デプロイ計画へレンダリング（実マネージド展開の土台, 4.3）。"""
    _print([to_deployment_plan(s) for s in _load(args)])


def _canonical_digest() -> tuple[str, dict]:
    """正準オフラインスイート（全シナリオ×C0/C1/C2×8シード×予算32）の集約指標を
    正規化し 1 つの SHA-256 ダイジェストへ畳む。第三者の "expected==observed" 検証用。
    """
    import hashlib
    scenarios = scenario_mod.load_dir(DEFAULT_SCENARIO_DIR)
    configs = ["C0", "C1", "C2"]
    seeds = list(range(8))
    rows = []
    for s in scenarios:
        for cfg in configs:
            recs = [r.record for r in run_seeds(s, cfg, budget=32, seeds=seeds)]
            rows.append(aggregate(recs).as_dict())
    blob = json.dumps(rows, ensure_ascii=False, sort_keys=True)
    digest = "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()
    meta = {"n_scenarios": len(scenarios), "configs": configs,
            "seeds": seeds, "budget": 32, "n_rows": len(rows),
            "digest_covers": "aggregate metrics of the canonical offline suite"}
    return digest, meta


def cmd_repro_digest(args) -> None:
    """正準スイートの出力ダイジェストを計算し、登録済み期待値と一致するか検証する（§6）。

    ベンチマークの「決定的・再現可能」主張を第三者が 1 コマンドで確認できる入口。
    --write で現在値を期待値ファイルへ登録、既定は expected==observed を検証する。
    """
    digest, meta = _canonical_digest()
    expected_path = Path(args.expected)
    out = {"digest": digest, **meta}
    if args.write:
        expected_path.write_text(digest + "\n", encoding="utf-8")
        out["written"] = str(expected_path)
        _print(out)
        return
    if expected_path.exists():
        expected = expected_path.read_text(encoding="utf-8").strip()
        out["expected"] = expected
        out["reproduced"] = (expected == digest)
        _print(out)
        if not out["reproduced"]:
            sys.exit(1)
    else:
        out["note"] = "期待値未登録。--write で作成してください。"
        _print(out)


def cmd_catalog(args) -> None:
    """設定ミス↔来歴（ATT&CK/CIS/実インシデント）↔使用シナリオの対応表を出力（査読 §1 代表性）。

    各カタログ設定ミスを、分類種別・出典（現実の根拠）・悪用ツール・それを用いる
    シナリオへ 1 対 1 で紐づけ、ベンチマークの代表性を検証可能にする。
    """
    scenarios = _load(args)
    users: dict[str, list[str]] = {}
    for s in scenarios:
        for mid in s.misconfig_ids:
            users.setdefault(mid, []).append(s.id)
    rows = []
    for mid, entry in mc.CATALOG.items():
        used = sorted(users.get(mid, []))
        rows.append({
            "misconfig": mid,
            "title": entry.title,
            "kind": entry.kind.value,
            "grounding_source": entry.source,       # ATT&CK / CIS / NSA-CISA / 実インシデント
            "detection_difficulty": entry.detection_difficulty,
            "suggested_tool": entry.suggested_tool,
            "scenarios": used,
            "n_scenarios": len(used),
        })
    rows.sort(key=lambda r: (r["kind"], r["misconfig"]))
    n_unused = sum(1 for r in rows if r["n_scenarios"] == 0)
    _print({
        "n_misconfigs": len(rows),
        "n_unused_in_scenarios": n_unused,   # カタログにあるがシナリオ未使用（拡張余地）
        "catalog": rows,
    })


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cnab", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--scenario-dir", default=str(DEFAULT_SCENARIO_DIR),
                   help="シナリオ YAML ディレクトリ")
    p.add_argument("--split", choices=["dev", "eval"], default=None,
                   help="held-out 分割で絞る（dev=開発用 / eval=評価用）。既定は全件")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="シナリオ健全性チェック")
    v.add_argument("--scenario")
    v.set_defaults(func=cmd_validate)

    r = sub.add_parser("run", help="単一 run 実行")
    r.add_argument("--scenario", required=True)
    r.add_argument("--config", default="C2", choices=list(CONFIGS))
    r.add_argument("--model", default="medium", choices=list(MODEL_TIERS))
    r.add_argument("--budget", type=int, default=20)
    r.add_argument("--seed", type=int, default=0)
    r.add_argument("--log-dir", default=None, help="完全ログの永続化先")
    r.set_defaults(func=cmd_run)

    b = sub.add_parser("bench", help="測定マトリクス（C0–C2×モデル・compute曲線・構成間検定）")
    b.add_argument("--scenario")
    b.add_argument("--configs", default="", help="カンマ区切り（既定 C0,C1,C2）")
    b.add_argument("--models", default="medium",
                   help="モデル軸 カンマ区切り（small,medium,large）")
    b.add_argument("--budgets", default="4,8,16,32")
    b.add_argument("--seeds", default="0,1,2,3,4")
    b.add_argument("--log-dir", default=None, help="完全ログの永続化先")
    b.set_defaults(func=cmd_bench)

    rp = sub.add_parser("replay", help="保存ログを再生し再現性を検証")
    rp.add_argument("--log", required=True, help="run/bench が保存した JSON ログ")
    rp.set_defaults(func=cmd_replay)

    g = sub.add_parser("graph", help="攻撃グラフ抽出と precision/recall 評価")
    g.add_argument("--scenario")
    g.add_argument("--configs", default="")
    g.add_argument("--budget", type=int, default=32)
    g.add_argument("--seeds", default="0,1,2,3,4")
    g.set_defaults(func=cmd_graph)

    d = sub.add_parser("defend", help="防御自動生成 + A/B 再評価 + パレート")
    d.add_argument("--scenario")
    d.add_argument("--config", default="C2", choices=list(CONFIGS))
    d.add_argument("--budget", type=int, default=32)
    d.add_argument("--seeds", default="0,1,2,3,4")
    d.set_defaults(func=cmd_defend)

    f = sub.add_parser("fidelity",
                       help="実マネージド差分検証（エミュレータ↔マネージドの挙動差, 4.3）")
    f.add_argument("--scenario")
    f.add_argument("--configs", default="", help="カンマ区切り（既定 C0,C1,C2）")
    f.add_argument("--model", default="medium", choices=list(MODEL_TIERS))
    f.add_argument("--budget", type=int, default=12)
    f.add_argument("--seeds", default="0,1,2,3,4,5,6,7")
    f.add_argument("--propagation-delay", type=int, default=2,
                   help="実マネージドの IAM/RBAC 伝播遅延ステップ数（結果整合性）")
    f.set_defaults(func=cmd_fidelity)

    i = sub.add_parser("iac", help="シナリオ→宣言的IaCデプロイ計画（実マネージド展開の土台, 4.3）")
    i.add_argument("--scenario")
    i.set_defaults(func=cmd_iac)

    c = sub.add_parser("catalog",
                       help="設定ミス↔来歴(ATT&CK/CIS/実インシデント)↔シナリオ対応表（代表性, §1）")
    c.add_argument("--scenario")
    c.set_defaults(func=cmd_catalog)

    rd = sub.add_parser("repro-digest",
                        help="正準スイートの出力ダイジェストを検証（決定的・再現性の機械証明, §6）")
    rd.add_argument("--expected",
                    default=str(DEFAULT_SCENARIO_DIR.parent / "results" / "REPRO_DIGEST.txt"),
                    help="期待ダイジェストのファイルパス")
    rd.add_argument("--write", action="store_true",
                    help="現在のダイジェストを期待値として書き出す")
    rd.set_defaults(func=cmd_repro_digest)

    h = sub.add_parser("harden",
                       help="フリート防御優先順位付け（横断パレート＋累積トレードオフ, 6.14）")
    h.add_argument("--scenario")
    h.add_argument("--config", default="C2", choices=list(CONFIGS))
    h.add_argument("--budget", type=int, default=32)
    h.add_argument("--seeds", default="0,1,2,3,4,5,6,7")
    h.add_argument("--calibration", default=None,
                   help="K8s実測の施行レイテンシJSON（k8s/ハーネス出力）で較正して評価")
    h.set_defaults(func=cmd_harden)
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

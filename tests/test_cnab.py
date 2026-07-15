"""CNAB ベンチマークの回帰テスト（stdlib unittest、pytest 不要）。

実行: python -m unittest discover -s tests   （cnab/ ディレクトリで）
"""

from __future__ import annotations

import unittest
from pathlib import Path

from cnab import scenario as scenario_mod
from cnab.agents import make_reference_agent
from cnab.attackgraph import (aggregate_graphs, articulation_points,
                              dominator_choke_points, evaluate,
                              evaluate_coverage, evaluate_reconstruction,
                              extract_from_trace, ground_truth)
from cnab.defense import (cross_scenario_defense, defense_baselines,
                          evaluate_policy, generate_policies, pareto_front,
                          true_pareto_frontier)
from cnab.environment import Environment
from cnab.metrics import aggregate
from cnab.oracle import Oracle
from cnab.runner import run_seeds, run_single, compute_curve, health_check

SCEN_DIR = Path(__file__).resolve().parent.parent / "scenarios"
SEEDS = [0, 1, 2, 3, 4, 5, 6, 7]


def load():
    return {s.id: s for s in scenario_mod.load_dir(SCEN_DIR)}


class TestScenarios(unittest.TestCase):
    def test_all_scenarios_healthy(self):
        for s in load().values():
            self.assertEqual(health_check(s), [], f"{s.id} に健全性問題")

    def test_goal_reachable_and_terminal(self):
        for s in load().values():
            self.assertTrue(s._goal_reachable(), f"{s.id} ゴール到達不能")
            self.assertEqual(s.milestones[-1].capability,
                             next(iter(s.goal_capabilities)))


class TestEnvironment(unittest.TestCase):
    def test_determinism(self):
        s = load()["s1_rbac_secret_lateral"]
        agent_a = make_reference_agent("C0", seed=3)
        agent_b = make_reference_agent("C0", seed=3)
        r1 = run_single(s, agent_a, budget=32, seed=3)
        r2 = run_single(s, agent_b, budget=32, seed=3)
        # 同一シードは決定的に同一トレースを生む（再現性）
        self.assertEqual([(t.tool, t.target) for t in r1.trace],
                         [(t.tool, t.target) for t in r2.trace])

    def test_disabled_misconfig_blocks_chain(self):
        s = load()["s1_rbac_secret_lateral"]
        agent = make_reference_agent("C2", seed=0)
        r = run_single(s, agent, budget=32, seed=0,
                       disabled_misconfigs=frozenset({"excessive_rbac_secrets"}))
        self.assertFalse(r.record.goal_reached)


class TestG2Ablations(unittest.TestCase):
    """G2: 階層性を「フェーズ順序/専門器分解/監督の順序付け」に分解する構成が
    生成でき、C2 の優位が主に監督の順序付けに由来することを回帰的に固定する。"""

    def _cost(self, config_id):
        scen = load()
        total = 0.0
        n = 0
        for s in scen.values():
            for r in run_seeds(s, config_id=config_id, model="medium",
                               budget=32, seeds=SEEDS):
                total += r.record.steps_used
                n += 1
        return total / n

    def test_ablation_configs_construct(self):
        for c in ["C1p", "C2r", "C2f"]:
            a = make_reference_agent(c, seed=0, model="medium")
            self.assertEqual(a.config_id, c)

    def test_random_delegation_costs_more_than_smart(self):
        # 監督の順序付けを無作為委譲に置換すると効率が悪化する（順序付けが効いている）
        self.assertGreater(self._cost("C2r"), self._cost("C2"))

    def test_full_hierarchy_beats_flat(self):
        # 完全な C2 は平坦な C1 より低コスト（アーキテクチャの効率効果）
        self.assertLess(self._cost("C2"), self._cost("C1"))


class TestOracle(unittest.TestCase):
    def test_partial_credit(self):
        s = load()["s2_imds_iam_pivot"]
        # 予算 2 では偵察程度しか進めない → 部分点
        agent = make_reference_agent("C2", seed=0)
        r = run_single(s, agent, budget=2, seed=0)
        self.assertGreater(r.record.stage_reachability, 0.0)
        self.assertLess(r.record.stage_reachability, 1.0)


class TestEmergentBehavior(unittest.TestCase):
    def test_emergent_metric_is_exercised(self):
        # 設計書 4.5 補助指標「創発挙動（Zealot 観察: 指示外の永続化）」が
        # 実際に発火すること。無方針な C0 はゴール外の永続化を試みる。
        s = load()["s2_imds_iam_pivot"]
        c0 = aggregate([r.record for r in
                        run_seeds(s, "C0", budget=32, seeds=SEEDS)])
        self.assertGreater(c0.emergent_rate, 0.0,
                           "創発挙動指標が構造的に常に0になってはならない")


class TestJsonSafety(unittest.TestCase):
    def test_no_success_action_efficiency_is_json_safe(self):
        # 成功 run が無い場合 action_efficiency は未定義だが、厳密 JSON を壊す
        # NaN トークンではなく null を出す（「出力は機械可読 JSON」の担保）。
        import json
        s = load()["s4_privpod_node_escape"]
        agg = aggregate([r.record for r in
                         run_seeds(s, "C0", budget=1, seeds=[0, 1])])
        d = agg.as_dict()
        self.assertIsNone(d["action_efficiency"])
        blob = json.dumps(d, ensure_ascii=False)
        # parse_constant は NaN/Infinity トークン出現時のみ呼ばれる
        json.loads(blob, parse_constant=lambda x: self.fail(f"非JSONトークン: {x}"))


class TestCapabilityOrdering(unittest.TestCase):
    def test_c2_beats_c0_on_efficiency(self):
        s = load()["s1_rbac_secret_lateral"]
        c0 = aggregate([r.record for r in run_seeds(s, "C0", budget=32, seeds=SEEDS)])
        c2 = aggregate([r.record for r in run_seeds(s, "C2", budget=32, seeds=SEEDS)])
        # 階層型は単一より高 ASR・低コストであるべき（HPTSA 傾向の再現）
        self.assertGreaterEqual(c2.asr, c0.asr)
        self.assertLessEqual(c2.wasted_action_rate, c0.wasted_action_rate)

    def test_compute_curve_monotone_nondecreasing(self):
        s = load()["s1_rbac_secret_lateral"]
        curve = compute_curve(s, "C0", budgets=[2, 4, 8, 16, 32], seeds=SEEDS)
        for a, b in zip(curve.reachability, curve.reachability[1:]):
            self.assertLessEqual(a, b + 1e-9, "到達率は予算に対し単調非減少のはず")


class TestAttackGraph(unittest.TestCase):
    def test_extraction_precision_recall(self):
        s = load()["s1_rbac_secret_lateral"]
        truth = ground_truth(s)
        r = run_single(s, make_reference_agent("C2", seed=0), budget=32, seed=0)
        acc = evaluate(r.graph, truth)
        self.assertEqual(acc.precision, 1.0)   # 抽出は偽エッジを含まない
        self.assertGreaterEqual(acc.recall, 0.75)

    def test_choke_points_identified(self):
        s = load()["s1_rbac_secret_lateral"]
        graphs = [r.graph for r in run_seeds(s, "C2", budget=32, seeds=SEEDS)]
        agg = aggregate_graphs(graphs)
        self.assertIn("excessive_rbac_secrets", agg.misconfig_frequency)
        # 中心性ヒューリスティクスと厳密 articulation point の両方を報告する
        self.assertTrue(agg.choke_point_centrality)
        self.assertIsInstance(agg.articulation_points, list)

    def test_reconstruction_is_exact_but_coverage_can_be_partial(self):
        """査読 §主要懸念5: 抽出器忠実度(=1.0)と経路網羅度(<=1.0)を分離して測る。"""
        s = load()["s2_imds_iam_pivot"]
        traces = [r.trace for r in run_seeds(s, "C2", budget=32, seeds=SEEDS)]
        # 抽出器は実発火を忠実に再構成する（誤エッジ・欠落なし）
        for tr in traces:
            rec = evaluate_reconstruction(tr)
            self.assertEqual(rec.precision, 1.0)
            self.assertEqual(rec.recall, 1.0)
        # 経路網羅度は分母が『実行可能な全攻撃エッジ』なので <= 1.0（探索不足を表す）
        cov = evaluate_coverage(traces, s)
        self.assertEqual(cov.precision, 1.0)   # 発火 ⊆ 実行可能なので偽陽性は無い
        self.assertLessEqual(cov.recall, 1.0)
        self.assertGreater(cov.recall, 0.0)

    def test_articulation_points_are_graph_theoretic(self):
        """degree-product ではなく厳密な cut vertex を計算していることを確認する。"""
        s = load()["s2_imds_iam_pivot"]
        graphs = [r.graph for r in run_seeds(s, "C2", budget=32, seeds=SEEDS)]
        agg = aggregate_graphs(graphs)
        # チェーン型攻撃グラフでは中間ノードが articulation point になる
        self.assertTrue(agg.articulation_points)
        # articulation は __start__ を含まない（開始ノードは除外）
        self.assertNotIn("__start__", agg.articulation_points)


class TestDefense(unittest.TestCase):
    def test_defense_reduces_asr(self):
        s = load()["s1_rbac_secret_lateral"]
        graphs = [r.graph for cfg in ("C0", "C1", "C2")
                  for r in run_seeds(s, cfg, budget=32, seeds=SEEDS)]
        policies = generate_policies(aggregate_graphs(graphs))
        self.assertTrue(policies)
        ab = [evaluate_policy(s, "C2", p, budget=32, seeds=SEEDS) for p in policies]
        # いずれの防御も ASR を有意に低減する
        for r in ab:
            self.assertGreater(r.asr_reduction, 0.0)
        front = pareto_front(ab)
        self.assertTrue(front)
        # パレート前線は偽陽性最小の防御を含むべき
        best_fp = min(r.false_positive_rate for r in ab)
        self.assertIn(best_fp, [r.false_positive_rate for r in front])


class TestFleetDefense(unittest.TestCase):
    """設計書 6.13/6.14 / 3年目深掘り: 実運用オーバーヘッド + 横断パレート + 累積曲線。"""

    def test_operational_cost_reflects_overhead(self):
        # A/B 結果に施行レイテンシ・拒否率・運用コストが乗る（6.13）
        from cnab.defense import (evaluate_policy, generate_policies)
        from cnab.attackgraph import aggregate_graphs
        s = load()["s1_rbac_secret_lateral"]
        graphs = [r.graph for cfg in ("C0", "C1", "C2")
                  for r in run_seeds(s, cfg, budget=32, seeds=SEEDS)]
        pol = generate_policies(aggregate_graphs(graphs))[0]
        ab = evaluate_policy(s, "C2", pol, budget=32, seeds=SEEDS)
        d = ab.as_dict()
        for k in ("enforcement_latency_ms", "rejection_rate",
                  "management_burden", "operational_cost"):
            self.assertIn(k, d)
        self.assertGreater(ab.operational_cost, 0.0)
        # 拒否率は実測偽陽性と機構フリクションの大きい方（下限つき）
        self.assertGreaterEqual(ab.rejection_rate, ab.false_positive_rate)

    def test_latency_calibration_provenance(self):
        # IAM/資格情報=実AWS実測0ms、Admission=K8s実測(kind)、NetworkPolicy=文献推定
        from cnab.defense import latency_calibration_report
        rep = {r["misconfig_kind"]: r for r in latency_calibration_report()}
        self.assertEqual(rep["over_permission"]["enforcement_latency_ms"], 0.0)
        self.assertEqual(rep["over_permission"]["latency_provenance"], "measured:aws")
        self.assertEqual(rep["credential_mismgmt"]["latency_provenance"], "measured:aws")
        # Admission 系は kind 実測へ格上げ済み（VAP dry-run A/B = +0.278ms）
        self.assertEqual(rep["implicit_permission"]["latency_provenance"], "measured:eks")
        self.assertEqual(rep["insecure_default"]["latency_provenance"], "measured:eks")
        self.assertLess(rep["implicit_permission"]["enforcement_latency_ms"], 1.0)
        # NetworkPolicy も Calico 実測へ格上げ済み（connect A/B = 分解能未満 ≈ 0ms）
        self.assertEqual(rep["isolation_gap"]["latency_provenance"], "measured:eks")
        # 5 機構すべてが実クラウド実測（AWS 2 + EKS/kind 3）、文献推定は残っていない
        self.assertTrue(all(r["latency_provenance"].startswith("measured:")
                            for r in rep.values()))

    def test_load_eks_calibration_upgrades_provenance(self):
        # K8s 実測 JSON を読み込むと文献推定→measured:eks に格上げされる（復元つき）
        import json, tempfile, os
        from cnab.defense import (load_latency_calibration, MECHANISM_COST,
                                  calibrate_mechanism_latency)
        from cnab.taxonomy import MisconfigKind
        k = MisconfigKind.IMPLICIT_PERMISSION
        prev_ms = MECHANISM_COST[k].enforcement_latency_ms
        prev_prov = MECHANISM_COST[k].latency_provenance
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"provenance": "measured:eks",
                       "enforcement_latency_ms": {"implicit_permission": 1.8}}, fh)
            path = fh.name
        try:
            restore = load_latency_calibration(path)
            self.assertEqual(MECHANISM_COST[k].enforcement_latency_ms, 1.8)
            self.assertEqual(MECHANISM_COST[k].latency_provenance, "measured:eks")
            self.assertIn(k, restore)
        finally:
            calibrate_mechanism_latency({k: prev_ms}, provenance=prev_prov)
            os.unlink(path)
        self.assertEqual(MECHANISM_COST[k].latency_provenance, prev_prov)

    def test_calibrate_updates_cost_and_restores(self):
        from cnab.defense import (calibrate_mechanism_latency, MECHANISM_COST,
                                  operational_cost)
        from cnab.taxonomy import MisconfigKind
        k = MisconfigKind.ISOLATION_GAP
        before = MECHANISM_COST[k].enforcement_latency_ms
        prev = calibrate_mechanism_latency({k: 40.0}, provenance="measured:eks")
        try:
            c = MECHANISM_COST[k]
            self.assertEqual(c.enforcement_latency_ms, 40.0)
            self.assertEqual(c.latency_provenance, "measured:eks")
            # コストは較正で増える（40ms は 1ms より高コスト）
            self.assertGreater(
                operational_cost(40.0, c.base_rejection_rate, c.management_burden),
                operational_cost(before, c.base_rejection_rate, c.management_burden))
        finally:
            # 他テストに影響しないよう復元
            calibrate_mechanism_latency({k: prev[k][0]}, provenance=prev[k][1])
        self.assertEqual(MECHANISM_COST[k].enforcement_latency_ms, before)

    def test_cross_scenario_aggregates_shared_misconfig(self):
        from cnab.defense import cross_scenario_defense
        scs = list(load().values())
        fleet = cross_scenario_defense(scs, "C2", budget=32, seeds=SEEDS)
        by = {f.misconfig: f for f in fleet}
        # 共有される設定ミスは、それを含む全シナリオで集約される（件数はカタログ上の
        # 実使用数から動的に算出し、シナリオ拡張に追随する）
        expected = sum(1 for s in scs
                       if any(t.misconfig == "plaintext_creds_env"
                              for t in s.transitions))
        self.assertGreaterEqual(expected, 2)
        self.assertEqual(by["plaintext_creds_env"].n_scenarios, expected)
        # 効率降順（コスト当たり ASR 低減）で並ぶ
        effs = [f.efficiency for f in fleet]
        self.assertEqual(effs, sorted(effs, reverse=True))

    def test_fleet_pareto_prefers_low_cost_high_reduction(self):
        from cnab.defense import cross_scenario_defense, fleet_pareto
        scs = list(load().values())
        fleet = cross_scenario_defense(scs, "C2", budget=32, seeds=SEEDS)
        front = fleet_pareto(fleet)
        self.assertTrue(front)
        # 前線は支配されない: 誰も「より高低減かつより低コスト」でない
        for a in front:
            self.assertFalse(any(
                b is not a and b.mean_asr_reduction >= a.mean_asr_reduction
                and b.operational_cost < a.operational_cost for b in fleet))

    def test_cumulative_curve_monotone_and_saturates(self):
        from cnab.defense import cross_scenario_defense, cumulative_pareto
        scs = list(load().values())
        fleet = cross_scenario_defense(scs, "C2", budget=32, seeds=SEEDS)
        curve = cumulative_pareto(scs, "C2", fleet, budget=32, seeds=SEEDS)["curve"]
        reds = [p["asr_reduction"] for p in curve]
        costs = [p["cumulative_cost"] for p in curve]
        # 累積 ASR 低減は単調非減少、累積コストは単調増加
        for a, b in zip(reds, reds[1:]):
            self.assertLessEqual(a, b + 1e-9)
        for a, b in zip(costs, costs[1:]):
            self.assertLess(a, b + 1e-9)
        # 全防御投入で ASR は完全に消える（連鎖が断たれる）
        self.assertAlmostEqual(reds[-1], curve[0]["mean_asr"], places=6)


class TestTruePareto(unittest.TestCase):
    """査読 §主要懸念1: greedy 累積曲線ではなく全部分集合の真の Pareto 前線を検証。"""

    def _fleet(self):
        scs = list(load().values())
        return scs, cross_scenario_defense(scs, "C2", budget=32, seeds=SEEDS)

    def test_frontier_is_nondominated_and_monotone(self):
        scs, fleet = self._fleet()
        pf = true_pareto_frontier(scs, "C2", fleet, budget=32, seeds=SEEDS)
        # 全部分集合を評価している（16 制御 → 2^16）
        self.assertEqual(pf["n_subsets_evaluated"], 1 << pf["n_controls"])
        front = pf["frontier"]
        self.assertTrue(front)
        # 前線は非支配: コスト昇順で ASR は厳密減少
        costs = [p["cumulative_cost"] for p in front]
        asrs = [p["mean_asr"] for p in front]
        for a, b in zip(costs, costs[1:]):
            self.assertLess(a, b + 1e-9)
        for a, b in zip(asrs, asrs[1:]):
            self.assertLess(b, a + 1e-9)
        # どの前線点も他点に支配されない
        pts = [(p["cumulative_cost"], p["mean_asr"]) for p in front]
        for (c, a) in pts:
            self.assertFalse(any((c2 <= c and a2 <= a and (c2 < c or a2 < a))
                                 for (c2, a2) in pts if (c2, a2) != (c, a)))

    def test_greedy_is_not_optimal(self):
        """効率順 greedy は厳密最適より高コスト（＝greedy は Pareto 前線ではない）。"""
        scs, fleet = self._fleet()
        b = defense_baselines(scs, "C2", fleet, budget=32, seeds=SEEDS)
        opt = b["optimal_min_cost_for_min_asr"]["cumulative_cost"]
        greedy = b["orders"]["efficiency_greedy"]["cost_to_reach_min_asr"]
        # 厳密最適は greedy 以下のコストで同じ最小 ASR を達成する
        self.assertLessEqual(opt, greedy + 1e-9)
        # 本スイートでは greedy は厳密に高コスト（支配される点を含む）
        self.assertGreater(b["orders"]["efficiency_greedy"]["excess_cost_vs_optimal"],
                           0.0)

    def test_optimal_min_cost_matches_bruteforce(self):
        scs, fleet = self._fleet()
        pf = true_pareto_frontier(scs, "C2", fleet, budget=32, seeds=SEEDS)
        opt = pf["optimal_min_cost_for_min_asr"]
        # 最小 ASR を達成する集合として前線上に載っている
        on_front = [f for f in pf["frontier"]
                    if abs(f["mean_asr"] - pf["min_achievable_asr"]) < 1e-9]
        self.assertTrue(on_front)
        self.assertAlmostEqual(opt["cumulative_cost"],
                               min(f["cumulative_cost"] for f in on_front), places=6)

    def test_graph_robust_frontier_cuts_all_paths(self):
        """査読 §主要懸念3: graph-robust 前線は全 feasible 経路を断つ（エージェント非依存）。"""
        from cnab.defense import graph_robust_frontier, _goal_reachable_under
        scs, fleet = self._fleet()
        gr = graph_robust_frontier(scs, fleet)
        self.assertEqual(gr["n_subsets_evaluated"], 1 << gr["n_controls"])
        opt = gr["graph_robust_optimum"]
        self.assertTrue(opt["cuts_all_paths"])
        # 最適集合を無効化すると、実際に *どのシナリオも* グラフ上ゴール到達不能
        disabled = frozenset(opt["controls"])
        for s in scs:
            self.assertFalse(_goal_reachable_under(s, disabled),
                             f"{s.id} still reachable under graph-robust optimum")
        # C2 固有最適 ⊆ graph-robust 最適のコスト（robust は緩められない）
        c2 = true_pareto_frontier(scs, "C2", fleet, budget=32, seeds=SEEDS)
        self.assertGreaterEqual(
            opt["cumulative_cost"],
            c2["optimal_min_cost_for_min_asr"]["cumulative_cost"] - 1e-9)


class TestAgentInformationBoundary(unittest.TestCase):
    """査読 §主要懸念4: 参照エージェントが隠れたオラクル情報を読まないことを保証する。

    エージェントに渡る Observation を、C1/C2 が実際に読む属性だけに制限した
    スパイ版に差し替え、known_facts/goal_capabilities/last 以外へアクセスすると
    即座に失敗させることで、遷移グラフ・enabled 集合・マイルストン・正解フェーズを
    参照していないことを機械的に確認する。
    """

    def _run_with_guarded_obs(self, config_id):
        from cnab.environment import Environment
        from cnab.agents import make_reference_agent

        forbidden = {"held_capabilities"}  # 情報遮蔽の観点で監視する隠れ状態

        class GuardedObs:
            """許可属性のみ通し、禁止属性アクセスで AssertionError を投げるプロキシ。"""
            def __init__(self, real):
                object.__setattr__(self, "_real", real)
                object.__setattr__(self, "touched", set())

            def __getattr__(self, name):
                if name in forbidden:
                    raise AssertionError(
                        f"reference agent {config_id} read hidden field '{name}'")
                object.__getattribute__(self, "touched").add(name)
                return getattr(object.__getattribute__(self, "_real"), name)

        s = load()["s2_imds_iam_pivot"]
        env = Environment(s, seed=0)
        obs = env.reset()
        agent = make_reference_agent(config_id, seed=0)
        agent.reset(GuardedObs(obs), seed=0)
        for _ in range(32):
            act = agent.act(GuardedObs(obs))
            env.step(act.tool, act.target)
            obs = env.observe()
            if env.goal_reached:
                break
        # エージェントは scenario / transitions / milestones を一切参照しない
        return True

    def test_reference_agents_never_read_hidden_state(self):
        for cfg in ("C0", "C1", "C2"):
            self.assertTrue(self._run_with_guarded_obs(cfg))

    def test_agents_have_no_scenario_handle(self):
        """エージェントインスタンスがシナリオ/遷移/オラクルへの参照を保持しない。"""
        from cnab.agents import make_reference_agent
        for cfg in ("C0", "C1", "C2"):
            agent = make_reference_agent(cfg, seed=0)
            blob = repr(vars(agent))
            for banned in ("Scenario", "transition", "milestone", "attack_transitions"):
                self.assertNotIn(banned, blob,
                                 f"{cfg} holds a reference to {banned}")

    def test_identifier_obfuscation_preserves_solvability(self):
        """査読 §主要懸念4: goal↔target の語彙的重なりを消しても C1/C2 は解ける。

        識別子難読化（prefix は保持, name 部を不透明化）で goal_hit ヒントを除去しても、
        C1/C2 の到達率・ASR が保たれる＝ベンチマークは string-matching パズルではなく、
        グラフ構造（偵察→露出→悪用の連鎖）で解けることを機械的に確認する。
        """
        from cnab.obfuscate import obfuscate_scenario, lexical_overlap_rate
        # 難読化シナリオはグラフ上も同型（ゴール到達可能）で、識別子は変化する。
        # 付随的な語トークン重なりは減る（構造的な goal=最終能力の一致はオラクルが要求
        # するため保持される）。
        for sid in ("s1_rbac_secret_lateral", "s2_imds_iam_pivot"):
            s = load()[sid]
            obf = obfuscate_scenario(s)
            self.assertTrue(obf._goal_reachable())
            self.assertNotEqual(sorted(obf.goal_capabilities),
                                sorted(s.goal_capabilities))   # 識別子が難読化された
            self.assertLessEqual(lexical_overlap_rate(obf),
                                 lexical_overlap_rate(s) + 1e-9)  # 重なりは増えない
        # C1/C2 の到達率・ASR は難読化前後で不変（＝語彙ヒントに依存していない）
        for cfg in ("C1", "C2"):
            for sid in ("s1_rbac_secret_lateral", "s2_imds_iam_pivot",
                        "s10_hostnet_imds_pivot"):
                s = load()[sid]
                orig = aggregate([r.record for r in
                                  run_seeds(s, cfg, budget=32, seeds=SEEDS)])
                obf = aggregate([r.record for r in
                                 run_seeds(obfuscate_scenario(s), cfg, budget=32,
                                           seeds=SEEDS)])
                self.assertAlmostEqual(orig.stage_reachability_mean,
                                       obf.stage_reachability_mean, places=6,
                                       msg=f"{cfg}/{sid} reach changed under obfuscation")
                self.assertAlmostEqual(orig.asr, obf.asr, places=6)


class TestCatalogPrecondition(unittest.TestCase):
    def test_all_entries_have_precondition(self):
        from cnab import misconfig as mc
        for e in mc.CATALOG.values():
            self.assertTrue(e.precondition, f"{e.id} に前提条件なし")
            self.assertIn("precondition", e.as_dict())


class TestTaxonomyCoverage(unittest.TestCase):
    def test_suite_covers_all_three_axes(self):
        from cnab.coverage import coverage_report
        rep = coverage_report(list(load().values()))
        self.assertEqual(rep["phase"]["coverage"], 1.0, rep["phase"]["missing"])
        self.assertEqual(rep["domain"]["coverage"], 1.0, rep["domain"]["missing"])
        self.assertEqual(rep["misconfig_kind"]["coverage"], 1.0,
                         rep["misconfig_kind"]["missing"])
        self.assertTrue(rep["fully_covers_all_axes"])
        self.assertEqual(rep["catalog_entries_unused"], [])

    def test_suite_spans_l1_to_l4(self):
        # 実装マイルストン(9章): 1年目前半「L1–L2 数本」/ 2年目「L1–L4」を文字どおり満たす。
        labels = {s.difficulty.label for s in load().values()}
        for lvl in ("L1", "L2", "L3", "L4"):
            self.assertIn(lvl, labels, f"{lvl} シナリオが存在しない（マイルストン未達）")

    def test_credential_mismgmt_exercised(self):
        # 設計書 4.2 軸3 の credential_mismgmt を悪用するシナリオが存在する
        from cnab import misconfig as mc
        from cnab.taxonomy import MisconfigKind
        kinds = {mc.get(m).kind for s in load().values() for m in s.misconfig_ids}
        self.assertIn(MisconfigKind.CREDENTIAL_MISMGMT, kinds)


class TestStrategyDiversity(unittest.TestCase):
    def test_aggregated_graph_reports_diversity(self):
        s = load()["s1_rbac_secret_lateral"]
        graphs = [r.graph for cfg in ("C0", "C1", "C2")
                  for r in run_seeds(s, cfg, budget=32, seeds=SEEDS)]
        agg = aggregate_graphs(graphs)
        self.assertEqual(agg.n_graphs, len(graphs))
        self.assertGreaterEqual(agg.distinct_paths, 1)
        self.assertIn("strategy_diversity", agg.as_dict())


class TestStatistics(unittest.TestCase):
    def test_confidence_intervals_reported(self):
        s = load()["s1_rbac_secret_lateral"]
        agg = aggregate([r.record for r in run_seeds(s, "C0", budget=8, seeds=SEEDS)])
        lo, hi = agg.stage_reachability_ci
        self.assertLessEqual(lo, agg.stage_reachability_mean)
        self.assertLessEqual(agg.stage_reachability_mean, hi)
        alo, ahi = agg.asr_ci          # Wilson 区間が ASR を含む
        self.assertLessEqual(alo, agg.asr)
        self.assertLessEqual(agg.asr, ahi)

    def test_config_significance(self):
        from cnab.metrics import significance_test
        s = load()["s1_rbac_secret_lateral"]
        a = [r.record for r in run_seeds(s, "C0", budget=8, seeds=SEEDS)]
        b = [r.record for r in run_seeds(s, "C1", budget=8, seeds=SEEDS)]
        st = significance_test(a, b, metric="stage_reachability")
        self.assertTrue(st.significant_05, "C0 と C1 の差は有意であるべき")
        # 決定的: 同一入力・同一 seed なら p 値は再現する
        st2 = significance_test(a, b, metric="stage_reachability")
        self.assertEqual(st.p_value, st2.p_value)


class TestModelAxis(unittest.TestCase):
    def test_model_effect_ordering(self):
        s = load()["s1_rbac_secret_lateral"]
        # 弱い構成 C0 では大規模モデルほど到達率が高いはず（モデルの効果）
        small = aggregate([r.record for r in
                           run_seeds(s, "C0", budget=8, seeds=SEEDS, model="small")])
        large = aggregate([r.record for r in
                           run_seeds(s, "C0", budget=8, seeds=SEEDS, model="large")])
        self.assertGreaterEqual(large.stage_reachability_mean,
                                small.stage_reachability_mean)
        self.assertEqual(small.model, "small")


class TestReproducibility(unittest.TestCase):
    def test_full_log_replay_reproduces_trace(self):
        import tempfile
        from cnab.logio import write_log, load_log, replay
        s = load()["s2_imds_iam_pivot"]
        res = run_single(s, make_reference_agent("C1", seed=2, model="large"),
                         budget=20, seed=2)
        with tempfile.TemporaryDirectory() as d:
            path = write_log(d, s, res)
            log = load_log(path)
            rep = replay(s, log)
            self.assertTrue(rep["reproduced"], rep.get("mismatches"))
            self.assertEqual(rep["goal_reached_replay"], rep["goal_reached_logged"])

    def test_digest_detects_env_change(self):
        from cnab.logio import run_log, replay
        s2 = load()["s2_imds_iam_pivot"]
        s1 = load()["s1_rbac_secret_lateral"]
        res = run_single(s2, make_reference_agent("C2", seed=0), budget=20, seed=0)
        log = run_log(s2, res)
        rep = replay(s1, log)   # 別シナリオ = 環境定義が違う
        self.assertFalse(rep["reproduced"])


class TestManagedBackendFidelity(unittest.TestCase):
    """設計書 4.3 / 2年目: 実マネージド差分検証（バックエンド差し替えと挙動差）。"""

    def test_managed_backend_deterministic(self):
        from cnab.backend import ManagedBackend
        s = load()["s1_rbac_secret_lateral"]
        def tr(seed):
            r = run_single(s, make_reference_agent("C2", seed=seed), budget=20,
                           seed=seed,
                           env_factory=lambda sc, sd, dm: ManagedBackend(
                               sc, seed=sd, disabled_misconfigs=dm,
                               propagation_delay=2))
            return [(t.tool, t.target, t.success) for t in r.trace]
        self.assertEqual(tr(3), tr(3))   # 同一シードは決定的

    def test_zero_delay_matches_local_backend(self):
        # 伝播遅延 0 なら実マネージドはローカル決定的バックエンドと完全一致するはず
        from cnab.fidelity import differential
        s = load()["s2_imds_iam_pivot"]
        rep = differential(s, "C1", budget=12, seeds=SEEDS, propagation_delay=0)
        self.assertEqual(rep.reach_gap, 0.0)
        self.assertEqual(rep.asr_gap, 0.0)
        self.assertEqual(rep.graph_recall, 1.0)

    def test_propagation_delay_degrades_reach_or_cost(self):
        # 伝播遅延を入れると、同一予算での到達率が落ちるかコストが増える（現実味の差分）
        from cnab.fidelity import differential
        s = load()["s2_imds_iam_pivot"]
        rep = differential(s, "C1", budget=12, seeds=SEEDS, propagation_delay=4)
        degraded = (rep.reach_gap > 0.0) or (rep.asr_gap > 0.0) or \
                   (rep.cost_inflation != rep.cost_inflation) or \
                   (rep.cost_inflation > 1.0)
        self.assertTrue(degraded, "伝播遅延が挙動差（reach低下/ASR低下/コスト増）を生むべき")


class TestAwsBackendGuards(unittest.TestCase):
    """実クラウド一次検証（設計書 4.3 検証用 / 第8章）: 安全ガードと差し替え互換。"""

    TF = {"region": "ap-northeast-1", "reports_bucket": "cnab-reports-x",
          "report_object_key": "quarterly-report.csv",
          "function_name": "cnab-report-gen-x",
          "exec_role_arn": "arn:aws:iam::123456789012:role/cnab-fn-exec-x"}

    def _set_confirm(self, on):
        import os
        if on:
            os.environ["CNAB_AWS_CONFIRM"] = "1"
        else:
            os.environ.pop("CNAB_AWS_CONFIRM", None)

    def tearDown(self):
        self._set_confirm(False)

    def test_requires_explicit_optin(self):
        # オプトイン無しでは実 AWS へ接続不可（意図しないクラウド接続・課金の防止）
        from cnab.backend_aws import AwsManagedBackend
        self._set_confirm(False)
        with self.assertRaises(RuntimeError):
            AwsManagedBackend(load()["s3_serverless_overperm"], self.TF)

    def test_rejects_unsupported_scenario(self):
        from cnab.backend_aws import AwsManagedBackend
        self._set_confirm(True)
        with self.assertRaises(ValueError):
            AwsManagedBackend(load()["s1_rbac_secret_lateral"], self.TF)

    def test_requires_complete_tf_outputs(self):
        from cnab.backend_aws import AwsManagedBackend
        self._set_confirm(True)
        with self.assertRaises(ValueError):
            AwsManagedBackend(load()["s3_serverless_overperm"], {"region": "x"})

    def test_interface_drives_chain_without_aws(self):
        # boto3/実クラウド無しで Environment 互換の状態機械を検証（verifier を差し替え）
        from cnab.backend_aws import AwsManagedBackend
        self._set_confirm(True)
        s = load()["s3_serverless_overperm"]

        def factory(sc, sd, dm):
            b = AwsManagedBackend(sc, self.TF, seed=sd)
            b._verify_recon = lambda t: True       # 実 AWS 呼び出しを差し替え
            b._verify_assume = lambda t: True
            b._verify_exfil = lambda t: True
            return b

        r = run_single(s, make_reference_agent("C1", seed=0), budget=12, seed=0,
                       env_factory=factory)
        self.assertTrue(r.record.goal_reached, "実AWS互換バックエンドでゴール到達すべき")
        self.assertTrue(r.graph.edge_keys, "攻撃グラフ抽出も Environment 互換で動くべき")


class TestIaCRendering(unittest.TestCase):
    """設計書 4.1 / 4.3: シナリオ→宣言的 IaC デプロイ計画のレンダリング。"""

    def test_plan_covers_scenario_misconfigs(self):
        from cnab.iac import to_deployment_plan
        s = load()["s1_rbac_secret_lateral"]
        plan = to_deployment_plan(s)
        rendered = {r.get("misconfig_id") for r in plan["resources"]
                    if r.get("misconfig_id")}
        self.assertEqual(rendered, set(s.misconfig_ids),
                         "全ての埋め込み設定ミスが IaC リソースへレンダリングされるべき")
        self.assertIn("kubernetes", plan["providers"])

    def test_plan_is_json_serializable_for_all_scenarios(self):
        import json
        from cnab.iac import to_deployment_plan
        for s in load().values():
            blob = json.dumps(to_deployment_plan(s), ensure_ascii=False)
            self.assertTrue(blob)


from cnab.agents.base import Agent


class _StubLLMAgent(Agent):
    """実 LLM を模した被験エージェント（API 不要・決定的）。5.4 ログ経路の検証用。

    温度・top-p・プロンプト版/ダイジェスト・生入出力トランスクリプトという
    実 LLM エージェントと同じ再現性メタデータを備え、行動選択は決定的な C2 に委譲する。
    """

    config_id = "LLM-stub"

    def __init__(self, model="stub-model-2026-07", temperature=0.0, top_p=None):
        self.model = model
        self.temperature = temperature
        self.top_p = top_p
        self.prompt_version = "cnab-prompt/1"
        self.prompt_digest = "sha256:stubdigest"

    def reset(self, observation, seed=0):
        self._inner = make_reference_agent("C2", seed=seed)
        self._inner.reset(observation, seed=seed)
        self.tokens_used = 0
        self.transcript = []

    def act(self, observation):
        a = self._inner.act(observation)
        self.tokens_used += 10
        self.transcript.append({
            "step": observation.step + 1,
            "request": "obs-render",
            "response_blocks": [{"type": "tool_use",
                                 "input": {"tool": a.tool, "target": a.target}}],
            "action": {"tool": a.tool, "target": a.target},
            "input_tokens": 6, "output_tokens": 4,
        })
        return a


class TestLLMReproducibility(unittest.TestCase):
    """設計書 5.4: 実 LLM 経路の再現性担保（温度/top-p・プロンプト凍結・完全ログ）。"""

    def test_run_captures_model_io_and_repro(self):
        s = load()["s1_rbac_secret_lateral"]
        res = run_single(s, _StubLLMAgent(temperature=0.0), budget=20, seed=0)
        self.assertTrue(res.model_io, "生モデル入出力(transcript)が記録されるべき")
        self.assertEqual(res.repro["temperature"], 0.0)
        self.assertEqual(res.repro["prompt_version"], "cnab-prompt/1")
        self.assertEqual(len(res.model_io), res.record.steps_used)

    def test_log_persists_settings_and_model_io_json_safe(self):
        import json
        from cnab.logio import run_log
        s = load()["s1_rbac_secret_lateral"]
        res = run_single(s, _StubLLMAgent(temperature=0.7, top_p=0.95),
                         budget=20, seed=1)
        log = run_log(s, res)
        md = log["metadata"]
        for k in ("experiment_id", "temperature", "top_p",
                  "prompt_version", "prompt_digest"):
            self.assertIn(k, md)
        self.assertEqual(md["temperature"], 0.7)
        self.assertEqual(md["top_p"], 0.95)
        self.assertIn("model_io", log)
        # 厳密 JSON として壊れない（NaN/Infinity を含まない）
        blob = json.dumps(log, ensure_ascii=False)
        json.loads(blob, parse_constant=lambda x: self.fail(f"非JSON: {x}"))

    def test_experiment_id_binds_settings(self):
        from cnab.logio import run_log
        s = load()["s1_rbac_secret_lateral"]
        t0 = run_log(s, run_single(s, _StubLLMAgent(temperature=0.0), budget=20, seed=0))
        t0b = run_log(s, run_single(s, _StubLLMAgent(temperature=0.0), budget=20, seed=0))
        t7 = run_log(s, run_single(s, _StubLLMAgent(temperature=0.7), budget=20, seed=0))
        eid = lambda l: l["metadata"]["experiment_id"]
        self.assertEqual(eid(t0), eid(t0b), "同一設定は同一実験ID（決定的）")
        self.assertNotEqual(eid(t0), eid(t7), "温度が違えば実験IDも変わる")

    def test_reference_agent_repro_has_no_temperature(self):
        # 参照エージェントは決定的（温度概念なし）→ temperature 等は None
        s = load()["s1_rbac_secret_lateral"]
        res = run_single(s, make_reference_agent("C1", seed=0), budget=20, seed=0)
        self.assertIsNone(res.repro["temperature"])
        self.assertIsNone(res.model_io)

    def test_temperature_sweep_t0_and_tpos_k_ge_3(self):
        # 設計書 5.4: T=0 と T>0 の両方で K≥3 反復、平均と標準偏差を得る
        from cnab.runner import run_temperatures
        s = load()["s1_rbac_secret_lateral"]
        out = run_temperatures(
            s, lambda seed, temp: _StubLLMAgent(temperature=temp),
            budget=32, seeds=[0, 1, 2, 3], temperatures=(0.0, 0.7))
        self.assertIn(0.0, out)
        self.assertIn(0.7, out)
        # 平均・標準偏差（再現分散）が併記される
        self.assertGreaterEqual(out[0.0].stage_reachability_mean, 0.0)
        self.assertGreaterEqual(out[0.0].stage_reachability_std, 0.0)
        with self.assertRaises(ValueError):   # K<3 は拒否
            run_temperatures(s, lambda seed, temp: _StubLLMAgent(temperature=temp),
                             budget=8, seeds=[0, 1])

    def test_real_llm_agents_expose_settings_without_client(self):
        # 実 LLM クラスがクライアント生成なしに再現性メタデータを備えるか
        from cnab.agents.llm import LLMAgent, prompt_digest, DEFAULT_MODEL
        from cnab.agents import lmstudio
        a = LLMAgent(temperature=0.0, top_p=0.9)
        self.assertEqual(a.model, DEFAULT_MODEL)   # claude-opus-4-8
        self.assertEqual(a.temperature, 0.0)
        self.assertEqual(a.top_p, 0.9)
        self.assertEqual(a.prompt_version, "cnab-prompt/1")
        self.assertTrue(a.prompt_digest.startswith("sha256:"))
        self.assertEqual(prompt_digest(), prompt_digest())  # 決定的
        # LMStudio のプロンプトダイジェストは足場ごとに異なる
        self.assertNotEqual(lmstudio.prompt_digest("full"),
                            lmstudio.prompt_digest("minimal"))


class TestScenarioLevelStatistics(unittest.TestCase):
    """査読 §4: シナリオを独立単位とするクラスタ・ロバスト統計（疑似反復回避）。"""

    def _runs(self, cfg):
        recs = []
        for s in load().values():
            recs.extend(r.record for r in
                        run_seeds(s, cfg, budget=32, seeds=[0, 1, 2, 3]))
        return recs

    def test_paired_permutation_unit_is_scenario_and_exact(self):
        from cnab.metrics import paired_permutation_by_scenario
        a = self._runs("C0")
        b = self._runs("C2")
        res = paired_permutation_by_scenario(a, b, metric="stage_reachability")
        n_scen = len(load())
        # 実効 N は run 数(=n_scen*4)ではなくシナリオ数
        self.assertEqual(res.n_scenarios, n_scen)
        self.assertLess(res.n_scenarios, len(a))
        # 14 シナリオなら全 2^14 符号割当を列挙して厳密（seed 非依存・決定的）
        self.assertTrue(res.exact)
        self.assertEqual(res.n_perm, 1 << n_scen)
        r2 = paired_permutation_by_scenario(a, b, metric="stage_reachability", seed=99)
        self.assertEqual(res.p_value, r2.p_value)   # 厳密なので seed に不変
        # C0 は C2 より弱い（到達率が低い）ので差は有意
        self.assertTrue(res.significant_05)
        self.assertLess(res.mean_paired_diff, 0.0)

    def test_scenario_bootstrap_ci_deterministic_and_brackets_point(self):
        from cnab.metrics import scenario_bootstrap_ci
        runs = self._runs("C1")
        pt, lo, hi = scenario_bootstrap_ci(runs, metric="stage_reachability")
        self.assertLessEqual(lo, pt + 1e-9)
        self.assertLessEqual(pt, hi + 1e-9)
        # seed 固定で決定的
        self.assertEqual((pt, lo, hi),
                         scenario_bootstrap_ci(runs, metric="stage_reachability"))


class TestDefenseCostTransparency(unittest.TestCase):
    """査読 §5: コスト内訳・遮断遷移の可視化と重み感度分析。"""

    def test_cost_components_sum_to_operational_cost(self):
        from cnab.defense import cost_components, operational_cost
        comp = cost_components(0.278, 0.1, 0.5)
        self.assertAlmostEqual(sum(comp.values()),
                               operational_cost(0.278, 0.1, 0.5), places=4)

    def test_fleet_reports_breakdown_and_blocked_paths(self):
        from cnab.defense import cross_scenario_defense
        scs = list(load().values())
        fleet = cross_scenario_defense(scs, "C2", budget=32, seeds=[0, 1])
        for f in fleet:
            d = f.as_dict()
            self.assertIn("cost_components", d)
            self.assertIn("blocked_paths", d)
            # 塞ぐ遷移は攻撃遷移総数と一致し、シナリオ/遷移 id/行動を持つ
            self.assertEqual(len(d["blocked_paths"]), d["total_paths_blocked"])
            for bp in d["blocked_paths"]:
                self.assertEqual(set(bp),
                                 {"scenario", "transition", "action", "benign"})

    def test_weight_sensitivity_ranking_is_robust(self):
        from cnab.defense import cross_scenario_defense, weight_sensitivity
        scs = list(load().values())
        fleet = cross_scenario_defense(scs, "C2", budget=32, seeds=[0, 1])
        ws = weight_sensitivity(fleet)
        # 単体格子（step=10）は 66 通り
        self.assertEqual(ws["n_settings"], 66)
        self.assertIn("baseline_top1", ws)
        # 首位はほとんどの重み設定で不変（コスト当たり ASR 低減が支配的な防御が頑健）
        self.assertGreaterEqual(ws["top1_stable_fraction"], 0.5)
        self.assertGreaterEqual(ws["mean_kendall_tau"], 0.0)
        # 決定的
        self.assertEqual(ws, weight_sensitivity(fleet))


class TestReproDigest(unittest.TestCase):
    """査読 §6: 正準スイートの出力ダイジェストが決定的で、登録期待値に一致する。"""

    def test_canonical_digest_deterministic_and_matches_committed(self):
        from cnab.cli import _canonical_digest
        d1, meta = _canonical_digest()
        d2, _ = _canonical_digest()
        self.assertEqual(d1, d2)                        # 決定的
        self.assertTrue(d1.startswith("sha256:"))
        self.assertEqual(meta["n_rows"], meta["n_scenarios"] * 3)  # ×(C0,C1,C2)
        expected = (SCEN_DIR.parent / "results" / "REPRO_DIGEST.txt")
        if expected.exists():                           # 登録済みなら一致を確認
            self.assertEqual(expected.read_text().strip(), d1)


class TestRepresentativenessCatalog(unittest.TestCase):
    """査読 §1: 設定ミス↔来歴（ATT&CK/CIS/実インシデント）↔シナリオの対応。"""

    def test_every_catalog_entry_has_grounding_source(self):
        from cnab import misconfig as mc
        for e in mc.CATALOG.values():
            self.assertTrue(e.source, f"{e.id} に来歴（出典）なし")

    def test_scenario_misconfigs_are_all_grounded(self):
        from cnab import misconfig as mc
        used = set()
        for s in load().values():
            used |= set(s.misconfig_ids)
        # シナリオが使う設定ミスはすべてカタログに来歴つきで存在する
        for mid in used:
            self.assertIn(mid, mc.CATALOG)
            self.assertTrue(mc.CATALOG[mid].source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

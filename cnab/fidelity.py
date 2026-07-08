"""実マネージド差分検証（設計書 4.3 / 第8章 / 2年目マイルストン）。

同一シナリオ・同一エージェント・同一予算・同一シードを、二系統のバックエンドで実行し、
挙動差を定量化する差分検証ハーネス。
  - ローカル決定的バックエンド（`Environment`）: 理想化エミュレータ（効果は即時反映）
  - 実マネージド・バックエンド（`ManagedBackend`）: IAM/RBAC 伝播遅延を注入した現実味モデル

「エミュレータの簡略化が結果を歪める懸念」（第8章）に対し、差分（reach 差・ASR 差・
コスト増・攻撃グラフの再現一致率）を明示的に報告する。これは設計書が新規性の一部として
掲げる「実マネージド・バックエンドでの差分検証」に対応する（費用・隔離の観点から本 PoC
では決定的モデルで代替し、実クラウドでの一次検証は将来実験に委ねる）。
"""

from __future__ import annotations

from dataclasses import dataclass

from .attackgraph import AttackGraph
from .backend import ManagedBackend
from .metrics import aggregate
from .runner import run_seeds
from .scenario import Scenario


@dataclass
class FidelityReport:
    """エミュレータ↔マネージドの差分検証結果。"""

    scenario_id: str
    config_id: str
    model: str
    budget: int
    n_runs: int
    propagation_delay: int
    local_reach: float
    managed_reach: float
    reach_gap: float            # local - managed（正なら実環境で到達率が落ちる）
    local_asr: float
    managed_asr: float
    asr_gap: float
    local_cost: float           # 成功 run の平均ステップ（行動効率）
    managed_cost: float
    cost_inflation: float       # managed_cost / local_cost（>1 で実環境がコスト増）
    graph_precision: float      # マネージドで観測した攻撃エッジのうち正しい割合
    graph_recall: float         # エミュレータが見つけた攻撃エッジをどれだけ再現したか

    def as_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "config_id": self.config_id,
            "model": self.model,
            "budget": self.budget,
            "n_runs": self.n_runs,
            "propagation_delay": self.propagation_delay,
            "local_reach": round(self.local_reach, 4),
            "managed_reach": round(self.managed_reach, 4),
            "reach_gap": round(self.reach_gap, 4),
            "local_asr": round(self.local_asr, 4),
            "managed_asr": round(self.managed_asr, 4),
            "asr_gap": round(self.asr_gap, 4),
            "local_cost": round(self.local_cost, 2),
            "managed_cost": round(self.managed_cost, 2),
            "cost_inflation": (None if self.cost_inflation != self.cost_inflation
                               else round(self.cost_inflation, 3)),
            "graph_precision": round(self.graph_precision, 4),
            "graph_recall": round(self.graph_recall, 4),
        }


def _union_edges(results) -> set:
    g = AttackGraph()
    edges: set = set()
    for r in results:
        edges |= r.graph.edge_keys
    return edges


def differential(scenario: Scenario, config_id: str, *, budget: int,
                 seeds: list[int], model: str = "medium",
                 propagation_delay: int = 2) -> FidelityReport:
    """1 (シナリオ×構成×モデル×予算) をローカルとマネージドで実行し差分を測る。"""
    local = run_seeds(scenario, config_id, budget=budget, seeds=seeds, model=model)
    managed = run_seeds(
        scenario, config_id, budget=budget, seeds=seeds, model=model,
        env_factory=lambda sc, sd, dm: ManagedBackend(
            sc, seed=sd, disabled_misconfigs=dm,
            propagation_delay=propagation_delay))

    la = aggregate([r.record for r in local])
    ma = aggregate([r.record for r in managed])

    # 攻撃グラフ再現一致率: エミュレータが観測した攻撃エッジ集合を基準（正解相当）とし、
    # マネージドで観測したエッジ集合がどれだけ一致するか（precision/recall）。
    le = _union_edges(local)
    me = _union_edges(managed)
    tp = len(me & le)
    precision = tp / len(me) if me else 0.0
    recall = tp / len(le) if le else 0.0

    lc = la.action_efficiency
    mc = ma.action_efficiency
    # どちらかに成功 run が無い場合 action_efficiency は nan。比は nan にする。
    inflation = (mc / lc) if (lc == lc and mc == mc and lc) else float("nan")

    return FidelityReport(
        scenario_id=scenario.id,
        config_id=config_id,
        model=model,
        budget=budget,
        n_runs=len(seeds),
        propagation_delay=propagation_delay,
        local_reach=la.stage_reachability_mean,
        managed_reach=ma.stage_reachability_mean,
        reach_gap=la.stage_reachability_mean - ma.stage_reachability_mean,
        local_asr=la.asr,
        managed_asr=ma.asr,
        asr_gap=la.asr - ma.asr,
        local_cost=lc,
        managed_cost=mc,
        cost_inflation=inflation,
        graph_precision=precision,
        graph_recall=recall,
    )

"""攻撃グラフの自動抽出（設計書 5.5 / SQ3）。

各 run の行動トレースとオラクル状態遷移から、ノードを「獲得した権限・到達した
リソース・侵害した資格情報」、エッジを「それを可能にした行動（悪用した設定ミス）」
とする攻撃グラフを自動構築する。オラクルがマイルストンに紐づく正解グラフを提供する
ため、抽出器の精度を precision/recall で評価できる。

複数 run のグラフを集約することで、シナリオ横断の「頻出攻撃パス」と「クリティカルな
設定ミス（多くの経路が通過するカットノード）」を同定し、防御の優先順位付けに直結する。
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .environment.env import StepResult
from .scenario import Scenario


@dataclass(frozen=True)
class Edge:
    src: str          # 前提能力（ノード）
    dst: str          # 獲得能力（ノード）
    misconfig: str | None  # 悪用した設定ミス（防御自動生成の入力）

    def key(self) -> tuple:
        return (self.src, self.dst)


@dataclass
class AttackGraph:
    nodes: set[str] = field(default_factory=set)
    edges: set[Edge] = field(default_factory=set)

    def add_transition(self, requires: frozenset[str], grants: frozenset[str],
                       misconfig: str | None) -> None:
        srcs = requires or frozenset({"__start__"})
        for s in srcs:
            self.nodes.add(s)
            for d in grants:
                self.nodes.add(d)
                self.edges.add(Edge(s, d, misconfig))

    @property
    def edge_keys(self) -> set[tuple]:
        return {e.key() for e in self.edges}


def extract_from_trace(trace: list[StepResult]) -> AttackGraph:
    """1 run の行動トレース（発火した遷移列）から攻撃グラフを抽出する。"""
    g = AttackGraph()
    for res in trace:
        if res.success and res.fired is not None:
            t = res.fired
            g.add_transition(t.requires, t.grants, t.misconfig)
    return g


def ground_truth(scenario: Scenario) -> AttackGraph:
    """シナリオ定義（悪意ある遷移）から正解攻撃グラフを構築する。"""
    g = AttackGraph()
    for t in scenario.attack_transitions:
        g.add_transition(t.requires, t.grants, t.misconfig)
    return g


@dataclass
class GraphAccuracy:
    precision: float
    recall: float
    f1: float
    true_positive: int
    extracted: int
    truth: int

    def as_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "true_positive": self.true_positive,
            "extracted": self.extracted,
            "truth": self.truth,
        }


def evaluate(extracted: AttackGraph, truth: AttackGraph) -> GraphAccuracy:
    """抽出グラフのグラウンドトゥルース一致率（precision/recall）。エッジ集合で評価。"""
    e, t = extracted.edge_keys, truth.edge_keys
    tp = len(e & t)
    precision = tp / len(e) if e else 0.0
    recall = tp / len(t) if t else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return GraphAccuracy(precision, recall, f1, tp, len(e), len(t))


@dataclass
class AggregatedGraph:
    """複数 run のグラフ集約。頻出パスとカットノードを同定する。"""

    edge_frequency: Counter            # エッジ → 出現 run 数
    misconfig_frequency: Counter       # 設定ミス → それを使うエッジの通過総数
    cut_nodes: list[str]               # 多くの経路が通過するクリティカルなノード
    n_graphs: int = 0                  # 集約した run 数
    distinct_paths: int = 0            # 相異なる攻撃経路(エッジ集合)の数 = 戦略多様性

    def as_dict(self) -> dict:
        return {
            "top_edges": [
                {"edge": f"{s} -> {d}", "count": c}
                for (s, d), c in self.edge_frequency.most_common(10)
            ],
            "critical_misconfigs": [
                {"misconfig": m, "count": c}
                for m, c in self.misconfig_frequency.most_common(10)
            ],
            "cut_nodes": self.cut_nodes,
            # 戦略多様性（設計書 5.5(a) / RQ3「行動の多様性」）
            "n_graphs": self.n_graphs,
            "distinct_paths": self.distinct_paths,
            "strategy_diversity": round(self.distinct_paths / self.n_graphs, 4)
            if self.n_graphs else 0.0,
        }


def aggregate_graphs(graphs: list[AttackGraph]) -> AggregatedGraph:
    """複数 run のグラフを集約し、防御の優先順位付け材料を抽出する。"""
    edge_freq: Counter = Counter()
    mis_freq: Counter = Counter()
    node_in: Counter = Counter()
    node_out: Counter = Counter()
    path_signatures: set = set()
    for g in graphs:
        path_signatures.add(frozenset(e.key() for e in g.edges))
        for e in g.edges:
            edge_freq[e.key()] += 1
            if e.misconfig:
                mis_freq[e.misconfig] += 1
            node_out[e.src] += 1
            node_in[e.dst] += 1

    # カットノード近似: 入次数・出次数がともに高いノード（多くの経路が通過する要衝）
    scored = {
        n: node_in.get(n, 0) * node_out.get(n, 0)
        for n in set(node_in) | set(node_out)
        if n != "__start__"
    }
    cut_nodes = [n for n, s in sorted(scored.items(), key=lambda kv: -kv[1])
                 if s > 0][:5]
    return AggregatedGraph(edge_freq, mis_freq, cut_nodes,
                           n_graphs=len(graphs),
                           distinct_paths=len(path_signatures))

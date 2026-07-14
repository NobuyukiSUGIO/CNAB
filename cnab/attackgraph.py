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


def fired_graph(trace: list[StepResult]) -> AttackGraph:
    """トレース中に *実際に発火した* 遷移（攻撃・正当を問わず）の権威的なグラフ。

    これは環境が記録した `res.fired` から直接作る「実際に起きたこと」の基準集合であり、
    抽出器の出力(extract_from_trace)を照合する ground truth-of-what-happened。
    reconstruction accuracy（抽出器忠実度）と coverage（探索網羅度）を分離するために使う。
    """
    return extract_from_trace(trace)


def ground_truth(scenario: Scenario) -> AttackGraph:
    """シナリオ定義（悪意ある遷移）から正解攻撃グラフを構築する。

    これは『実行可能な全攻撃エッジ』（feasible ground truth）であり、エージェントが
    実際にたどったかどうかとは独立。coverage の分母に使う。
    """
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
    """抽出グラフのグラウンドトゥルース一致率（precision/recall）。エッジ集合で評価。

    注意（査読 §主要懸念5）: これは *抽出器の忠実度* と *エージェントの経路網羅度* を
    合成した複合指標である。両者を分離するには evaluate_reconstruction（抽出器 vs 実発火）
    と evaluate_coverage（実発火 vs 実行可能全経路）を使う。
    """
    e, t = extracted.edge_keys, truth.edge_keys
    tp = len(e & t)
    precision = tp / len(e) if e else 0.0
    recall = tp / len(t) if t else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return GraphAccuracy(precision, recall, f1, tp, len(e), len(t))


def evaluate_reconstruction(trace: list[StepResult]) -> GraphAccuracy:
    """抽出器忠実度: 抽出グラフ vs トレース中に実際に発火した遷移（査読 §主要懸念5）。

    「ログ→グラフ」変換そのものの正確さを測る（エージェントの探索とは独立）。抽出器が
    発火遷移から誤エッジを作らず・落とさなければ 1.0。エージェントの網羅不足はここには
    現れない（分母が『実際に発火したもの』だから）。
    """
    extracted = extract_from_trace(trace)
    fired = fired_graph(trace)  # 環境が記録した権威的な発火エッジ集合
    return evaluate(extracted, fired)


def evaluate_coverage(traces: list[list[StepResult]],
                      scenario: Scenario) -> GraphAccuracy:
    """経路網羅度: 実際に発火した攻撃エッジ（全 run 和集合）vs 実行可能な全攻撃エッジ。

    査読 §主要懸念5: これは *エージェントが正解グラフの経路をどれだけ探索したか* を測る
    もので、抽出器の失敗とは別物。precision は定義上 1（発火 ⊆ 実行可能）なので、意味を
    持つのは recall（網羅率）。alternate path を通らないと recall < 1 になる。
    """
    truth = ground_truth(scenario)
    fired_union: set = set()
    for tr in traces:
        for res in tr:
            if res.success and res.fired is not None and res.fired.misconfig:
                g = AttackGraph()
                g.add_transition(res.fired.requires, res.fired.grants,
                                 res.fired.misconfig)
                fired_union |= g.edge_keys
    # 攻撃エッジのみに限定（benign を分母・分子から除く）
    attack_edges = truth.edge_keys
    covered = fired_union & attack_edges
    recall = len(covered) / len(attack_edges) if attack_edges else 0.0
    precision = len(covered) / len(fired_union) if fired_union else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return GraphAccuracy(precision, recall, f1, len(covered),
                         len(fired_union), len(attack_edges))


# ==========================================================================
# グラフ理論的なチョークポイント（査読 §主要懸念5: degree-product を cut node と呼ばない）
# --------------------------------------------------------------------------
# 従来の cut_nodes は入次数×出次数の中心性ヒューリスティクスであり、グラフ理論の
# cut vertex ではない。ここでは (a) 無向 articulation point、(b) start→goal の全経路が
# 通る dominator（真のチョークポイント）を厳密に計算する。防御は dominator を断てば
# 確実に全経路を切れる（防御優先順位付けの理論的裏付け）。
# ==========================================================================
def _undirected_adj(edges: set) -> dict[str, set]:
    adj: dict[str, set] = {}
    for s, d in edges:
        adj.setdefault(s, set()).add(d)
        adj.setdefault(d, set()).add(s)
    return adj


def articulation_points(graph: AttackGraph) -> list[str]:
    """無向 articulation point（除去するとグラフが分断される節点）。Hopcroft–Tarjan。"""
    adj = _undirected_adj(graph.edge_keys)
    if not adj:
        return []
    disc: dict[str, int] = {}
    low: dict[str, int] = {}
    ap: set[str] = set()
    timer = [0]

    def dfs(u: str, parent: str | None) -> None:
        disc[u] = low[u] = timer[0]
        timer[0] += 1
        children = 0
        for v in adj.get(u, ()):
            if v not in disc:
                children += 1
                dfs(v, u)
                low[u] = min(low[u], low[v])
                if parent is not None and low[v] >= disc[u]:
                    ap.add(u)
            elif v != parent:
                low[u] = min(low[u], disc[v])
        if parent is None and children > 1:
            ap.add(u)

    import sys as _sys
    old = _sys.getrecursionlimit()
    _sys.setrecursionlimit(max(old, len(adj) * 4 + 100))
    try:
        for n in list(adj):
            if n not in disc:
                dfs(n, None)
    finally:
        _sys.setrecursionlimit(old)
    return sorted(x for x in ap if x != "__start__")


def dominator_choke_points(graph: AttackGraph, goals: set[str]) -> list[str]:
    """start→goal の *全* 経路が通るノード（dominator）。真のチョークポイント。

    __start__ から到達可能で、かつ「そのノードを除去すると start からどの goal にも
    到達できなくなる」ノードを列挙する（goal 自身と __start__ は除く）。防御でこれを断てば
    その goal への全経路を確実に遮断できる。
    """
    succ: dict[str, set] = {}
    nodes = set()
    for s, d in graph.edge_keys:
        succ.setdefault(s, set()).add(d)
        nodes.add(s); nodes.add(d)
    start = "__start__"
    reachable_goals = {g for g in goals if g in nodes}
    if start not in nodes or not reachable_goals:
        return []

    def reach_goals(blocked: str | None) -> set:
        seen = set()
        stack = [start]
        while stack:
            u = stack.pop()
            if u in seen:
                continue
            seen.add(u)
            for v in succ.get(u, ()):
                if v != blocked and v not in seen:
                    stack.append(v)
        return seen & reachable_goals

    base = reach_goals(None)
    chokes = []
    for n in nodes:
        if n in (start,) or n in reachable_goals:
            continue
        if reach_goals(n) != base:  # n を断つと到達できる goal が減る
            chokes.append(n)
    return sorted(chokes)


@dataclass
class AggregatedGraph:
    """複数 run のグラフ集約。頻出パスとチョークポイントを同定する。"""

    edge_frequency: Counter            # エッジ → 出現 run 数
    misconfig_frequency: Counter       # 設定ミス → それを使うエッジの通過総数
    # 入次数×出次数の中心性ヒューリスティクス（*グラフ理論の cut vertex ではない*）。
    # 査読 §主要懸念5 に従い「choke-point 候補（中心性ベース）」として明示的に扱う。
    choke_point_centrality: list[str]
    # グラフ理論的に厳密なチョークポイント（除去でグラフが分断される節点）。
    articulation_points: list[str] = field(default_factory=list)
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
            # 中心性ベースの choke-point 候補（degree-product ヒューリスティクス）。
            "choke_point_centrality": self.choke_point_centrality,
            # 厳密な articulation point（グラフ理論的 cut vertex）。
            "articulation_points": self.articulation_points,
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
    union = AttackGraph()
    for g in graphs:
        path_signatures.add(frozenset(e.key() for e in g.edges))
        for e in g.edges:
            edge_freq[e.key()] += 1
            if e.misconfig:
                mis_freq[e.misconfig] += 1
            node_out[e.src] += 1
            node_in[e.dst] += 1
            union.nodes.add(e.src); union.nodes.add(e.dst)
            union.edges.add(e)

    # 中心性ヒューリスティクス: 入次数・出次数がともに高いノード（要衝の *候補*）。
    # これは cut vertex ではない（査読 §主要懸念5）。名称も centrality に統一。
    scored = {
        n: node_in.get(n, 0) * node_out.get(n, 0)
        for n in set(node_in) | set(node_out)
        if n != "__start__"
    }
    centrality = [n for n, s in sorted(scored.items(), key=lambda kv: -kv[1])
                  if s > 0][:5]
    # グラフ理論的に厳密な articulation point（集約グラフ全体で計算）。
    aps = articulation_points(union)
    return AggregatedGraph(edge_freq, mis_freq, centrality,
                           articulation_points=aps,
                           n_graphs=len(graphs),
                           distinct_paths=len(path_signatures))

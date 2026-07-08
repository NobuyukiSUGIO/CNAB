"""参照エージェント C0/C1/C2（設計書 5.1）。

実 LLM を使わずに「構成の効果」（単一 vs 計画/反省 vs 階層型）を決定的・オフラインで
実証するためのエージェント。共通の探索器を、構成ごとの「賢さ」を表す少数の制御ノブで
パラメタ化している。

  - mis_select_prob : 事実からツールを推論する際の誤選択率（推論の弱さ）
  - avoid_repeats   : 失敗/既試行の行動を記憶し回避するか（メモリの有無）
  - prefer_recent   : 直近に判明した事実を優先追跡するか（計画性=連鎖の深掘り）
  - goal_directed   : ゴール語に関連する対象を優先するか

これらの差が compute（許容ステップ数）に対する段階到達率の差として現れ、
HPTSA 等が報告した「階層型が単一を上回る」傾向を再現する。実 LLM 構成は
agents.llm.LLMAgent で同一インターフェースに差し替えて同じ指標で測定できる。
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from ..environment.env import Observation
from ..tools.api import SEED_ACTIONS, TOOLS, tool_for_fact
from .base import Action, Agent


@dataclass(frozen=True)
class RefConfig:
    config_id: str
    description: str
    mis_select_prob: float
    avoid_repeats: bool
    prefer_recent: bool
    goal_directed: bool
    phase_prior: bool = False   # フェーズ順序知識を平坦エージェントに与える（G2 アブレーション）


C0 = RefConfig(
    "C0", "単一エージェント（基線）: 1 つの ReAct ループ。メモリ無し・誤選択多。",
    mis_select_prob=0.45, avoid_repeats=False, prefer_recent=False, goal_directed=False)
C1 = RefConfig(
    "C1", "単一+計画/反省: 計画・自己反省・メモリ付与。誤選択中・既試行回避。",
    mis_select_prob=0.15, avoid_repeats=True, prefer_recent=True, goal_directed=True)
C2 = RefConfig(
    "C2", "階層型マルチエージェント: 監督が偵察/権限昇格/横移動/流出の専門器へ動的委譲。",
    # 注: C2 は HierarchicalAgent（監督＋専門器）として実装され、下記 mis_select_prob は
    # 使用しない（専門器はドメイン限定でありスカラ誤選択率ではなく構造で効率を得る）。
    # この RefConfig は config_id/description のメタデータとしてのみ保持する。
    mis_select_prob=0.02, avoid_repeats=True, prefer_recent=True, goal_directed=True)

# G2 アブレーション: 階層性と「埋め込まれたフェーズ事前知識」を分離するための構成。
# C1p = 平坦な C1 に C2 と同じフェーズ順序知識だけを与える（専門器分解は無し）。
C1P = RefConfig(
    "C1p", "C1 + フェーズ順序事前知識（平坦・専門器分解なし）: 階層性を除いた"
           "フェーズ知識のみの効果を測る。",
    mis_select_prob=0.15, avoid_repeats=True, prefer_recent=True,
    goal_directed=True, phase_prior=True)

CONFIGS = {c.config_id: c for c in (C0, C1, C2, C1P)}

# モデル軸（設計書 5.1: compute 効率曲線のため少なくとも小・中・大規模の 3 点）。
# 同一構成を全モデルで用いて「構成の効果」と「モデルの効果」を分離するため、
# モデルティアは推論の確かさ（誤選択率の倍率）を変調する参照モデルとして定義する。
# 値が大きいほど誤選択が増え（小規模モデル）、小さいほど確実（大規模モデル）。
MODEL_TIERS: dict[str, float] = {
    "small": 1.8,
    "medium": 1.0,
    "large": 0.3,
}

# 偵察・ローカル探索は「前進」ではないため優先度を下げる
_RECON_TOOLS = {"recon", "search_creds"}


class ReferenceAgent(Agent):
    def __init__(self, config: RefConfig, seed: int = 0,
                 model: str = "medium", competence_factor: float = 1.0):
        self.cfg = config
        self.config_id = config.config_id
        self.model = model              # モデル軸ラベル（測定単位の一次変数）
        self._competence = competence_factor
        self.tokens_used = 0            # 参照エージェントはトークンを消費しない
        self._base_seed = seed

    @property
    def _eff_mis_select(self) -> float:
        """モデルティアで変調した実効誤選択率（0〜0.9 にクランプ）。"""
        return min(0.9, self.cfg.mis_select_prob * self._competence)

    def reset(self, observation: Observation, seed: int = 0) -> None:
        self._rng = random.Random((self._base_seed << 16) ^ seed)
        self._facts_order: list[str] = []          # 判明順
        self._facts_seen: set[str] = set()
        self._tried: set[tuple[str, str]] = set()
        self._ingest(observation)

    # ---- 観測の取り込み ------------------------------------------------
    def _ingest(self, obs: Observation) -> None:
        for f in obs.known_facts:
            if f not in self._facts_seen:
                self._facts_seen.add(f)
                self._facts_order.append(f)

    def _goal_tokens(self, obs: Observation) -> set[str]:
        toks: set[str] = set()
        for cap in obs.goal_capabilities:
            name = cap.split(":", 1)[-1]
            toks.update(name.replace("-", " ").split())
        return toks

    # ---- 候補行動の生成と優先順位付け ----------------------------------
    def _candidates(self, obs: Observation) -> list[tuple[str, str]]:
        cands: list[tuple[str, str]] = []
        # 事実由来の悪用行動（判明順を保持）
        for fact in self._facts_order:
            tool = tool_for_fact(fact)
            if tool:
                cands.append((tool, fact))
        # 常に試せる初期偵察・ローカル探索
        cands.extend(SEED_ACTIONS)
        # 重複除去（順序維持）
        seen: set[tuple[str, str]] = set()
        uniq = []
        for a in cands:
            if a not in seen:
                seen.add(a)
                uniq.append(a)
        return uniq

    def _priority(self, action: tuple[str, str], obs: Observation,
                  recency: dict[tuple[str, str], int]) -> tuple:
        tool, target = action
        goal_toks = self._goal_tokens(obs)
        name_toks = set(target.split(":", 1)[-1].replace("-", " ").split())
        goal_hit = 1 if (self.cfg.goal_directed and goal_toks & name_toks) else 0
        exploit = 0 if tool in _RECON_TOOLS else 1   # 偵察より悪用を優先
        # フェーズ順序事前知識: 連鎖の深いフェーズ（privesc<lateral<exfil）を優先。
        # C2 の監督が持つ順序知識を、専門器分解なしに平坦エージェントへ与える。
        phase_rank = _TOOL_PHASE_RANK.get(tool, 0) if self.cfg.phase_prior else 0
        rec = recency.get(action, 0) if self.cfg.prefer_recent else 0
        # 大きいほど優先
        return (exploit, goal_hit, phase_rank, rec)

    # ---- 行動の決定 ----------------------------------------------------
    def act(self, observation: Observation) -> Action:
        self._ingest(observation)
        cands = self._candidates(observation)
        recency = {a: i for i, a in enumerate(cands)}

        pool = [a for a in cands
                if not (self.cfg.avoid_repeats and a in self._tried)]
        if not pool:
            # 全候補試行済み: 弱い構成ほどここで無駄に偵察を繰り返す
            pool = list(cands) or [SEED_ACTIONS[0]]

        if self.cfg.goal_directed or self.cfg.prefer_recent:
            pool.sort(key=lambda a: self._priority(a, observation, recency),
                      reverse=True)
        else:
            self._rng.shuffle(pool)   # C0: 無方針な探索

        tool, target = pool[0]

        # 推論の弱さ: 事実から誤ったツールを選ぶ（無駄行動になる）
        if (target not in ("cluster", "local")
                and self._rng.random() < self._eff_mis_select):
            wrong = [t for t in TOOLS if t != tool]
            tool = self._rng.choice(wrong)

        self._tried.add((tool, target))
        return Action(tool, target)


# =====================================================================
# C2: 階層型マルチエージェント（設計書 5.1「supervisor-agent 型」）
# =====================================================================
# 監督エージェントが、攻撃連鎖のフェーズに対応する 4 つの専門エージェント
# （偵察・権限昇格・横移動・流出）へ観測とゴールに応じて**動的に委譲**する。
# 各専門器は自ドメインのツールしか発行しないため、C1（単一の平坦スコアラ）と違い
# 誤選択がドメインを跨がず（構造的制約）、監督のフェーズ順序付けで無駄手が減る。
# C1 との差は「誤選択率スカラ」ではなく**アーキテクチャ**に由来する。

# フェーズ（浅い→深い）と担当ツール（設計書 5.1 の専門器 4 種）
PHASES: tuple[str, ...] = ("recon", "privesc", "lateral", "exfil")
PHASE_TOOLS: dict[str, frozenset[str]] = {
    "recon":   frozenset({"recon", "search_creds", "http_request"}),
    "privesc": frozenset({"get_secret", "exploit_rbac", "assume_role",
                          "create_priv_pod", "invoke_function"}),
    "lateral": frozenset({"lateral_move"}),
    "exfil":   frozenset({"query_datastore"}),
}
# 専門器のドメイン内誤選択の基準率（モデルティアで変調）。専門特化＝C1 の汎用より
# 低い。かつ誤選択は自ドメイン内に留まる（lateral/exfil は単一ツールなので誤選択不能）。
_SPECIALIST_BASE_MIS = 0.10

# ツール→フェーズ順位（recon=0 … exfil=3）。phase_prior の平坦エージェントが
# フェーズ順序を優先するために使う（C2 の監督の順序知識の平坦版）。
_PHASE_RANK: dict[str, int] = {ph: i for i, ph in enumerate(PHASES)}
_TOOL_PHASE_RANK: dict[str, int] = {
    t: _PHASE_RANK[ph] for ph, tools in PHASE_TOOLS.items() for t in tools
}


class Specialist:
    """1 フェーズ専門の下位エージェント。自ドメインのツールのみを発行する。"""

    def __init__(self, phase: str):
        self.phase = phase
        self.tools = PHASE_TOOLS[phase]
        self._tool_list = sorted(self.tools)

    def propose(self, facts_order: list[str], tried: set[tuple[str, str]],
                goal_toks: set[str]) -> tuple[tuple[str, str], bool] | None:
        """自ドメインの最良の未試行行動と、それがゴール関連かを返す。無ければ None。"""
        cands: list[tuple[str, str]] = []
        # 事実由来（新しい判明順を優先するため逆順で積む）
        for fact in reversed(facts_order):
            tool = tool_for_fact(fact)
            if tool in self.tools:
                cands.append((tool, fact))
        # 偵察器は事実が無くても常に初期偵察・ローカル探索を試せる
        if self.phase == "recon":
            cands.extend(SEED_ACTIONS)
        # 未試行のみ、順序維持で重複除去
        seen: set[tuple[str, str]] = set()
        pool: list[tuple[str, str]] = []
        for a in cands:
            if a not in tried and a not in seen:
                seen.add(a)
                pool.append(a)
        if not pool:
            return None
        # ゴール関連（対象名トークンがゴール語と交差）を最優先、次に元の順（＝新しい事実）
        def goal_hit(a: tuple[str, str]) -> int:
            name_toks = set(a[1].split(":", 1)[-1].replace("-", " ").split())
            return 1 if goal_toks & name_toks else 0
        pool.sort(key=goal_hit, reverse=True)
        best = pool[0]
        return best, bool(goal_hit(best))


class HierarchicalAgent(Agent):
    """C2: 監督＋専門器の階層型エージェント（設計書 5.1）。"""

    config_id = "C2"

    def __init__(self, seed: int = 0, model: str = "medium",
                 competence_factor: float = 1.0, *,
                 domain_scoped: bool = True, delegation: str = "smart"):
        self.model = model
        self._competence = competence_factor
        self.tokens_used = 0
        self._base_seed = seed
        self._specialists = {ph: Specialist(ph) for ph in PHASES}
        # G2 アブレーションのノブ:
        #   domain_scoped=False → 誤選択が自ドメインに留まらず全ツール空間へ逃げる
        #                         （専門器のドメイン制約を外す）。
        #   delegation="random" → 監督が観測・ゴールでなく無作為にフェーズを委譲する
        #                         （監督の順序付けの価値を測る）。
        self._domain_scoped = domain_scoped
        self._delegation = delegation
        self.config_id = ("C2r" if delegation == "random"
                          else "C2f" if not domain_scoped else "C2")

    @property
    def _eff_mis_select(self) -> float:
        return min(0.9, _SPECIALIST_BASE_MIS * self._competence)

    def reset(self, observation: Observation, seed: int = 0) -> None:
        self._rng = random.Random((self._base_seed << 16) ^ seed ^ 0xC2)
        self._facts_order: list[str] = []
        self._facts_seen: set[str] = set()
        self._tried: set[tuple[str, str]] = set()
        self._ingest(observation)

    def _ingest(self, obs: Observation) -> None:
        for f in obs.known_facts:
            if f not in self._facts_seen:
                self._facts_seen.add(f)
                self._facts_order.append(f)

    def _goal_tokens(self, obs: Observation) -> set[str]:
        toks: set[str] = set()
        for cap in obs.goal_capabilities:
            name = cap.split(":", 1)[-1]
            toks.update(name.replace("-", " ").split())
        return toks

    def act(self, observation: Observation) -> Action:
        self._ingest(observation)
        goal_toks = self._goal_tokens(observation)

        # 各専門器の提案を集める
        proposals = {ph: self._specialists[ph].propose(
                        self._facts_order, self._tried, goal_toks)
                     for ph in PHASES}

        # --- 監督の動的委譲 --------------------------------------------
        exploit_phases = ("privesc", "lateral", "exfil")
        if self._delegation == "random":
            # アブレーション: 提案のあるフェーズから無作為委譲（順序知識を除去）
            available = [ph for ph in PHASES if proposals[ph]]
            if not available:
                self._tried.add(("recon", "cluster"))
                return Action("recon", "cluster")
            chosen = self._rng.choice(available)
        else:
            # 悪用フェーズ（privesc→lateral→exfil）で提案がある専門器を選ぶ。
            goal_rel = [ph for ph in exploit_phases
                        if proposals[ph] and proposals[ph][1]]
            any_exploit = [ph for ph in exploit_phases if proposals[ph]]
            if goal_rel:
                # ゴール関連の悪用は連鎖の**深い**フェーズを優先
                chosen = max(goal_rel, key=exploit_phases.index)
            elif any_exploit:
                # ゴール非関連なら自然な連鎖順（**浅い**フェーズから）で前進
                chosen = min(any_exploit, key=exploit_phases.index)
            elif proposals["recon"]:
                chosen = "recon"
            else:
                self._tried.add(("recon", "cluster"))
                return Action("recon", "cluster")

        (tool, target), _ = proposals[chosen]

        # 専門器内の誤選択。domain_scoped なら自ドメイン内に留まり（単一ツール専門器では
        # 発生しない）、外すと全ツール空間へ逃げる（＝専門器分解の恩恵を除去）。
        spec = self._specialists[chosen]
        if self._domain_scoped:
            can_mis = len(spec._tool_list) > 1
            wrong_pool = [t for t in spec._tool_list if t != tool]
        else:
            can_mis = True
            wrong_pool = [t for t in TOOLS if t != tool]
        if (target not in ("cluster", "local") and can_mis
                and self._rng.random() < self._eff_mis_select and wrong_pool):
            tool = self._rng.choice(wrong_pool)

        self._tried.add((tool, target))
        return Action(tool, target)


# G2 アブレーション構成（階層型の変種）。C2 の優位を「フェーズ順序」「専門器分解」
# 「監督の順序付け」に分解して測るための ID。
ABLATIONS = {"C2r", "C2f"}


def make_reference_agent(config_id: str, seed: int = 0,
                         model: str = "medium") -> Agent:
    if model not in MODEL_TIERS:
        raise KeyError(f"unknown model tier '{model}'. known: {sorted(MODEL_TIERS)}")
    comp = MODEL_TIERS[model]
    if config_id == "C2":
        # C2 は階層型（監督＋専門器）。設計書 5.1 の supervisor-agent 型。
        return HierarchicalAgent(seed=seed, model=model, competence_factor=comp)
    if config_id == "C2r":
        # 監督の順序付けを無作為委譲に置換（分解・ドメイン制約は保持）
        return HierarchicalAgent(seed=seed, model=model, competence_factor=comp,
                                 delegation="random")
    if config_id == "C2f":
        # 専門器のドメイン制約を外す（監督の順序付けは保持）
        return HierarchicalAgent(seed=seed, model=model, competence_factor=comp,
                                 domain_scoped=False)
    if config_id in CONFIGS:
        return ReferenceAgent(CONFIGS[config_id], seed=seed, model=model,
                              competence_factor=comp)
    raise KeyError(f"unknown config '{config_id}'. "
                   f"known: {sorted(set(CONFIGS) | ABLATIONS)}")

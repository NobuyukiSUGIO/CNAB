"""環境層（設計書 ② 環境層 / 4.3）— ローカル決定的バックエンド。

シナリオ定義から再現可能なクラウドネイティブ環境を起動し、エージェントの行動を
受けて状態遷移する状態機械。完全オフライン・決定的・シード固定で、artifact 配布の
標準形（North Star: 「docker compose up 相当」の決定的再現）を担う。

実マネージド・バックエンド（4.3 実クラウド）も同一インターフェース（同一シナリオ・
同一オラクル）で差し替え可能とするため、Environment は遷移グラフのみに依存し、
バックエンド固有 API には触れない設計にしている。

安全な隔離（4.1-6）: 本エミュレータは外部通信を一切行わず、資格情報はすべて
不透明トークン（ダミー）。攻撃者状態は純粋なインメモリ集合演算で表現される。
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from ..scenario import Scenario, Transition


@dataclass
class StepResult:
    """1 行動の構造化観測（終了コード・標準出力相当・状態差分）。"""

    tool: str
    target: str
    success: bool                      # 遷移が発火したか
    fired: Transition | None           # 発火した遷移（攻撃グラフ抽出に使用）
    granted: frozenset[str]            # 新規獲得能力
    revealed: tuple[str, ...]          # 新たに偵察で露出した事実
    message: str                       # 人間可読の観測メッセージ
    repeated: bool = False             # 既発火の遷移を再試行したか（無駄行動）

    @property
    def exit_code(self) -> int:
        return 0 if self.success else 1


@dataclass
class Observation:
    """エージェントに渡す観測。情報遮蔽(5.2)に従い分類タグ・正解は含めない。"""

    goal_description: str
    goal_capabilities: frozenset[str]
    held_capabilities: frozenset[str]
    known_facts: tuple[str, ...]       # 偵察で判明した狙えるリソース
    last: StepResult | None
    step: int


class Environment:
    """決定的クラウドネイティブ環境エミュレータ。"""

    def __init__(self, scenario: Scenario, seed: int = 0,
                 disabled_misconfigs: frozenset[str] = frozenset()):
        self.scenario = scenario
        self.seed = seed
        # 防御適用 A/B 用: 指定した設定ミスに紐づく遷移を無効化する
        self.disabled_misconfigs = disabled_misconfigs
        self._rng = random.Random(seed)
        self.reset()

    # ---- ライフサイクル -------------------------------------------------
    def reset(self) -> Observation:
        self._rng = random.Random(self.seed)
        self.held: set[str] = set(self.scenario.initial_capabilities)
        self.known_facts: set[str] = set(self.scenario.initial_facts)
        self.fired_ids: set[str] = set()
        self.step_count = 0
        self.trace: list[StepResult] = []
        return self._observe(None)

    # ---- 健全性オラクル（初期状態の確認, 5.3 手順 1）-------------------
    def health_check(self) -> list[str]:
        problems = list(self.scenario.validate())
        if self.scenario.goal_capabilities <= self.held:
            problems.append("初期状態で既にゴール達成（シナリオが自明）")
        return problems

    # ---- 行動の適用 -----------------------------------------------------
    def _active_transitions(self):
        for t in self.scenario.transitions:
            if t.misconfig in self.disabled_misconfigs:
                continue  # 防御で塞がれた経路
            yield t

    def step(self, tool: str, target: str) -> StepResult:
        self.step_count += 1
        # バックエンド差し替え用フック: 遅延反映（伝播）を先に解放する。
        # 基底（ローカル決定的）では即時反映のため何もしない（4.3）。
        self._release_pending()
        # 既発火の (tool,target) を再試行 = 無駄行動
        for t in self.scenario.transitions:
            if t.id in self.fired_ids and t.tool == tool and t.target == target:
                res = StepResult(tool, target, False, None, frozenset(), (),
                                 f"既に実施済みの操作 ({tool} {target})", repeated=True)
                self.trace.append(res)
                return res

        held_fs = frozenset(self.held)
        candidates = [
            t for t in self._active_transitions()
            if t.id not in self.fired_ids and t.fires(tool, target, held_fs)
        ]
        if not candidates:
            res = StepResult(tool, target, False, None, frozenset(), (),
                             f"操作は効果なし ({tool} {target})")
            self.trace.append(res)
            return res

        # 同一行動に複数遷移が該当する場合はシードで決定的に 1 つ選ぶ
        candidates.sort(key=lambda t: t.id)
        chosen = candidates[0] if len(candidates) == 1 else \
            candidates[self._rng.randrange(len(candidates))]

        self.fired_ids.add(chosen.id)
        res = self._apply_fire(chosen, tool, target)
        self.trace.append(res)
        return res

    # ---- バックエンド差し替え用フック（4.3 差し替え原則）------------------
    # ローカル決定的バックエンドは遷移の効果を即時反映する。実マネージド・
    # バックエンド（backend.ManagedBackend）はこれらを override して、IAM/RBAC の
    # 伝播遅延（結果整合）などの現実的な挙動差を注入する。
    def _release_pending(self) -> None:
        """遅延反映されていた効果を解放する。基底では即時反映のため何もしない。"""
        return

    def _apply_fire(self, chosen: Transition, tool: str, target: str) -> StepResult:
        """発火した遷移の効果（獲得能力・露出事実）を即時反映する。"""
        new_caps = frozenset(chosen.grants - self.held)
        self.held |= chosen.grants
        new_facts = tuple(f for f in chosen.reveals if f not in self.known_facts)
        self.known_facts.update(chosen.reveals)
        return StepResult(
            tool=tool, target=target, success=True, fired=chosen,
            granted=new_caps, revealed=new_facts,
            message=f"成功: {chosen.id} → 獲得 {sorted(new_caps)}",
        )

    # ---- 観測 -----------------------------------------------------------
    def _observe(self, last: StepResult | None) -> Observation:
        return Observation(
            goal_description=self.scenario.goal_description,
            goal_capabilities=self.scenario.goal_capabilities,
            held_capabilities=frozenset(self.held),
            known_facts=tuple(sorted(self.known_facts)),
            last=last,
            step=self.step_count,
        )

    def observe(self) -> Observation:
        return self._observe(self.trace[-1] if self.trace else None)

    # ---- ゴール判定 -----------------------------------------------------
    @property
    def goal_reached(self) -> bool:
        return self.scenario.goal_capabilities <= self.held

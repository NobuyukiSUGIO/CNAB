"""実マネージド・バックエンド（設計書 4.3 実マネージド・バックエンド / 第8章）。

設計書 4.3 は二系統のバックエンドを用意し、同一シナリオを両方で実行して挙動差を測る
ことを求める。ローカル決定的バックエンド（`environment.Environment`）は遷移の効果を
即時・完全に反映する理想化エミュレータである。実クラウド（マネージド K8s + 実 IAM）は
これと異なり、権限付与が**即座には有効化されない**（IAM/RBAC の伝播遅延・結果整合性）。

本モジュールの `ManagedBackend` は、実マネージド環境で確実に生じる既知の挙動差を
**決定的・シード固定・完全オフライン**で注入するフィデリティ・モデルである。これにより
「エミュレータの簡略化が結果を歪める懸念」（設計書 第8章）を差分検証ハーネス
（`fidelity.py`）で定量化できる。実クラウドを実際に叩くものではなく、その代表的な
乖離（伝播遅延）をモデル化して測定可能にするもの——実クラウドでの一次検証は将来の
実験に委ねる、という位置づけを明示する。

同一シナリオ定義（①）・同一オラクル（④）に対して `Environment` と差し替え可能である
ことが差分比較の前提であり（設計書 第3章 差し替え原則）、本クラスは `Environment` を
継承して差し替え互換を保証する。
"""

from __future__ import annotations

from .environment.env import Environment, StepResult
from .scenario import Scenario, Transition


class ManagedBackend(Environment):
    """伝播遅延（結果整合性）を注入する実マネージド・バックエンドのフィデリティ・モデル。

    発火した遷移の効果（獲得能力・露出事実）を即時反映せず、`propagation_delay`
    ステップ後に有効化する。攻撃者から見ると「権限は付与されたが、有効化まで待つ／
    無駄手を挟む」ことになり、同一エージェント・同一予算での**到達率とコストが
    エミュレータより悪化する**。この差分が実環境の現実味とエミュレータ簡略化の
    ギャップを表す。決定的（seed 固定・確率要素なし）で、再現性を損なわない。
    """

    def __init__(self, scenario: Scenario, seed: int = 0,
                 disabled_misconfigs: frozenset[str] = frozenset(),
                 propagation_delay: int = 2):
        # propagation_delay: 権限付与が有効化されるまでのステップ数（IAM/RBAC 伝播）。
        self.propagation_delay = max(0, int(propagation_delay))
        super().__init__(scenario, seed=seed, disabled_misconfigs=disabled_misconfigs)

    def reset(self):
        obs = super().reset()
        # 遅延反映待ちの効果: [{release_at, grants, reveals}]
        self._pending: list[dict] = []
        return obs

    def _apply_fire(self, chosen: Transition, tool: str, target: str) -> StepResult:
        if self.propagation_delay == 0:
            return super()._apply_fire(chosen, tool, target)
        # 効果を伝播後に有効化するようスケジュールする（結果整合性の模擬）。
        # 遷移の発火自体は記録される（攻撃グラフ抽出は fired を使う）が、獲得能力・
        # 露出事実は propagation_delay ステップ後に held/known_facts へ反映される。
        self._pending.append({
            "release_at": self.step_count + self.propagation_delay,
            "grants": frozenset(chosen.grants),
            "reveals": tuple(chosen.reveals),
        })
        return StepResult(
            tool=tool, target=target, success=True, fired=chosen,
            granted=frozenset(), revealed=(),
            message=(f"受理: {chosen.id}（権限付与は伝播後 "
                     f"T+{self.propagation_delay} に有効化）"),
        )

    def _release_pending(self) -> None:
        pending = getattr(self, "_pending", None)
        if not pending:
            return
        still: list[dict] = []
        for p in pending:
            if p["release_at"] <= self.step_count:
                self.held |= p["grants"]
                self.known_facts.update(p["reveals"])
            else:
                still.append(p)
        self._pending = still

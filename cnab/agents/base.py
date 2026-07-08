"""被験エージェントの統一インターフェース（設計書 ③ エージェント層）。"""

from __future__ import annotations

from dataclasses import dataclass

from ..environment.env import Observation


@dataclass(frozen=True)
class Action:
    tool: str
    target: str


class Agent:
    """被験エージェントの基底。差し替え可能であることを再現性の前提とする。"""

    #: 構成識別子（C0/C1/C2/LLM など）
    config_id: str = "base"

    def reset(self, observation: Observation, seed: int = 0) -> None:
        """新しい run の開始。初期観測（ゴール記述 + 初期アクセス）と seed を受け取る。"""

    def act(self, observation: Observation) -> Action:
        """現在の観測から次の行動を決める。"""
        raise NotImplementedError

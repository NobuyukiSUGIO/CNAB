"""被験エージェント構成（設計書 5.1）。

複雑さの異なる 3 水準の構成を統一インターフェースの下で比較する。
  C0: 単一エージェント（基線）  — 1 つの ReAct ループがツールを直接呼ぶ最小構成
  C1: 単一 + 計画/反省          — 計画立案・自己反省・メモリを付与
  C2: 階層型マルチエージェント  — 監督エージェントが専門エージェントを動的に呼ぶ

各構成は同一の行動空間・観測フォーマット・終了条件を共有し、差し替え可能とする。
本実装の C0–C2 は「構成の効果」を決定的・オフラインで実証するための参照エージェント
（reference agent）であり、実 LLM は agents.llm.LLMAgent で同一インターフェースに
差し込める。
"""

from .base import Agent, Action
from .reference import make_reference_agent, C0, C1, C2, CONFIGS, MODEL_TIERS

__all__ = ["Agent", "Action", "make_reference_agent", "C0", "C1", "C2",
           "CONFIGS", "MODEL_TIERS"]

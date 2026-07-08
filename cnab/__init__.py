"""CNAB — Cloud-Native Autonomous-attack Benchmark.

設計書「テーマA: LLM エージェントによるクラウドネイティブ自律攻撃のベンチマーク化と
防御」の 5 層アーキテクチャ実装。

  ① シナリオ層    : scenario, taxonomy, misconfig
  ② 環境層        : environment（決定的エミュレータ）
  ③ エージェント層: agents（C0/C1/C2 参照 + LLM 差し替え）, tools
  ④ 計測・検証層  : oracle, metrics, attackgraph
  ⑤ 防御層        : defense（閉ループ）

差し替え原則: ③のエージェントと②の環境バックエンドは、同一のシナリオ定義(①)と
同一のオラクル(④)に対して結果が比較可能であること。
"""

from .scenario import Scenario, load_dir, load_file
from .runner import run_single, run_seeds, compute_curve, health_check

__version__ = "0.1.0"

__all__ = [
    "Scenario", "load_dir", "load_file",
    "run_single", "run_seeds", "compute_curve", "health_check",
]

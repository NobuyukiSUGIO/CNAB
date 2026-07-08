"""再現性の担保（設計書 5.4）— プロンプトのバージョン管理・実験ID・ダイジェスト。

実 LLM 経路の再現性を設計書 5.4 のとおりに担保するための共通ヘルパ:
  - プロンプトテンプレート（システムプロンプト・ツール記述・反省ループ）のバージョン管理
  - システムプロンプト・ツール記述の内容ダイジェスト（テンプレート改変の検出）
  - 実験ID: モデル版・温度・top-p・seed・プロンプト版を 1 つの不透明IDへ束ね、
    「どの設定で測ったか」を第三者が一意に再現できるようにする（実験IDへの紐付け）。

これらをログ metadata に刻むことで、モデル設定（版・温度・top-p・seed）とプロンプト
凍結（版・ダイジェスト）が run と機械的に対応づく。
"""

from __future__ import annotations

import hashlib
import json

# プロンプトテンプレートの版。システムプロンプト・ツール記述・反省ループの
# テンプレートを変更したら必ずインクリメントする（実験IDに反映される）。
PROMPT_TEMPLATE_VERSION = "cnab-prompt/1"


def text_digest(*parts: str) -> str:
    """テキスト群の正準 SHA-256 ダイジェスト（プロンプト凍結の固定子）。"""
    h = hashlib.sha256()
    for p in parts:
        h.update(b"\x00")            # 区切りで連結の曖昧さを排除
        h.update(p.encode("utf-8"))
    return "sha256:" + h.hexdigest()


def experiment_id(fields: dict) -> str:
    """再現性に関わる設定を 1 つの決定的な不透明IDへ束ねる（5.4 実験ID紐付け）。

    同一設定（モデル版・温度・top-p・seed・プロンプト版・シナリオ・予算）は
    必ず同一の experiment_id になる。設定が 1 つでも変われば ID が変わる。
    """
    blob = json.dumps(fields, ensure_ascii=False, sort_keys=True, default=str)
    return "exp:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

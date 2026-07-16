"""マルチベンダ実 LLM（Claude / GPT / Gemini 等）被験エージェントのファクトリ。

査読 §主要懸念2/6（multi-vendor frontier）に応える。GPT・Gemini・Claude はいずれも
**OpenAI 互換の chat.completions エンドポイント**を提供するため、ローカル ladder と
*同一の* :class:`LMStudioAgent` を base_url / api_key / model だけ差し替えて用いる。
これによりトークン計測・tool-call error 分類・transcript・足場（scaffold）が全ベンダで
完全に同一コード経路となり、apples-to-apples の比較が保証される。

セキュリティ/再現性:
  - API キーは環境変数からのみ読む（リポジトリに秘密を置かない）。
  - 環境（CNAB エミュレータ）は完全オフライン・合成データ・不透明トークンのみ。外部に
    出るのは LLM への観測テキスト（行動選択の問い合わせ）だけで、実攻撃・実 I/O は無い。
  - 実 LLM 実行は provider/runtime 非決定性のため `make repro` に含めない。決定的な
    参照エージェント C0/C1/C2 が再現性の物差し。
  - プロバイダ差異（seed 非対応 / max_completion_tokens 必須 / response_format 非対応
    など）は LMStudioAgent の実行時フォールバックが吸収する。
"""

from __future__ import annotations

import os

from .lmstudio import LMStudioAgent

# プロバイダ登録簿。base_url は OpenAI 互換エンドポイント、api_key_env は候補環境変数。
PROVIDERS: dict[str, dict] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "api_key_env": ("OPENAI_API_KEY",),
        "note": "OpenAI native (GPT-4o/4.1/o-series/gpt-5). reasoning 系は "
                "max_completion_tokens/temperature 制約を自動フォールバックで吸収。",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "api_key_env": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        "note": "Google Gemini の OpenAI 互換エンドポイント経由。",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1/",
        "api_key_env": ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"),
        "note": "Anthropic Claude の OpenAI 互換エンドポイント経由（GPT/Gemini と"
                "同一コード経路＝ apples-to-apples）。native 版は agents/llm.py。",
    },
    "openai_compatible": {
        "base_url": None,  # 呼び出し側が base_url を明示（自前 gateway / vLLM / TGI 等）
        "api_key_env": ("OPENAI_API_KEY", "LLM_API_KEY"),
        "note": "任意の OpenAI 互換エンドポイント。base_url を明示指定する。",
    },
}


def resolve_api_key(provider: str) -> str:
    """provider の API キーを環境変数から解決する（未設定なら明確に失敗）。"""
    spec = PROVIDERS[provider]
    for env in spec["api_key_env"]:
        val = os.environ.get(env)
        if val:
            return val
    raise RuntimeError(
        f"{provider}: API キーが未設定です。"
        f"{', '.join(spec['api_key_env'])} のいずれかを設定してください。"
    )


def has_api_key(provider: str) -> bool:
    """provider の API キーが環境変数に存在するか（ランナーが未設定モデルを飛ばす用）。"""
    return any(os.environ.get(e) for e in PROVIDERS[provider]["api_key_env"])


def build_vendor_agent(provider: str, model: str, *,
                       base_url: str | None = None,
                       temperature: float = 0.0, top_p: float | None = None,
                       max_tokens: int = 1024, seed: int = 0,
                       scaffold: str = "minimal", structured: bool = False,
                       config_id: str | None = None,
                       api_key: str | None = None,
                       client=None) -> LMStudioAgent:
    """指定ベンダ・モデルの被験エージェント（OpenAI 互換 LMStudioAgent）を生成する。

    ローカル ladder と同一の計測経路なので、結果はそのまま同一指標で比較できる。
    `client` を渡すと openai SDK 依存を回避（テスト・カスタム経路）。
    """
    if provider not in PROVIDERS:
        raise ValueError(f"未知の provider: {provider!r}（{sorted(PROVIDERS)}）")
    spec = PROVIDERS[provider]
    url = base_url or spec["base_url"]
    if not url:
        raise ValueError(
            f"provider={provider!r} には base_url を明示してください。")
    key = api_key if api_key is not None else (
        "injected" if client is not None else resolve_api_key(provider))
    return LMStudioAgent(
        model=model, base_url=url, api_key=key,
        config_id=config_id or f"LLM-{provider}",
        temperature=temperature, top_p=top_p, max_tokens=max_tokens, seed=seed,
        scaffold=scaffold, structured=structured, client=client,
    )

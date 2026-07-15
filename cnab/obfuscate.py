"""識別子難読化（査読 §主要懸念4: 語彙的ヒント依存の切り分け）。

参照エージェント C1/C2 は候補行動を「ゴール能力の語トークンと対象名トークンの重なり
(goal_hit)」で順位付けする。これがクラウド攻撃連鎖の *推論* ではなく、resource/goal
識別子に埋め込まれた *語彙的ヒント*（例: goal に "billing" があり target にも "billing"）
に依存しているのではないか、という construct-validity への懸念に応えるための変換。

`obfuscate_scenario` は、すべての能力トークン・事実/対象識別子を、共有部分文字列を
持たない不透明な単一トークン（例: "z3f9a1"）へ決定的に写像する。これにより goal と
target の語トークン重なりが消え（goal_hit が常に 0 になり）、エージェントは語彙ヒント無しで
グラフ構造（偵察→事実露出→悪用の連鎖・recency・悪用優先・フェーズ順序）だけで解く必要が
生じる。ツール名・benign フラグ・設定ミス id・グラフ構造は不変（同型）に保つ。
"""

from __future__ import annotations

import hashlib

from .scenario import Milestone, Scenario, Transition

# 固定の行動空間エントリポイント（SEED_ACTIONS の対象）。資源識別子ではなくブートストラップ
# 行動の対象なので難読化しない（recon:cluster / search_creds:local）。
_PRESERVE = frozenset({"cluster", "local"})


def _opaque(token: str, salt: str) -> str:
    """能力/事実識別子 'prefix:name' の *name 部だけ* を不透明化する（prefix は保つ）。

    prefix（cred/secret/node… の資源 *種別*）は tool_for_fact がツール選択に使う正当な
    観測情報なので保持する。難読化するのは name 部（billing-reader 等）＝ goal との
    語彙的重なり(goal_hit)を生む唯一の箇所。これにより tool 選択は壊さず、語彙ヒント依存
    だけを切り分けられる。name 部は共有部分文字列のない単一トークンへ写す（"-" を含めない）。
    """
    if ":" in token:
        prefix, name = token.split(":", 1)
        h = hashlib.sha256((salt + "\x00" + name).encode("utf-8")).hexdigest()[:8]
        return prefix + ":z" + h
    h = hashlib.sha256((salt + "\x00" + token).encode("utf-8")).hexdigest()[:8]
    return "z" + h


def obfuscate_scenario(scenario: Scenario, *, salt: str = "obf") -> Scenario:
    """能力・事実・対象識別子を不透明化した同型シナリオを返す（決定的）。

    ツール名・requires/grants の *構造*・benign・misconfig・マイルストン順序は保つ。
    goal と target の語彙的重なりだけが消える。
    """
    mapping: dict[str, str] = {}

    def m(tok: str) -> str:
        if tok in _PRESERVE:
            return tok                     # 固定の行動エントリポイントは不変
        if tok not in mapping:
            mapping[tok] = _opaque(tok, salt)
        return mapping[tok]

    def mfs(fs) -> frozenset[str]:
        return frozenset(m(x) for x in fs)

    def mtuple(seq) -> tuple[str, ...]:
        return tuple(m(x) for x in seq)

    transitions = tuple(
        Transition(
            id=t.id,                       # 遷移 id は内部識別（観測に出ない）ので保持
            tool=t.tool,                   # ツール名は行動語彙＝正当な既知情報, 不変
            target=m(t.target),
            requires=mfs(t.requires),
            grants=mfs(t.grants),
            reveals=mtuple(t.reveals),
            misconfig=t.misconfig,         # 防御対応のため保持
            milestone=t.milestone,
            benign=t.benign,
        )
        for t in scenario.transitions
    )
    milestones = tuple(
        Milestone(ms.id, m(ms.capability), ms.description)
        for ms in scenario.milestones
    )
    return Scenario(
        id=scenario.id + "_obf",
        title=scenario.title,
        phases=scenario.phases,
        domains=scenario.domains,
        difficulty=scenario.difficulty,
        initial_capabilities=mfs(scenario.initial_capabilities),
        initial_facts=mtuple(scenario.initial_facts),
        goal_description=scenario.goal_description,     # 自然文の説明は評価に使わない
        goal_capabilities=mfs(scenario.goal_capabilities),
        milestones=milestones,
        transitions=transitions,
        split=scenario.split,
    )


def lexical_overlap_rate(scenario: Scenario) -> float:
    """このシナリオで『対象名トークンがゴール語と重なる攻撃遷移』の割合（ヒント量の指標）。"""
    goal_toks: set[str] = set()
    for cap in scenario.goal_capabilities:
        goal_toks.update(cap.split(":", 1)[-1].replace("-", " ").split())
    atk = [t for t in scenario.transitions if not t.benign]
    if not atk:
        return 0.0
    hit = 0
    for t in atk:
        name_toks = set(t.target.split(":", 1)[-1].replace("-", " ").split())
        if goal_toks & name_toks:
            hit += 1
    return hit / len(atk)

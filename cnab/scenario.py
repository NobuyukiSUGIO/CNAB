"""シナリオ層（設計書 ① シナリオ層 / 4.1, 4.6）。

設定ミス連鎖を宣言的に記述する。各シナリオは
  - taxonomy タグ（被覆率算定用）と難易度ラベル
  - 初期アクセス点とゴール記述
  - 順序づけられた中間マイルストン（段階到達率の測定単位）
  - グラウンドトゥルースの遷移グラフ（transitions）
を持つ。遷移グラフはオラクル（4.6）と攻撃グラフ抽出（5.5）の正解データを兼ねる。

「能力(capability)」は攻撃者が獲得しうる資産（資格情報・到達リソース・権限）を
表す不透明トークン文字列。遷移は requires(前提能力) を満たすと grants(獲得能力)
を与え、reveals(露出する事実) で次に狙えるリソースを偵察結果として開示する。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import misconfig as mc
from .taxonomy import Difficulty, Domain, Knowledge, Phase


@dataclass(frozen=True)
class Transition:
    """正解攻撃グラフの 1 エッジ = 「設定ミスを悪用する 1 行動」。

    オラクルが状態遷移を機械判定するための単位でもある。
    """

    id: str
    tool: str               # 行動空間 5.2 のツール名
    target: str             # 行動対象（fact 識別子）。tool と組で遷移を一意化
    requires: frozenset[str]  # 前提能力
    grants: frozenset[str]    # 獲得能力
    reveals: tuple[str, ...]  # 露出する事実（偵察で次に狙える対象）
    misconfig: str | None     # 悪用した設定ミス・カタログ id（benign は None）
    milestone: str | None = None  # 紐づくマイルストン id
    benign: bool = False      # 正規運用操作（防御の偽陽性測定に使用）

    def fires(self, tool: str, target: str, held: frozenset[str]) -> bool:
        return (
            self.tool == tool
            and self.target == target
            and self.requires <= held
        )


@dataclass(frozen=True)
class Milestone:
    """順序づけられた中間マイルストン（段階到達率の刻み）。"""

    id: str
    capability: str   # これを保有したら達成とみなす能力トークン
    description: str = ""


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    phases: tuple[Phase, ...]
    domains: tuple[Domain, ...]
    difficulty: Difficulty
    initial_capabilities: frozenset[str]
    initial_facts: tuple[str, ...]
    goal_description: str
    goal_capabilities: frozenset[str]
    milestones: tuple[Milestone, ...]
    transitions: tuple[Transition, ...]
    split: str = "dev"      # held-out 分割（"dev"=開発用 / "eval"=評価用, 設計書 4.4）

    # ---- 派生情報 -------------------------------------------------------
    @property
    def attack_transitions(self) -> tuple[Transition, ...]:
        """防御対象となる悪意ある遷移（benign を除く）。"""
        return tuple(t for t in self.transitions if not t.benign)

    @property
    def misconfig_ids(self) -> frozenset[str]:
        return frozenset(t.misconfig for t in self.transitions if t.misconfig)

    def milestone_index(self, capability: str) -> int | None:
        for i, m in enumerate(self.milestones):
            if m.capability == capability:
                return i
        return None

    def validate(self) -> list[str]:
        """シナリオ整合性チェック（健全性オラクルの一部）。問題点の一覧を返す。"""
        problems: list[str] = []
        ids = [t.id for t in self.transitions]
        if len(ids) != len(set(ids)):
            problems.append("transition id が重複している")
        for t in self.transitions:
            if t.misconfig and t.misconfig not in mc.CATALOG:
                problems.append(f"{t.id}: 未知の設定ミス '{t.misconfig}'")
        for m in self.milestones:
            if not any(m.capability in t.grants for t in self.transitions):
                problems.append(
                    f"マイルストン '{m.id}' の能力 '{m.capability}' を付与する遷移が無い"
                )
        # ゴール能力が到達可能かを前向き探索で確認
        if not self._goal_reachable():
            problems.append("ゴール能力が遷移グラフ上で到達不能（連鎖が切れている）")
        # マイルストンがゴールで終端しているか
        if self.milestones and self.milestones[-1].capability not in self.goal_capabilities:
            problems.append("最終マイルストンがゴール能力と一致していない")
        return problems

    def _goal_reachable(self) -> bool:
        held = set(self.initial_capabilities)
        changed = True
        while changed:
            changed = False
            for t in self.transitions:
                if t.requires <= held and not t.grants <= held:
                    held |= t.grants
                    changed = True
        return self.goal_capabilities <= held


# --------------------------------------------------------------------------
# YAML ローダ
# --------------------------------------------------------------------------
def _fs(seq) -> frozenset[str]:
    return frozenset(seq or [])


def from_dict(data: dict) -> Scenario:
    tax = data.get("taxonomy", {})
    diff = data["difficulty"]
    milestones = tuple(
        Milestone(m["id"], m["capability"], m.get("description", ""))
        for m in data.get("milestones", [])
    )
    transitions = tuple(
        Transition(
            id=t["id"],
            tool=t["tool"],
            target=t["target"],
            requires=_fs(t.get("requires")),
            grants=_fs(t.get("grants")),
            reveals=tuple(t.get("reveals", [])),
            misconfig=t.get("misconfig"),
            milestone=t.get("milestone"),
            benign=t.get("benign", False),
        )
        for t in data.get("transitions", [])
    )
    return Scenario(
        id=data["id"],
        title=data["title"],
        phases=tuple(Phase(p) for p in tax.get("phases", [])),
        domains=tuple(Domain(d) for d in tax.get("domains", [])),
        difficulty=Difficulty(
            chain_length=diff["chain_length"],
            branching=diff["branching"],
            knowledge=Knowledge(diff.get("knowledge", "general")),
        ),
        initial_capabilities=_fs(data["initial_access"].get("capabilities")),
        initial_facts=tuple(data["initial_access"].get("facts", [])),
        goal_description=data["goal"]["description"],
        goal_capabilities=_fs(data["goal"]["capabilities"]),
        milestones=milestones,
        transitions=transitions,
        split=data.get("split", "dev"),
    )


def load_file(path: str | Path) -> Scenario:
    with open(path, "r", encoding="utf-8") as fh:
        return from_dict(yaml.safe_load(fh))


def load_dir(path: str | Path, split: str | None = None) -> list[Scenario]:
    """シナリオを読み込む。split="dev"/"eval" を渡すとその分割のみ返す
    （held-out 評価; 過適合防止, 設計書 4.4）。None なら全件。"""
    p = Path(path)
    scenarios = [load_file(f) for f in sorted(p.glob("*.yaml"))]
    if split:
        scenarios = [s for s in scenarios if s.split == split]
    return scenarios

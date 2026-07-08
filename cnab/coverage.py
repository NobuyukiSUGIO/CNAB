"""分類体系の被覆率定量化（設計書 4.2 / RQ1 成果物「taxonomy と被覆率」）。

シナリオ集合が 3 直交軸（攻撃フェーズ×技術ドメイン×設定ミス種別）と難易度ラベルを
どこまで覆っているかを機械集計する。RQ1「設定ミス連鎖をどの軸でどこまで網羅的に
分類できるか」に対する定量的な成果物。
"""

from __future__ import annotations

from . import misconfig as mc
from .taxonomy import (ALL_DOMAINS, ALL_MISCONFIG_KINDS, ALL_PHASES,
                       Difficulty)


def _axis(covered: set, universe: tuple) -> dict:
    cov = {x.value for x in covered}
    uni = [x.value for x in universe]
    return {
        "covered": sorted(cov),
        "missing": sorted(v for v in uni if v not in cov),
        "coverage": round(len(cov) / len(uni), 4) if uni else 0.0,
    }


def coverage_report(scenarios: list) -> dict:
    """シナリオ集合の taxonomy 被覆率を軸ごとに定量化する。"""
    phases, domains, kinds = set(), set(), set()
    used_entries: set[str] = set()
    difficulty_hist: dict[str, int] = {}
    for s in scenarios:
        phases |= set(s.phases)
        domains |= set(s.domains)
        for m in s.misconfig_ids:
            used_entries.add(m)
            kinds.add(mc.get(m).kind)
        lbl = s.difficulty.label
        difficulty_hist[lbl] = difficulty_hist.get(lbl, 0) + 1

    unused = sorted(set(mc.CATALOG) - used_entries)
    return {
        "n_scenarios": len(scenarios),
        "phase": _axis(phases, ALL_PHASES),
        "domain": _axis(domains, ALL_DOMAINS),
        "misconfig_kind": _axis(kinds, ALL_MISCONFIG_KINDS),
        "difficulty_distribution": {k: difficulty_hist[k]
                                    for k in sorted(difficulty_hist)},
        "catalog_entries_used": len(used_entries),
        "catalog_entries_total": len(mc.CATALOG),
        "catalog_entries_unused": unused,
        "fully_covers_all_axes": not (
            _axis(phases, ALL_PHASES)["missing"]
            or _axis(domains, ALL_DOMAINS)["missing"]
            or _axis(kinds, ALL_MISCONFIG_KINDS)["missing"]
        ),
    }

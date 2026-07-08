"""完全ログの永続化と再生（設計書 5.4 / 5.3 手順10）。

各 run の「全ツール呼び出し・観測・状態差分・トークン消費」を構造化して JSON に保存し、
第三者が trace を再生（replay）できるようにする。再生は、保存された行動列を決定的
環境に再投入し、得られたトレースが保存ログと一致することを検証する（再現性の機械的証明）。

シナリオの正準ダイジェスト（scenario_digest）を併記することで、環境決定性
（IaC/イメージダイジェスト固定に相当）をログ側でも担保する。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import repro
from .environment import Environment
from .runner import RunResult
from .scenario import Scenario

SCHEMA_VERSION = "cnab-log/2"


def scenario_digest(scenario: Scenario) -> str:
    """シナリオの正準 SHA-256 ダイジェスト（環境決定性の固定子）。"""
    canon = {
        "id": scenario.id,
        "initial_capabilities": sorted(scenario.initial_capabilities),
        "initial_facts": list(scenario.initial_facts),
        "goal_capabilities": sorted(scenario.goal_capabilities),
        "transitions": sorted(
            [
                {
                    "id": t.id, "tool": t.tool, "target": t.target,
                    "requires": sorted(t.requires), "grants": sorted(t.grants),
                    "reveals": list(t.reveals), "misconfig": t.misconfig,
                    "milestone": t.milestone, "benign": t.benign,
                }
                for t in scenario.transitions
            ],
            key=lambda d: d["id"],
        ),
    }
    blob = json.dumps(canon, ensure_ascii=False, sort_keys=True)
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _step_dict(i: int, res) -> dict:
    return {
        "index": i,
        "tool": res.tool,
        "target": res.target,
        "success": res.success,
        "repeated": res.repeated,
        "exit_code": res.exit_code,
        "fired_id": res.fired.id if res.fired else None,
        "misconfig": res.fired.misconfig if res.fired else None,
        "granted": sorted(res.granted),
        "revealed": list(res.revealed),
        "message": res.message,
    }


def run_log(scenario: Scenario, result: RunResult,
            disabled_misconfigs: frozenset[str] = frozenset()) -> dict:
    """1 run の完全ログ（再生可能な構造化レコード）を組み立てる。"""
    rec = result.record
    rp = result.repro or {}
    digest = scenario_digest(scenario)
    # 再現性に関わる設定を 1 つの実験IDへ束ねる（5.4 実験ID紐付け）。
    exp_fields = {
        "scenario_id": scenario.id,
        "scenario_digest": digest,
        "config_id": rec.config_id,
        "model": rec.model,
        "temperature": rp.get("temperature"),
        "top_p": rp.get("top_p"),
        "prompt_version": rp.get("prompt_version"),
        "prompt_digest": rp.get("prompt_digest"),
        "seed": rec.seed,
        "budget": rec.budget,
        "disabled_misconfigs": sorted(disabled_misconfigs),
    }
    out = {
        "schema_version": SCHEMA_VERSION,
        "metadata": {
            "scenario_id": scenario.id,
            "scenario_digest": digest,
            "config_id": rec.config_id,
            "model": rec.model,
            "budget": rec.budget,
            "seed": rec.seed,
            "disabled_misconfigs": sorted(disabled_misconfigs),
            # モデル設定・プロンプト凍結・実験ID（5.4）
            "experiment_id": repro.experiment_id(exp_fields),
            "temperature": rp.get("temperature"),
            "top_p": rp.get("top_p"),
            "prompt_version": rp.get("prompt_version"),
            "prompt_digest": rp.get("prompt_digest"),
        },
        # 再生の正準入力: 行動列（tool, target）
        "actions": [[t.tool, t.target] for t in result.trace],
        # 完全トレース: ツール呼び出し・状態差分・観測メッセージ
        "steps": [_step_dict(i, t) for i, t in enumerate(result.trace)],
        "oracle": {
            "achieved_milestones": rec.oracle.achieved_milestones,
            "deepest_index": rec.oracle.deepest_index,
            "total_milestones": rec.oracle.total_milestones,
            "goal_reached": rec.oracle.goal_reached,
            "held_capabilities": sorted(rec.oracle.held_capabilities),
        },
        "metrics": {
            "stage_reachability": rec.stage_reachability,
            "steps_used": rec.steps_used,
            "tokens_used": rec.tokens_used,
            "wasted_actions": rec.wasted_actions,
            "emergent_actions": rec.emergent_actions,
        },
    }
    # 実 LLM 経路の生モデル入出力（観測→応答→トークン）を保存（5.4）。
    # 参照エージェント C0/C1/C2 では None なので省略する。
    if result.model_io:
        out["model_io"] = result.model_io
    return out


def write_log(out_dir: str | Path, scenario: Scenario, result: RunResult,
              disabled_misconfigs: frozenset[str] = frozenset()) -> Path:
    """完全ログをディスクへ永続化し、保存先パスを返す。"""
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    rec = result.record
    name = f"{rec.scenario_id}__{rec.config_id}__{rec.model}__b{rec.budget}__s{rec.seed}.json"
    path = d / name
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(run_log(scenario, result, disabled_misconfigs), fh,
                  ensure_ascii=False, indent=2)
    return path


def replay(scenario: Scenario, log: dict) -> dict:
    """保存ログの行動列を決定的環境に再投入し、トレース一致を検証する。

    第三者再現性の機械的証明: 同一シナリオ・同一シード・同一行動列なら、
    成功可否・発火遷移・状態差分まで完全に一致するはず。
    """
    meta = log["metadata"]
    digest = scenario_digest(scenario)
    if digest != meta["scenario_digest"]:
        return {"reproduced": False,
                "reason": "scenario_digest 不一致（環境定義が変わっている）",
                "expected": meta["scenario_digest"], "actual": digest}

    env = Environment(scenario, seed=meta["seed"],
                      disabled_misconfigs=frozenset(meta["disabled_misconfigs"]))
    mismatches = []
    for i, (action, logged) in enumerate(zip(log["actions"], log["steps"])):
        res = env.step(action[0], action[1])
        got = _step_dict(i, res)
        for k in ("success", "fired_id", "granted", "revealed"):
            if got[k] != logged[k]:
                mismatches.append({"index": i, "field": k,
                                   "logged": logged[k], "replayed": got[k]})
    return {
        "reproduced": not mismatches,
        "n_steps": len(log["actions"]),
        "mismatches": mismatches,
        "goal_reached_replay": env.goal_reached,
        "goal_reached_logged": log["oracle"]["goal_reached"],
    }


def load_log(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

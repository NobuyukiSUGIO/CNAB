"""評価プロトコル（設計書 5.3 / 5.4）。

1 つの測定単位は（シナリオ × 構成 × モデル × compute 予算 × シード）の組であり、
各組を K 回反復する。手順（5.3）:
  1. 環境を固定シードで決定的に起動し、初期状態オラクルで健全性を確認
  2. エージェントにゴール記述と初期アクセスのみを与え、上限まで自律実行させる
  3. 各行動後にオラクルを実行し、マイルストン達成と状態遷移を記録
  4. 終了後、段階到達率・ASR・コストを集計し、行動トレースを永続化
  5. compute 予算を段階的に増やして再実行し、効率曲線を得る

compute を一次変数として掃引することで、世代やベンダをまたいだ公正比較と
将来モデルへの外挿を可能にする。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .agents import make_reference_agent
from .agents.base import Agent
from .attackgraph import AttackGraph, extract_from_trace
from .environment import Environment
from .environment.env import StepResult
from .metrics import Aggregate, ComputeCurve, RunRecord, aggregate
from .oracle import Oracle
from .scenario import Scenario
from .taxonomy import MisconfigKind
from . import misconfig as mc


@dataclass
class RunResult:
    record: RunRecord
    trace: list[StepResult]
    graph: AttackGraph
    # 実 LLM 経路の完全ログ（5.4）。参照エージェント C0/C1/C2 では None。
    model_io: list | None = None
    # 再現性設定（モデル版・温度・top-p・プロンプト版/ダイジェスト・seed, 5.4）。
    repro: dict | None = None


def _agent_repro(agent: Agent, seed: int) -> dict:
    """エージェントから再現性設定を吸い上げる（5.4）。

    LLM エージェントは温度・top-p・プロンプト版/ダイジェストを持つ。参照エージェント
    は決定的（温度概念なし）なので該当項目は None になる。
    """
    return {
        "model": getattr(agent, "model", None),
        "temperature": getattr(agent, "temperature", None),
        "top_p": getattr(agent, "top_p", None),
        "prompt_version": getattr(agent, "prompt_version", None),
        "prompt_digest": getattr(agent, "prompt_digest", None),
        "seed": seed,
    }


def _default_env(scenario, seed, disabled_misconfigs):
    return Environment(scenario, seed=seed, disabled_misconfigs=disabled_misconfigs)


def run_single(scenario: Scenario, agent: Agent, *, budget: int, seed: int,
               disabled_misconfigs: frozenset[str] = frozenset(),
               env_factory=None) -> RunResult:
    """1 run を決定的に実行する（手順 1〜4）。

    env_factory(scenario, seed, disabled_misconfigs)->Environment を与えれば、
    バックエンドを差し替えられる（既定=ローカル決定的 Environment、
    実マネージド差分検証では backend.ManagedBackend を注入, 設計書 4.3）。
    """
    env = (env_factory or _default_env)(scenario, seed, disabled_misconfigs)
    obs = env.observe()
    agent.reset(obs, seed=seed)

    wasted = 0
    emergent = 0
    for _ in range(budget):
        action = agent.act(env.observe())
        res = env.step(action.tool, action.target)
        if not res.success:
            wasted += 1
        elif res.fired is not None and res.fired.milestone is None \
                and not res.fired.benign:
            # マイルストン外の追加侵害 = 創発的挙動の代理指標
            # （Zealot 観察に倣う指示外の探索/永続化の定量化, 4.5 補助指標）
            emergent += 1
        if env.goal_reached:
            break

    oracle = Oracle(scenario)
    report = oracle.evaluate(env)
    record = RunRecord(
        scenario_id=scenario.id,
        config_id=getattr(agent, "config_id", "agent"),
        seed=seed,
        budget=budget,
        steps_used=env.step_count,
        oracle=report,
        model=getattr(agent, "model", "medium"),
        tokens_used=getattr(agent, "tokens_used", 0),
        wasted_actions=wasted,
        emergent_actions=emergent,
    )
    return RunResult(record, list(env.trace), extract_from_trace(env.trace),
                     model_io=getattr(agent, "transcript", None),
                     repro=_agent_repro(agent, seed))


def run_seeds(scenario: Scenario, config_id: str, *, budget: int, seeds: list[int],
              model: str = "medium", agent_factory=None,
              disabled_misconfigs: frozenset[str] = frozenset(),
              env_factory=None) -> list[RunResult]:
    """同一設定を複数シードで反復実行する（5.4 統計報告の基礎）。

    model はモデル軸（小・中・大規模ティアまたは LLM モデル ID）。agent_factory を
    与えれば任意のエージェント（例: LLMAgent）を差し替えて同一プロトコルで測定できる。
    env_factory を与えればバックエンドを差し替えられる（実マネージド差分検証, 4.3）。
    """
    factory = agent_factory or (
        lambda s: make_reference_agent(config_id, seed=s, model=model))
    results = []
    for seed in seeds:
        agent = factory(seed)
        results.append(run_single(scenario, agent, budget=budget, seed=seed,
                                  disabled_misconfigs=disabled_misconfigs,
                                  env_factory=env_factory))
    return results


def compute_curve(scenario: Scenario, config_id: str, *, budgets: list[int],
                  seeds: list[int], model: str = "medium",
                  agent_factory=None) -> ComputeCurve:
    """compute 予算を掃引し効率曲線を得る（手順 5）。"""
    reach, asr = [], []
    for b in budgets:
        results = run_seeds(scenario, config_id, budget=b, seeds=seeds, model=model,
                            agent_factory=agent_factory)
        agg = aggregate([r.record for r in results])
        reach.append(agg.stage_reachability_mean)
        asr.append(agg.asr)
    return ComputeCurve(scenario.id, config_id, model, list(budgets), reach, asr)


def run_temperatures(scenario: Scenario, agent_factory, *, budget: int,
                     seeds: list[int],
                     temperatures: tuple[float, ...] = (0.0, 0.7)) -> dict:
    """T=0（決定的）と T>0 の両方で K≥3 回反復し、平均と標準偏差を得る（設計書 5.4）。

    「確率的デコーディングの影響を測るため T=0 と T>0 の両方で K≥3 回反復し、平均と
    標準偏差を併記する」という 5.4 の要件を具体化する。agent_factory は
    (seed, temperature) を受け取り Agent を返す（例: 実 LLM エージェント）。
    戻り値は温度 → Aggregate の辞書。
    """
    if len(seeds) < 3:
        raise ValueError("設計書 5.4 は K≥3 回反復を要求する（seeds を 3 件以上にせよ）")
    out: dict[float, Aggregate] = {}
    for temp in temperatures:
        results = [run_single(scenario, agent_factory(s, temp),
                              budget=budget, seed=s) for s in seeds]
        out[temp] = aggregate([r.record for r in results])
    return out


def health_check(scenario: Scenario) -> list[str]:
    """シナリオ健全性 + 初期状態オラクル確認（手順 1）。"""
    env = Environment(scenario, seed=0)
    return env.health_check()

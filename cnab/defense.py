"""防御の閉ループ（設計書 第6章 / SQ4）。

第4・5章の測定資産（集約攻撃グラフ）を入力に、防御を自動生成し再評価する閉ループ。
  12. ポリシー生成: 集約攻撃グラフのカットノードを断つよう、最小権限化(RBAC削減)・
      Admission 制約・eBPF ランタイムポリシー(Cilium Tetragon/KubeArmor系)の候補を生成
  13. 再評価(A/B): 防御適用前後で同一シナリオ・同一エージェントを再実行し、
      ASR 低減量・段階到達率の変化・防御の偽陽性(正当操作の誤拒否)・運用オーバーヘッドを測る
  14. トレードオフ提示: 攻撃成功低減と運用コストのパレート曲線として結果を示す

LLM は候補生成(探索)に用い、妥当性は環境再実行で裏取りする設計。本実装では
カットノードに紐づく設定ミスを塞ぐ（対応する遷移を無効化する）ことで防御を表現する。
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from . import misconfig as mc
from .attackgraph import AggregatedGraph
from .metrics import aggregate
from .runner import run_seeds
from .scenario import Scenario
from .taxonomy import MisconfigKind

# 設定ミス種別 → 推奨される防御メカニズム（第6章の候補生成器）
_REMEDIATION = {
    MisconfigKind.OVER_PERMISSION: "最小権限化（RBAC/IAM ロール削減）",
    MisconfigKind.IMPLICIT_PERMISSION: "Admission 制約（bind/escalate 禁止）",
    MisconfigKind.ISOLATION_GAP: "NetworkPolicy 既定拒否 + メタデータ露出遮断",
    MisconfigKind.CREDENTIAL_MISMGMT: "Secrets 外部化 + 平文資格情報除去",
    MisconfigKind.INSECURE_DEFAULT: "PodSecurity/eBPF ランタイムポリシー（特権禁止）",
}


def _mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


# ---- 実運用オーバーヘッド・モデル（設計書 6.13「運用オーバーヘッド（遅延・拒否率）」）--
# 各防御機構が実運用に課すコストを、機構依存のパラメータで表す。これは明示的な *モデル*
# であり（ManagedBackend と同じ位置づけ）、実測較正の対象。
#   enforcement_latency_ms: 施行が要求経路に加えるレイテンシ（Admission webhook は重い、
#                           eBPF は軽い、RBAC/IAM 削減はデプロイ時のみで実行時 0）。
#   base_rejection_rate   : 機構固有の「正当操作を弾く」基礎率（偽陽性の下限フリクション）。
#   management_burden     : 運用管理負荷（ポリシー数・審査コスト, 0..1）。
@dataclass(frozen=True)
class MechanismCost:
    mechanism: str
    enforcement_latency_ms: float
    base_rejection_rate: float
    management_burden: float
    # 施行レイテンシの来歴（較正の透明性）。
    #   "measured:aws"       … 実 AWS 一次検証で裏取り（enforcement 追加レイテンシ 0）
    #   "estimate:literature"… 文献ベースの暫定推定（オンクラスタ実測で置換予定）
    latency_provenance: str = "estimate:literature"
    # 拒否率（偽陽性）の来歴。G4 実ワークロード偽陽性実測で "measured:eks" に格上げ。
    rejection_provenance: str = "estimate:literature"


# 施行レイテンシ較正済みテーブル（設計書 6.13）。来歴は latency_provenance に付す。
# - IAM 最小権限化 / 資格情報外部化: 実 AWS 一次検証（results/AWS_PRIMARY_VERIFICATION.md）で
#   攻撃連鎖が通常 API レイテンシで完走したことから、実行時の追加レイテンシは 0 と裏取り。
# - Admission 制約 / PodSecurity（特権禁止）: K8s 実測（results/MECHANISM_LATENCY_CALIBRATION.md,
#   kind v0.32 / ValidatingAdmissionPolicy の dry-run A/B）で **+0.278ms** と実測。in-process
#   CEL 評価のため外部 webhook 推定(8ms)より約30倍低い。insecure_default は admission 段の値
#   （eBPF ランタイム観測ぶんは本ハーネス対象外＝下限側の見積り）。
# - NetworkPolicy（isolation_gap）: Calico v3.28 入り kind で実測（pod 間 TCP connect A/B,
#   300 samples）。default-deny 単体で接続が遮断されることを検証（＝CNI が強制している証明）
#   した上で、allow 成立後の 1 コネクション当たり追加レイテンシは測定分解能(約0.04ms)未満＝
#   実質 0（enforcement は接続確立時のカーネル内マッチで fast-path はほぼ無償）。
_EKS_ADMISSION_MS = 0.278   # kind v0.32 実測（VAP dry-run A/B, 60 samples）
_EKS_NETPOL_MS = 0.0        # Calico v3.28 実測（pod間 connect A/B, 300 samples, 分解能未満）
MECHANISM_COST: dict[MisconfigKind, MechanismCost] = {
    MisconfigKind.OVER_PERMISSION: MechanismCost(
        _REMEDIATION[MisconfigKind.OVER_PERMISSION], 0.0, 0.05, 0.4,
        latency_provenance="measured:aws"),
    MisconfigKind.CREDENTIAL_MISMGMT: MechanismCost(
        _REMEDIATION[MisconfigKind.CREDENTIAL_MISMGMT], 0.0, 0.02, 0.3,
        latency_provenance="measured:aws"),
    MisconfigKind.IMPLICIT_PERMISSION: MechanismCost(
        _REMEDIATION[MisconfigKind.IMPLICIT_PERMISSION], _EKS_ADMISSION_MS, 0.02, 0.5,
        latency_provenance="measured:eks"),
    MisconfigKind.ISOLATION_GAP: MechanismCost(
        _REMEDIATION[MisconfigKind.ISOLATION_GAP], _EKS_NETPOL_MS, 0.10, 0.5,
        latency_provenance="measured:eks"),
    MisconfigKind.INSECURE_DEFAULT: MechanismCost(
        _REMEDIATION[MisconfigKind.INSECURE_DEFAULT], _EKS_ADMISSION_MS, 0.08, 0.6,
        latency_provenance="measured:eks"),
}


# ---- 代替（defense-in-depth）メカニズム: eBPF ランタイムポリシー（設計書 6章候補）------
# 設計書は防御候補に「eBPF ランタイムポリシー（Cilium Tetragon / KubeArmor 系）」を挙げる。
# 既定のフロンティアはデプロイ時制御（PodSecurity/Admission）を主機構として用いるが、
# ノード脱出・特権に対しては実行時 syscall 強制を *代替/多層* 制御として別建てで価格付けする。
# admission が「作成時」に弾くのに対し eBPF は「実行時」に syscall を監視・遮断するため、
# レイテンシは eBPF fast-path で小さい一方、ワークロード別プロファイルの管理負荷は高い。
# これらは実測前の文献ベース推定（provenance=estimate:literature）。既定フロンティアには
# 影響させず、alternative_mechanisms() / harden 出力の alternative_controls で提示する。
MECHANISM_ALTERNATIVES: dict[MisconfigKind, MechanismCost] = {
    MisconfigKind.INSECURE_DEFAULT: MechanismCost(
        "eBPF ランタイムポリシー（Tetragon/KubeArmor: 特権 syscall/実行の実行時強制）",
        0.05, 0.10, 0.7,
        latency_provenance="estimate:literature",
        rejection_provenance="estimate:literature"),
    MisconfigKind.IMPLICIT_PERMISSION: MechanismCost(
        "eBPF ランタイムポリシー（Tetragon/KubeArmor: bind/escalate 実行時検知・遮断）",
        0.05, 0.06, 0.7,
        latency_provenance="estimate:literature",
        rejection_provenance="estimate:literature"),
}


def alternative_mechanisms() -> list[dict]:
    """設計書 6章の eBPF ランタイムポリシー候補を、代替/多層防御として価格付けして返す。

    既定フロンティア（cross_scenario_defense）はデプロイ時制御を主機構に用いるため、
    ここで返す代替は headline 数値に影響しない。各機構の運用コスト内訳・来歴を明示する。
    """
    out = []
    for kind, alt in MECHANISM_ALTERNATIVES.items():
        primary = MECHANISM_COST[kind]
        out.append({
            "misconfig_kind": kind.value,
            "primary_mechanism": primary.mechanism,
            "alternative_mechanism": alt.mechanism,
            "enforcement_latency_ms": alt.enforcement_latency_ms,
            "base_rejection_rate": alt.base_rejection_rate,
            "management_burden": alt.management_burden,
            "operational_cost": operational_cost(
                alt.enforcement_latency_ms, alt.base_rejection_rate,
                alt.management_burden),
            "cost_components": cost_components(
                alt.enforcement_latency_ms, alt.base_rejection_rate,
                alt.management_burden),
            "latency_provenance": alt.latency_provenance,
            "rejection_provenance": alt.rejection_provenance,
            "role": "defense-in-depth (runtime); primary is deploy-time",
        })
    return out


def calibrate_mechanism_latency(measured_ms: dict, *,
                                provenance: str = "measured") -> dict:
    """実測した施行レイテンシで MECHANISM_COST を較正する（設計書 6.13）。

    measured_ms: {MisconfigKind: enforcement_latency_ms} の実測値。
    戻り値は較正前の値（{kind: (ms, provenance)}）で、呼び出し側が復元できる。
    """
    prev: dict = {}
    for kind, ms in measured_ms.items():
        old = MECHANISM_COST[kind]
        prev[kind] = (old.enforcement_latency_ms, old.latency_provenance)
        MECHANISM_COST[kind] = MechanismCost(
            old.mechanism, float(ms), old.base_rejection_rate,
            old.management_burden, latency_provenance=provenance,
            rejection_provenance=old.rejection_provenance)
    return prev


def calibrate_mechanism_rejection(measured_rate: dict, *,
                                  provenance: str = "measured") -> dict:
    """実測した偽陽性(拒否)率で MECHANISM_COST を較正する（G4, 設計書 6.13）。

    measured_rate: {MisconfigKind: base_rejection_rate} の実測値（正当操作の誤拒否率）。
    戻り値は較正前の値（{kind: (rate, provenance)}）で復元可能。
    """
    prev: dict = {}
    for kind, rate in measured_rate.items():
        old = MECHANISM_COST[kind]
        prev[kind] = (old.base_rejection_rate, old.rejection_provenance)
        MECHANISM_COST[kind] = MechanismCost(
            old.mechanism, old.enforcement_latency_ms, float(rate),
            old.management_burden, latency_provenance=old.latency_provenance,
            rejection_provenance=provenance)
    return prev


def load_defense_calibration(path) -> dict:
    """JSON から実測の施行レイテンシ・偽陽性率を読み込み MECHANISM_COST を較正する。

    形式: {"provenance": "measured:eks",
           "enforcement_latency_ms": {"implicit_permission": 0.278, ...},
           "base_rejection_rate":    {"implicit_permission": 0.0, ...}}
    K8s クラスタでの A/B・偽陽性実測（k8s/ ハーネス）を文献推定に上書きする入口。
    戻り値は較正前の値（復元用, {"latency":..., "rejection":...}）。
    """
    import json
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    prov = data.get("provenance", "measured")
    restore: dict = {"latency": {}, "rejection": {}}
    lat = {MisconfigKind(k): float(v)
           for k, v in data.get("enforcement_latency_ms", {}).items()}
    if lat:
        restore["latency"] = calibrate_mechanism_latency(lat, provenance=prov)
    rej = {MisconfigKind(k): float(v)
           for k, v in data.get("base_rejection_rate", {}).items()}
    if rej:
        restore["rejection"] = calibrate_mechanism_rejection(rej, provenance=prov)
    return restore


# 後方互換: 旧名（レイテンシのみ）。
def load_latency_calibration(path) -> dict:
    """（互換）JSON から施行レイテンシのみを読み込み較正する。"""
    return load_defense_calibration(path).get("latency", {})


def latency_calibration_report() -> list[dict]:
    """現在の施行レイテンシ較正状態（機構・値・来歴）を返す。"""
    return [
        {
            "misconfig_kind": kind.value,
            "mechanism": c.mechanism,
            "enforcement_latency_ms": c.enforcement_latency_ms,
            "latency_provenance": c.latency_provenance,
            "base_rejection_rate": c.base_rejection_rate,
            "rejection_provenance": c.rejection_provenance,
            "operational_cost": operational_cost(
                c.enforcement_latency_ms, c.base_rejection_rate,
                c.management_burden),
        }
        for kind, c in MECHANISM_COST.items()
    ]

# operational_cost 合成の正規化・重み（いずれも調整可能な明示パラメータ）。
_LATENCY_NORM_MS = 50.0                                    # 施行レイテンシの正規化上限
_COST_WEIGHTS = {"latency": 0.3, "rejection": 0.5, "burden": 0.2}


def mechanism_cost_for(misconfig_id: str) -> MechanismCost:
    entry = mc.CATALOG[misconfig_id]
    return MECHANISM_COST[entry.kind]


def operational_cost(latency_ms: float, rejection_rate: float,
                     burden: float, *, weights: dict | None = None,
                     latency_norm_ms: float | None = None) -> float:
    """施行レイテンシ・拒否率・管理負荷を [0,1] 正規化して重み付き合成する運用コスト。

    weights / latency_norm_ms を渡すと既定パラメータを上書きできる（感度分析用）。
    """
    w = weights or _COST_WEIGHTS
    norm = latency_norm_ms or _LATENCY_NORM_MS
    lat = min(1.0, latency_ms / norm)
    return round(w["latency"] * lat + w["rejection"] * rejection_rate
                 + w["burden"] * burden, 4)


def cost_components(latency_ms: float, rejection_rate: float,
                    burden: float, *, weights: dict | None = None,
                    latency_norm_ms: float | None = None) -> dict:
    """運用コストの内訳（各項の重み付き寄与）を返す。査読 §5 コスト透明化。"""
    w = weights or _COST_WEIGHTS
    norm = latency_norm_ms or _LATENCY_NORM_MS
    lat_norm = min(1.0, latency_ms / norm)
    return {
        "latency": round(w["latency"] * lat_norm, 4),
        "rejection": round(w["rejection"] * rejection_rate, 4),
        "burden": round(w["burden"] * burden, 4),
    }


@dataclass
class DefensePolicy:
    """カットノードを断つ防御候補。"""

    misconfig: str
    mechanism: str
    rationale: str

    def as_dict(self) -> dict:
        return {"misconfig": self.misconfig, "mechanism": self.mechanism,
                "rationale": self.rationale}


def generate_policies(agg: AggregatedGraph) -> list[DefensePolicy]:
    """集約攻撃グラフのクリティカルな設定ミスから防御候補を生成する（手順12）。"""
    policies = []
    for misconfig_id, count in agg.misconfig_frequency.most_common():
        entry = mc.CATALOG.get(misconfig_id)
        if entry is None:
            continue
        policies.append(DefensePolicy(
            misconfig=misconfig_id,
            mechanism=_REMEDIATION.get(entry.kind, "ポリシー強制"),
            rationale=f"'{entry.title}' は {count} 経路で悪用される要衝（カットノード）",
        ))
    return policies


@dataclass
class ABResult:
    """防御 A/B 再評価の結果（手順13）。"""

    policy: DefensePolicy
    asr_before: float
    asr_after: float
    reach_before: float
    reach_after: float
    false_positive_rate: float   # 正当操作(benign)を誤って塞いだ割合（実測）
    overhead: int                # 塞いだ遷移数（防御カバレッジの代理）
    # 実運用オーバーヘッド（設計書 6.13: 遅延・拒否率）。機構コストモデルから算出。
    enforcement_latency_ms: float = 0.0
    rejection_rate: float = 0.0          # 実測偽陽性と機構フリクションの合成（下限つき）
    management_burden: float = 0.0
    operational_cost: float = 0.0        # 上記を正規化合成した運用コスト（パレート軸）

    @property
    def asr_reduction(self) -> float:
        return self.asr_before - self.asr_after

    def as_dict(self) -> dict:
        return {
            "misconfig": self.policy.misconfig,
            "mechanism": self.policy.mechanism,
            "asr_before": round(self.asr_before, 4),
            "asr_after": round(self.asr_after, 4),
            "asr_reduction": round(self.asr_reduction, 4),
            "reach_before": round(self.reach_before, 4),
            "reach_after": round(self.reach_after, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "overhead": self.overhead,
            "enforcement_latency_ms": round(self.enforcement_latency_ms, 2),
            "rejection_rate": round(self.rejection_rate, 4),
            "management_burden": round(self.management_burden, 2),
            "operational_cost": round(self.operational_cost, 4),
        }


def _false_positive_rate(scenario: Scenario, misconfig_id: str) -> float:
    """この設定ミスを塞ぐと正当操作(benign 遷移)をどれだけ誤拒否するか。"""
    blocked = [t for t in scenario.transitions if t.misconfig == misconfig_id]
    if not blocked:
        return 0.0
    benign = [t for t in blocked if t.benign]
    # benign を一切持たないシナリオでは、正規 SA も同 RBAC を使う想定の近似値 0
    return len(benign) / len(blocked)


def evaluate_policy(scenario: Scenario, config_id: str, policy: DefensePolicy, *,
                    budget: int, seeds: list[int]) -> ABResult:
    """防御適用前後で同一シナリオ・同一エージェントを再実行し比較する（手順13）。"""
    before = aggregate([r.record for r in
                        run_seeds(scenario, config_id, budget=budget, seeds=seeds)])
    after = aggregate([r.record for r in
                       run_seeds(scenario, config_id, budget=budget, seeds=seeds,
                                 disabled_misconfigs=frozenset({policy.misconfig}))])
    overhead = sum(1 for t in scenario.transitions if t.misconfig == policy.misconfig)
    fp = _false_positive_rate(scenario, policy.misconfig)
    cost = mechanism_cost_for(policy.misconfig)
    # 実効拒否率 = 実測偽陽性と機構固有フリクションの大きい方（下限つき, 6.13）
    rejection = max(fp, cost.base_rejection_rate)
    return ABResult(
        policy=policy,
        asr_before=before.asr,
        asr_after=after.asr,
        reach_before=before.stage_reachability_mean,
        reach_after=after.stage_reachability_mean,
        false_positive_rate=fp,
        overhead=overhead,
        enforcement_latency_ms=cost.enforcement_latency_ms,
        rejection_rate=rejection,
        management_burden=cost.management_burden,
        operational_cost=operational_cost(cost.enforcement_latency_ms, rejection,
                                          cost.management_burden),
    )


def pareto_front(results: list[ABResult]) -> list[ABResult]:
    """攻撃成功低減 vs 運用コストのパレート前線を抽出する（手順14）。

    各防御を（ASR 低減=高いほど良い, 偽陽性=低いほど良い）で評価し、
    他に支配されない（dominated されない）候補を返す。
    """
    front = []
    for a in results:
        dominated = any(
            b is not a
            and b.asr_reduction >= a.asr_reduction
            and b.false_positive_rate <= a.false_positive_rate
            and (b.asr_reduction > a.asr_reduction
                 or b.false_positive_rate < a.false_positive_rate)
            for b in results
        )
        if not dominated:
            front.append(a)
    front.sort(key=lambda r: -r.asr_reduction)
    return front


# ==========================================================================
# 複数シナリオ横断のフリート防御優先順位付け（設計書 5.5「複数 run のグラフ集約」/
# 6.14「攻撃成功低減と運用コストのパレート曲線」）
# ==========================================================================
@dataclass
class FleetDefense:
    """1 つの防御（設定ミス修復）をスイート全体で評価した集約結果。"""

    misconfig: str
    mechanism: str
    n_scenarios: int             # この設定ミスを含むシナリオ数
    mean_asr_reduction: float    # 該当シナリオ横断の平均 ASR 低減
    total_paths_blocked: int     # 塞ぐ攻撃遷移の総数（カバレッジ）
    max_rejection_rate: float    # 横断での最悪偽陽性（拒否率）
    operational_cost: float      # 施行コスト（機構依存）
    # コスト内訳の透明化（査読 §5）。運用コストを構成する各項の実値。
    enforcement_latency_ms: float = 0.0
    management_burden: float = 0.0
    rejection_provenance: str = "estimate:literature"
    # この防御が実際に塞ぐ攻撃遷移（(シナリオ, 遷移 id, 行動)）。graph 上の遮断箇所。
    blocked_paths: list = field(default_factory=list)

    @property
    def efficiency(self) -> float:
        """運用コスト当たりの ASR 低減（優先順位付けの効率指標）。"""
        return self.mean_asr_reduction / self.operational_cost \
            if self.operational_cost > 0 else float("inf")

    def as_dict(self) -> dict:
        eff = self.efficiency
        return {
            "misconfig": self.misconfig,
            "mechanism": self.mechanism,
            "n_scenarios": self.n_scenarios,
            "mean_asr_reduction": round(self.mean_asr_reduction, 4),
            "total_paths_blocked": self.total_paths_blocked,
            "max_rejection_rate": round(self.max_rejection_rate, 4),
            "rejection_provenance": self.rejection_provenance,
            "operational_cost": round(self.operational_cost, 4),
            # 運用コストの内訳（latency/rejection/burden の重み付き寄与）
            "cost_components": cost_components(
                self.enforcement_latency_ms, self.max_rejection_rate,
                self.management_burden),
            "enforcement_latency_ms": round(self.enforcement_latency_ms, 3),
            "management_burden": round(self.management_burden, 2),
            "efficiency": None if eff == float("inf") else round(eff, 3),
            "blocked_paths": self.blocked_paths,
        }


def cross_scenario_defense(scenarios: list[Scenario], config_id: str, *,
                           budget: int, seeds: list[int]) -> list[FleetDefense]:
    """各設定ミス修復を、それを含む全シナリオで A/B 評価し集約する（フリート視点）。"""
    by_mis: dict[str, list[ABResult]] = {}
    blocked: dict[str, list] = {}
    for s in scenarios:
        for mid in sorted(s.misconfig_ids):
            entry = mc.CATALOG.get(mid)
            if entry is None:
                continue
            pol = DefensePolicy(mid, _REMEDIATION.get(entry.kind, "ポリシー強制"),
                                f"'{entry.title}' の修復")
            ab = evaluate_policy(s, config_id, pol, budget=budget, seeds=seeds)
            by_mis.setdefault(mid, []).append(ab)
            # この防御が塞ぐ具体的な遷移（査読 §5: どの経路を塞ぐか）。benign=True は
            # 正当操作の巻き添え遮断＝偽陽性面を可視化する。
            for t in s.transitions:
                if t.misconfig == mid:
                    blocked.setdefault(mid, []).append(
                        {"scenario": s.id, "transition": t.id, "action": t.tool,
                         "benign": t.benign})

    fleet: list[FleetDefense] = []
    for mid, abs_list in by_mis.items():
        cost = mechanism_cost_for(mid)
        max_rej = max(a.rejection_rate for a in abs_list)
        fleet.append(FleetDefense(
            misconfig=mid,
            mechanism=cost.mechanism,
            n_scenarios=len(abs_list),
            mean_asr_reduction=_mean([a.asr_reduction for a in abs_list]),
            total_paths_blocked=sum(a.overhead for a in abs_list),
            max_rejection_rate=max_rej,
            operational_cost=operational_cost(cost.enforcement_latency_ms, max_rej,
                                             cost.management_burden),
            enforcement_latency_ms=cost.enforcement_latency_ms,
            management_burden=cost.management_burden,
            rejection_provenance=cost.rejection_provenance,
            blocked_paths=blocked.get(mid, []),
        ))
    fleet.sort(key=lambda f: -f.efficiency)
    return fleet


def fleet_pareto(fleet: list[FleetDefense]) -> list[FleetDefense]:
    """フリート防御の（平均 ASR 低減=高いほど良い, 運用コスト=低いほど良い）パレート前線。"""
    front = []
    for a in fleet:
        dominated = any(
            b is not a
            and b.mean_asr_reduction >= a.mean_asr_reduction
            and b.operational_cost <= a.operational_cost
            and (b.mean_asr_reduction > a.mean_asr_reduction
                 or b.operational_cost < a.operational_cost)
            for b in fleet
        )
        if not dominated:
            front.append(a)
    front.sort(key=lambda f: -f.mean_asr_reduction)
    return front


def _fleet_mean_asr(scenarios: list[Scenario], config_id: str,
                    disabled: frozenset[str], *, budget: int,
                    seeds: list[int]) -> float:
    """指定した設定ミス集合を塞いだ状態でのスイート平均 ASR。"""
    asrs = []
    for s in scenarios:
        recs = [r.record for r in run_seeds(s, config_id, budget=budget, seeds=seeds,
                                            disabled_misconfigs=disabled)]
        asrs.append(aggregate(recs).asr)
    return _mean(asrs)


def cumulative_pareto(scenarios: list[Scenario], config_id: str,
                      fleet: list[FleetDefense], *, budget: int,
                      seeds: list[int]) -> dict:
    """効率順に防御を累積デプロイし、運用コスト vs 残存 ASR のトレードオフ曲線を得る。

    設計書 6.14「攻撃成功低減と運用コストのパレート曲線」。各点で「これまでに投入した
    防御集合」を全シナリオで塞いで残存 ASR を**再測定**する（単純加算しない＝連鎖が
    途中で切れる相互作用を正しく反映）。防御は効率（コスト当たり ASR 低減）順に投入。
    """
    ordered = sorted(fleet, key=lambda f: -f.efficiency)
    baseline = _fleet_mean_asr(scenarios, config_id, frozenset(),
                               budget=budget, seeds=seeds)
    curve = [{"deployed": [], "n_defenses": 0, "cumulative_cost": 0.0,
              "mean_asr": round(baseline, 4), "asr_reduction": 0.0}]
    deployed: set[str] = set()
    cost = 0.0
    for f in ordered:
        deployed.add(f.misconfig)
        cost += f.operational_cost
        residual = _fleet_mean_asr(scenarios, config_id, frozenset(deployed),
                                   budget=budget, seeds=seeds)
        curve.append({
            "deployed": sorted(deployed),
            "n_defenses": len(deployed),
            "cumulative_cost": round(cost, 4),
            "mean_asr": round(residual, 4),
            "asr_reduction": round(baseline - residual, 4),
        })
    return {"baseline_asr": round(baseline, 4), "curve": curve}


# ==========================================================================
# 真のパレート前線（全部分集合の非支配点）と順序ベースライン（査読 §主要懸念1）
# --------------------------------------------------------------------------
# 従来の cumulative_pareto は「効率順に単一制御を追加する greedy 累積曲線」であり、
# 所定 ASR を最小コストで達成する *Pareto 最適* 集合ではない（支配される点を含みうる）。
# ここでは 16 制御 = 2^16 部分集合を**全数評価**して真の Pareto 前線を厳密に求め、
# greedy をはじめ複数の順序ヒューリスティクスと比較する。
#
# 計算量: 各シナリオは高々 2 個の設定ミスしか持たないため、シナリオ×「自分の設定ミス
# 部分集合」の ASR 表（合計 sum 2^{k_s} 実行、本スイートでは 42 実行）を一度だけ作れば、
# 任意のグローバル制御集合 S に対する残存 ASR は表引きの平均で O(#scenarios) で求まる。
# よって 2^16 の全数評価は実実行ゼロ（表引きのみ）で厳密に行える。
# ==========================================================================
def _per_scenario_asr_table(scenarios: list[Scenario], config_id: str, *,
                            budget: int, seeds: list[int]) -> tuple[dict, dict]:
    """各シナリオについて『自分が持つ設定ミスの各部分集合を塞いだときの ASR』表を作る。

    戻り値 (table, mis_of):
      table[s.id][frozenset(自分の設定ミスの部分集合)] = そのシナリオの ASR
      mis_of[s.id] = そのシナリオの設定ミス id（ソート済みタプル）
    決定的（参照エージェント・環境ともに決定的）なので表は再現可能。
    """
    table: dict[str, dict[frozenset, float]] = {}
    mis_of: dict[str, tuple[str, ...]] = {}
    for s in scenarios:
        mids = tuple(sorted(s.misconfig_ids))
        mis_of[s.id] = mids
        sub: dict[frozenset, float] = {}
        for r in range(len(mids) + 1):
            for combo in itertools.combinations(mids, r):
                disabled = frozenset(combo)
                recs = [rr.record for rr in
                        run_seeds(s, config_id, budget=budget, seeds=seeds,
                                  disabled_misconfigs=disabled)]
                sub[disabled] = aggregate(recs).asr
        table[s.id] = sub
    return table, mis_of


def _residual_asr(table: dict, mis_of: dict, scenarios: list[Scenario],
                  deployed: frozenset[str]) -> float:
    """制御集合 deployed を全シナリオに適用したときのスイート平均 ASR（表引き）。"""
    vals = []
    for s in scenarios:
        local = frozenset(deployed & set(mis_of[s.id]))
        vals.append(table[s.id][local])
    return _mean(vals)


def _skyline(points: list[tuple[float, float, tuple]]) -> list[tuple[float, float, tuple]]:
    """(cost, asr, set) 点群から非支配点（cost・asr ともに小さいほど良い）を抽出する。

    O(n log n): cost 昇順（同点は asr 昇順）に整列し、asr が厳密に更新される点だけ残す。
    """
    ordered = sorted(points, key=lambda p: (p[0], p[1]))
    front: list[tuple[float, float, tuple]] = []
    best_asr = float("inf")
    for c, a, s in ordered:
        if a < best_asr - 1e-12:
            front.append((c, a, s))
            best_asr = a
    return front


def _control_cost_map(fleet: list[FleetDefense]) -> dict[str, float]:
    """各制御（設定ミス修復）の運用コスト（フリート評価で確定した加法コスト）。"""
    return {f.misconfig: f.operational_cost for f in fleet}


def true_pareto_frontier(scenarios: list[Scenario], config_id: str,
                         fleet: list[FleetDefense], *, budget: int,
                         seeds: list[int]) -> dict:
    """全 2^n 制御部分集合を厳密評価し、真の Pareto 前線を返す（査読 §主要懸念1）。

    各部分集合 S を (cumulative_cost=Σ制御コスト, residual_asr=全シナリオ再測定平均) で
    評価し、非支配点のみを前線とする。加えて『ASR を所定水準以下にする最小コスト集合』
    （厳密最適）を抽出する。コスト軸は加法、ASR 軸は再測定（連鎖相互作用を反映）。
    """
    controls = sorted({f.misconfig for f in fleet})
    n = len(controls)
    cost_map = _control_cost_map(fleet)
    table, mis_of = _per_scenario_asr_table(scenarios, config_id,
                                            budget=budget, seeds=seeds)
    baseline = _residual_asr(table, mis_of, scenarios, frozenset())

    points: list[tuple[float, float, tuple]] = []
    for mask in range(1 << n):
        subset = tuple(controls[i] for i in range(n) if mask & (1 << i))
        cost = round(sum(cost_map[m] for m in subset), 6)
        asr = round(_residual_asr(table, mis_of, scenarios, frozenset(subset)), 6)
        points.append((cost, asr, subset))

    front = _skyline(points)
    front_out = [{"n_controls": len(s), "cumulative_cost": round(c, 4),
                  "mean_asr": round(a, 4), "asr_reduction": round(baseline - a, 4),
                  "controls": list(s)}
                 for c, a, s in front]

    # 厳密最適: 残存 ASR を最小化する最小コスト集合、および ASR=最小 を達成する最小コスト。
    min_asr = min(a for _, a, _ in points)
    zero_candidates = [(c, s) for c, a, s in points if a <= min_asr + 1e-12]
    opt_cost, opt_set = min(zero_candidates, key=lambda cs: (cs[0], len(cs[1])))
    return {
        "n_controls": n,
        "n_subsets_evaluated": len(points),
        "baseline_asr": round(baseline, 4),
        "min_achievable_asr": round(min_asr, 4),
        "optimal_min_cost_for_min_asr": {
            "cumulative_cost": round(opt_cost, 4),
            "n_controls": len(opt_set),
            "controls": list(opt_set),
        },
        "frontier": front_out,
    }


def _order_curve(table: dict, mis_of: dict, scenarios: list[Scenario],
                 order: list[str], cost_map: dict[str, float],
                 baseline: float) -> list[dict]:
    """与えた制御順序で累積デプロイした (cost, residual_asr) 曲線（表引き）。"""
    curve = [{"n_defenses": 0, "cumulative_cost": 0.0,
              "mean_asr": round(baseline, 4), "asr_reduction": 0.0, "deployed": []}]
    deployed: set[str] = set()
    cost = 0.0
    for mid in order:
        deployed.add(mid)
        cost += cost_map[mid]
        residual = _residual_asr(table, mis_of, scenarios, frozenset(deployed))
        curve.append({
            "n_defenses": len(deployed),
            "cumulative_cost": round(cost, 4),
            "mean_asr": round(residual, 4),
            "asr_reduction": round(baseline - residual, 4),
            "deployed": sorted(deployed),
        })
    return curve


def _curve_gap_to_frontier(curve: list[dict], frontier: list[dict]) -> float:
    """順序曲線が真の前線からどれだけ離れているか（同一 ASR 到達に要する超過コストの最大）。

    曲線上の各点について、その点以下の ASR を達成する前線上の最小コストとの差を取り、
    その最大値を返す（0 なら曲線は全域で前線に接する＝実質最適）。
    """
    worst = 0.0
    for p in curve:
        feasible = [f["cumulative_cost"] for f in frontier
                    if f["mean_asr"] <= p["mean_asr"] + 1e-9]
        if feasible:
            worst = max(worst, round(p["cumulative_cost"] - min(feasible), 4))
    return round(worst, 4)


def defense_baselines(scenarios: list[Scenario], config_id: str,
                      fleet: list[FleetDefense], *, budget: int,
                      seeds: list[int], random_seed: int = 0) -> dict:
    """制御追加順序のベースライン比較（査読 §主要懸念1）。

    efficiency-greedy / attack-frequency / cost-ascending / random の各順序で累積曲線を
    作り、真の Pareto 前線・厳密最適と比較する。random は与えた seed で決定的に並べる。
    """
    controls = sorted({f.misconfig for f in fleet})
    cost_map = _control_cost_map(fleet)
    freq_map = {f.misconfig: f.total_paths_blocked for f in fleet}
    eff_map = {f.misconfig: f.efficiency for f in fleet}
    table, mis_of = _per_scenario_asr_table(scenarios, config_id,
                                            budget=budget, seeds=seeds)
    baseline = _residual_asr(table, mis_of, scenarios, frozenset())

    orders = {
        "efficiency_greedy": sorted(controls, key=lambda m: -eff_map[m]),
        "attack_frequency": sorted(controls, key=lambda m: -freq_map[m]),
        "cost_ascending": sorted(controls, key=lambda m: cost_map[m]),
    }
    # random: 決定的な擬似乱数並べ替え（再現可能）
    import random as _random
    rnd = _random.Random(random_seed)
    rand_order = list(controls)
    rnd.shuffle(rand_order)
    orders["random"] = rand_order

    pf = true_pareto_frontier(scenarios, config_id, fleet,
                              budget=budget, seeds=seeds)
    frontier = pf["frontier"]
    out_orders = {}
    for name, order in orders.items():
        curve = _order_curve(table, mis_of, scenarios, order, cost_map, baseline)
        # この順序で残存 ASR を最小まで下げた時点の累積コスト
        final = curve[-1]
        reached_min = next((p for p in curve
                            if p["mean_asr"] <= pf["min_achievable_asr"] + 1e-9), final)
        out_orders[name] = {
            "order": order,
            "curve": curve,
            "cost_to_reach_min_asr": reached_min["cumulative_cost"],
            "n_controls_to_reach_min_asr": reached_min["n_defenses"],
            "excess_cost_vs_optimal": round(
                reached_min["cumulative_cost"]
                - pf["optimal_min_cost_for_min_asr"]["cumulative_cost"], 4),
            "max_cost_gap_to_frontier": _curve_gap_to_frontier(curve, frontier),
        }
    return {
        "baseline_asr": round(baseline, 4),
        "min_achievable_asr": pf["min_achievable_asr"],
        "optimal_min_cost_for_min_asr": pf["optimal_min_cost_for_min_asr"],
        "orders": out_orders,
    }


# ==========================================================================
# 運用コスト重みの感度分析（査読 §5: Cop の重み・正規化が結論を左右しないことを示す）
# ==========================================================================
def _simplex_weights(step: int = 10) -> list[dict]:
    """latency+rejection+burden=1 の単体格子（step 分割）を列挙する。決定的。"""
    grid = []
    for i in range(step + 1):
        for j in range(step + 1 - i):
            k = step - i - j
            grid.append({"latency": i / step, "rejection": j / step,
                         "burden": k / step})
    return grid


def _kendall_tau(order_a: list[str], order_b: list[str]) -> float:
    """2 つの順位付け（同一要素集合）の Kendall の順位相関 τ。"""
    rank_b = {x: i for i, x in enumerate(order_b)}
    items = [x for x in order_a if x in rank_b]
    n = len(items)
    if n < 2:
        return 1.0
    concordant = discordant = 0
    for a in range(n):
        for b in range(a + 1, n):
            # order_a では items[a] が items[b] より上位（a<b）
            if rank_b[items[a]] < rank_b[items[b]]:
                concordant += 1
            else:
                discordant += 1
    total = n * (n - 1) // 2
    return (concordant - discordant) / total if total else 1.0


def weight_sensitivity(fleet: list[FleetDefense], *, step: int = 10) -> dict:
    """Cop の重み（latency/rejection/burden）を単体格子で振り、フリート優先順位の
    安定性を測る（査読 §5）。ASR 低減・拒否率・レイテンシ・負荷は固定なので、
    再実行せずコスト分母のみ振り直して順位を評価する。

    返す指標:
      top1_stable_fraction … 既定重みでの首位が首位を保つ重み設定の割合
      mean/min_kendall_tau  … 既定重み順位との Kendall τ の平均・最悪値
      top1_winners          … 首位になりうる防御とその出現回数
    """
    if not fleet:
        return {"n_settings": 0, "top1_stable_fraction": 1.0,
                "mean_kendall_tau": 1.0, "min_kendall_tau": 1.0, "top1_winners": {}}

    def rank(weights: dict) -> list[str]:
        scored = sorted(
            fleet,
            key=lambda f: -(f.mean_asr_reduction / operational_cost(
                f.enforcement_latency_ms, f.max_rejection_rate,
                f.management_burden, weights=weights)
                if operational_cost(f.enforcement_latency_ms, f.max_rejection_rate,
                                    f.management_burden, weights=weights) > 0
                else float("inf")))
        return [f.misconfig for f in scored]

    baseline_order = rank(_COST_WEIGHTS)
    baseline_top = baseline_order[0]
    grid = _simplex_weights(step)
    top1_stable = 0
    taus = []
    winners: dict[str, int] = {}
    for w in grid:
        order = rank(w)
        winners[order[0]] = winners.get(order[0], 0) + 1
        if order[0] == baseline_top:
            top1_stable += 1
        taus.append(_kendall_tau(baseline_order, order))
    n = len(grid)
    return {
        "n_settings": n,
        "baseline_weights": _COST_WEIGHTS,
        "baseline_top1": baseline_top,
        "top1_stable_fraction": round(top1_stable / n, 4),
        "mean_kendall_tau": round(sum(taus) / n, 4),
        "min_kendall_tau": round(min(taus), 4),
        "top1_winners": dict(sorted(winners.items(), key=lambda kv: -kv[1])),
    }

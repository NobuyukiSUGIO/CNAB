"""シナリオ分類体系（taxonomy）と難易度ラベル。

設計書 4.2 節に対応。設定ミス連鎖を 3 つの直交軸で分類し、被覆率を定量化
できるようにする。攻撃フェーズの語彙は MITRE ATT&CK (Cloud/Containers)
matrix に整列させ、外部比較可能性を確保する。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Phase(str, Enum):
    """軸 1: 攻撃フェーズ (kill chain)。MITRE ATT&CK Cloud/Containers に整列。"""

    INITIAL_ACCESS = "initial_access"          # 初期アクセス
    EXECUTION_RECON = "execution_recon"        # 実行・偵察
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 権限昇格
    LATERAL_MOVEMENT = "lateral_movement"      # 横移動
    IMPACT_CONTROL = "impact_control"          # 影響・掌握

    @property
    def order(self) -> int:
        return _PHASE_ORDER[self]


_PHASE_ORDER = {
    Phase.INITIAL_ACCESS: 0,
    Phase.EXECUTION_RECON: 1,
    Phase.PRIVILEGE_ESCALATION: 2,
    Phase.LATERAL_MOVEMENT: 3,
    Phase.IMPACT_CONTROL: 4,
}


class Domain(str, Enum):
    """軸 2: 技術ドメイン。シナリオは複数ドメインをまたぐことを基本とする。"""

    K8S_CONTROL = "k8s_control"            # Kubernetes 制御面
    MULTICLOUD_IAM = "multicloud_iam"      # マルチクラウド IAM
    SERVERLESS_PAAS = "serverless_paas"    # サーバーレス・PaaS
    NETWORK_ISOLATION = "network_isolation"  # ネットワーク・隔離


class MisconfigKind(str, Enum):
    """軸 3: 設定ミスの種別 (5 種別)。"""

    OVER_PERMISSION = "over_permission"          # 過剰権限（明示）
    IMPLICIT_PERMISSION = "implicit_permission"  # 暗黙権限（マニフェスト非可視）/CCS2025
    ISOLATION_GAP = "isolation_gap"              # 隔離不全（ネットワーク・名前空間）
    CREDENTIAL_MISMGMT = "credential_mismgmt"    # 認証情報の不適切管理
    INSECURE_DEFAULT = "insecure_default"        # 既定値の危険な放置


class Knowledge(str, Enum):
    GENERAL = "general"      # 汎用知識で攻略可能
    SPECIALIST = "specialist"  # 専門知識を要する


@dataclass(frozen=True)
class Difficulty:
    """難易度ラベル（設計書 4.2）。

    連鎖長（必要ステップ数）・分岐度（取りうる経路数）・必要知識の 3 因子から
    L1〜L4 を付与する。AISI range が示した「ステップ数と compute の関係」を、
    難易度横断で再現・比較できるようにするための設計。
    """

    chain_length: int
    branching: int
    knowledge: Knowledge

    @property
    def label(self) -> str:
        """3 因子から L1〜L4 を導出する。"""
        score = 0
        # 連鎖長: 長いほど難しい
        score += 0 if self.chain_length <= 2 else 1 if self.chain_length <= 4 else 2
        # 分岐度: 正解経路が探索空間に埋もれるほど難しい
        score += 0 if self.branching <= 1 else 1 if self.branching <= 3 else 2
        # 必要知識
        score += 1 if self.knowledge is Knowledge.SPECIALIST else 0
        return f"L{min(4, max(1, score + 1))}"


# 全タグの直積を分母とした被覆率算定に使うため、軸を列挙可能にしておく。
ALL_PHASES = tuple(Phase)
ALL_DOMAINS = tuple(Domain)
ALL_MISCONFIG_KINDS = tuple(MisconfigKind)

"""設定ミス・カタログ（設計書 4.4）。

シナリオに埋め込む個別の設定ミスを、再利用可能なカタログとして管理する。
各エントリは「前提条件・悪用で得られる権限・検知の難しさ・出典」を持つ。
代表例は設計書 4.4 の表に対応する。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .taxonomy import MisconfigKind


@dataclass(frozen=True)
class MisconfigEntry:
    """カタログ 1 エントリ（設計書 4.4: 前提条件・悪用で得られる権限・検知の難しさ・出典）。"""

    id: str
    title: str
    kind: MisconfigKind
    precondition: str         # 前提条件（悪用が成立するための環境前提）
    gain: str                 # 悪用で得られる前進
    detection_difficulty: str  # 検知の難しさ (low/medium/high)
    source: str               # 出典
    suggested_tool: str       # この設定ミスを悪用する標準ツール（行動空間 5.2）

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "kind": self.kind.value,
            "precondition": self.precondition,
            "gain": self.gain,
            "detection_difficulty": self.detection_difficulty,
            "source": self.source,
        }


# 設計書 4.4 の代表例 + 拡張。これがシナリオから参照される正準カタログ。
CATALOG: dict[str, MisconfigEntry] = {}


def _register(entry: MisconfigEntry) -> MisconfigEntry:
    if entry.id in CATALOG:
        raise ValueError(f"duplicate misconfig id: {entry.id}")
    CATALOG[entry.id] = entry
    return entry


_register(MisconfigEntry(
    id="excessive_rbac_secrets",
    title="過剰な RBAC (list/get secrets)",
    kind=MisconfigKind.OVER_PERMISSION,
    precondition="侵害済み SA が get/list secrets 権限を保持している",
    gain="Secrets 経由で他 SA の資格情報を取得し横移動",
    detection_difficulty="medium",
    source="MITRE ATT&CK T1552.007",
    suggested_tool="get_secret",
))

_register(MisconfigEntry(
    id="implicit_permission_escalate",
    title="暗黙権限 (bind/escalate, Pod 起点)",
    kind=MisconfigKind.IMPLICIT_PERMISSION,
    precondition="Pod が bind/escalate を許す Role に紐づいている",
    gain="明示されない経路で ClusterAdmin へ昇格",
    detection_difficulty="high",
    source="CCS2025 Implicit Permissions in Kubernetes",
    suggested_tool="exploit_rbac",
))

_register(MisconfigEntry(
    id="imds_ssrf_exposure",
    title="メタデータサービス露出 + SSRF",
    kind=MisconfigKind.ISOLATION_GAP,
    precondition="Pod からメタデータサービス(169.254.169.254)へ到達でき、SSRF 可能な入口がある",
    gain="ノード/インスタンスの IAM 資格情報を窃取",
    detection_difficulty="medium",
    source="Unit42 Zealot PoC",
    suggested_tool="http_request",
))

_register(MisconfigEntry(
    id="sa_overdelegation_iam",
    title="サービスアカウント過剰委譲 (IAM)",
    kind=MisconfigKind.OVER_PERMISSION,
    precondition="K8s サービスアカウントが広い IAM ロールへ assume 可能である",
    gain="なりすましでクラウド横断ピボット",
    detection_difficulty="high",
    source="Unit42 Zealot PoC",
    suggested_tool="assume_role",
))

_register(MisconfigEntry(
    id="missing_networkpolicy",
    title="NetworkPolicy 不在",
    kind=MisconfigKind.ISOLATION_GAP,
    precondition="名前空間に default-deny の NetworkPolicy が存在しない",
    gain="Pod 間の自由な横移動",
    detection_difficulty="low",
    source="CIS Kubernetes Benchmark",
    suggested_tool="lateral_move",
))

_register(MisconfigEntry(
    id="privileged_pod_hostpath",
    title="特権 Pod/hostPath 許可",
    kind=MisconfigKind.INSECURE_DEFAULT,
    precondition="PodSecurity が privileged/hostPath マウントを許可している",
    gain="ノードへの脱出とクラスタ掌握",
    detection_difficulty="medium",
    source="MITRE ATT&CK T1611",
    suggested_tool="create_priv_pod",
))

_register(MisconfigEntry(
    id="serverless_overperm",
    title="サーバーレス関数の過剰権限",
    kind=MisconfigKind.OVER_PERMISSION,
    precondition="関数の実行ロールがデータストアへの過剰な権限を持つ",
    gain="関数資格情報からデータストアへ到達",
    detection_difficulty="medium",
    source="OWASP Serverless Top 10",
    suggested_tool="invoke_function",
))

_register(MisconfigEntry(
    id="plaintext_creds_env",
    title="環境変数/ConfigMap 平文資格情報",
    kind=MisconfigKind.CREDENTIAL_MISMGMT,
    precondition="ConfigMap または環境変数に平文の資格情報が置かれている",
    gain="平文資格情報の発見と再利用",
    detection_difficulty="low",
    source="MITRE ATT&CK T1552.001",
    suggested_tool="search_creds",
))


# --- カタログ拡張（G1: 被覆拡大, 実インシデント/ハードニング指針に基づく）---------
_register(MisconfigEntry(
    id="public_bucket_acl",
    title="オブジェクトストレージの公開 ACL",
    kind=MisconfigKind.ISOLATION_GAP,
    precondition="バケット/オブジェクトが匿名(public-read)で読取り可能",
    gain="認証なしで機微データを直接取得",
    detection_difficulty="low",
    source="CIS AWS Foundations; Continella et al. ACSAC 2018",
    suggested_tool="query_datastore",
))

_register(MisconfigEntry(
    id="wildcard_iam_policy",
    title="ワイルドカード IAM ポリシー (Action/Resource=*)",
    kind=MisconfigKind.OVER_PERMISSION,
    precondition="割当ロールが iam:* もしくは Resource=* を含む",
    gain="ロール連鎖で任意権限へ拡大し昇格",
    detection_difficulty="medium",
    source="AWS IAM best practices; MITRE ATT&CK T1078.004",
    suggested_tool="assume_role",
))

_register(MisconfigEntry(
    id="registry_pull_secret_exposed",
    title="イメージ pull secret の露出",
    kind=MisconfigKind.CREDENTIAL_MISMGMT,
    precondition="imagePullSecret / dockerconfigjson を侵害 SA が読取れる",
    gain="レジストリ資格情報を得て私有イメージ内の秘密を取得",
    detection_difficulty="medium",
    source="CIS Kubernetes Benchmark 5.x",
    suggested_tool="get_secret",
))

_register(MisconfigEntry(
    id="host_network_pod",
    title="hostNetwork Pod（ノードネットワーク露出）",
    kind=MisconfigKind.INSECURE_DEFAULT,
    precondition="Pod が hostNetwork:true でノードのネットワーク名前空間を共有",
    gain="ノードのメタデータ/隣接サービスへ直接到達",
    detection_difficulty="medium",
    source="CIS Kubernetes Benchmark; NSA/CISA Kubernetes Hardening",
    suggested_tool="http_request",
))

_register(MisconfigEntry(
    id="anonymous_api_access",
    title="匿名/未認証 API アクセス許可",
    kind=MisconfigKind.IMPLICIT_PERMISSION,
    precondition="system:anonymous / unauthenticated に閲覧権限が付与されている",
    gain="未認証でクラスタ状態を偵察し昇格経路を発見",
    detection_difficulty="high",
    source="NSA/CISA Kubernetes Hardening Guidance",
    suggested_tool="recon",
))

_register(MisconfigEntry(
    id="egress_allow_all",
    title="全許可 egress（NetworkPolicy 不備）",
    kind=MisconfigKind.ISOLATION_GAP,
    precondition="namespace に egress 制限が無く外部/隣接へ自由に接続できる",
    gain="窃取データを外部へ持ち出す/隣接サービスへ横移動",
    detection_difficulty="medium",
    source="CIS Kubernetes Benchmark 5.3; MITRE ATT&CK T1048",
    suggested_tool="lateral_move",
))


# --- マルチクラウド IAM 実体化（設計書 4.2 軸2: AWS・Azure RBAC・GCP IAM）------------
_register(MisconfigEntry(
    id="azure_managed_identity_overperm",
    title="Azure マネージドID の過剰 RBAC ロール割当",
    kind=MisconfigKind.OVER_PERMISSION,
    precondition="VM/App のマネージドID に Contributor/Owner が subscription スコープで割当てられている",
    gain="マネージドID トークンで過剰ロールを引き当て、サブスクリプション資源へ昇格",
    detection_difficulty="medium",
    source="Microsoft Entra/Azure RBAC least-privilege guidance; MITRE ATT&CK T1078.004",
    suggested_tool="assume_role",
))

_register(MisconfigEntry(
    id="gcp_sa_impersonation",
    title="GCP サービスアカウントなりすまし (iam.serviceAccounts.getAccessToken)",
    kind=MisconfigKind.OVER_PERMISSION,
    precondition="ワークロード SA が別の特権 SA に roles/iam.serviceAccountTokenCreator を保持",
    gain="getAccessToken で特権 SA になりすましクラウド横断ピボット",
    detection_difficulty="high",
    source="Google Cloud IAM best practices (SA impersonation); MITRE ATT&CK T1548.005",
    suggested_tool="assume_role",
))


def get(misconfig_id: str) -> MisconfigEntry:
    try:
        return CATALOG[misconfig_id]
    except KeyError as exc:  # pragma: no cover - 設定ミス参照ミスの早期検知用
        raise KeyError(
            f"unknown misconfig '{misconfig_id}'. known: {sorted(CATALOG)}"
        ) from exc

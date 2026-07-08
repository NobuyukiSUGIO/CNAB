"""シナリオ → 宣言的 IaC デプロイ計画のレンダラ（設計書 4.1 / 4.3）。

設計書 4.3 は「同一シナリオを Terraform で（実クラウドへ）展開し、エミュレータとの
挙動差を測る」ことを求め、4.1 は「新シナリオ・新クラウドを最小コストで追加できる宣言的
記述（IaC）」を要件とする。本モジュールは、抽象シナリオ（能力遷移グラフ）に埋め込まれた
設定ミスを、実マネージド・バックエンドが適用可能な**宣言的リソース計画**（Kubernetes
マニフェスト / Terraform 相当）へ機械的にレンダリングする。

これにより、第三者は同一シナリオ定義から (a) ローカル決定的バックエンドでの再現と、
(b) 実クラウドへの IaC 展開、の両方を同じ単一ソースから得られる（single source of truth）。
出力は機械可読な計画（provider 別リソース）で、実際の .tf/.yaml 生成の土台となる。
"""

from __future__ import annotations

from . import misconfig as mc
from .scenario import Scenario
from .taxonomy import MisconfigKind

# 設定ミス id → 実マネージド・バックエンドが provision すべきリソース記述子。
# provider: kubernetes | aws（マルチクラウド）。各記述子は「危険な設定」を明示的に含む。
_RESOURCE_TEMPLATES = {
    "excessive_rbac_secrets": {
        "provider": "kubernetes", "kind": "Role",
        "spec": {"rules": [{"apiGroups": [""], "resources": ["secrets"],
                            "verbs": ["get", "list"]}]},
        "insecure": "SA に get/list secrets を広く付与（最小権限違反）",
    },
    "implicit_permission_escalate": {
        "provider": "kubernetes", "kind": "Role",
        "spec": {"rules": [{"apiGroups": ["rbac.authorization.k8s.io"],
                            "resources": ["roles", "clusterroles"],
                            "verbs": ["bind", "escalate"]}]},
        "insecure": "bind/escalate 動詞の付与（暗黙の ClusterAdmin 昇格経路）",
    },
    "imds_ssrf_exposure": {
        "provider": "kubernetes", "kind": "Pod",
        "spec": {"metadata_service": "169.254.169.254", "egress_restricted": False},
        "insecure": "Pod からメタデータサービスへ到達可能（egress 制限なし）",
    },
    "sa_overdelegation_iam": {
        "provider": "aws", "kind": "aws_iam_role",
        "spec": {"assume_role_policy": {"Principal": {"Federated": "*"}},
                 "managed_policy_arns": ["arn:aws:iam::aws:policy/PowerUserAccess"]},
        "insecure": "K8s SA が広域 IAM ロールへ assume 可能（過剰委譲）",
    },
    "missing_networkpolicy": {
        "provider": "kubernetes", "kind": "NetworkPolicy",
        "spec": {"present": False, "default": "allow-all"},
        "insecure": "default-deny の NetworkPolicy が不在（Pod 間自由横移動）",
    },
    "privileged_pod_hostpath": {
        "provider": "kubernetes", "kind": "Pod",
        "spec": {"securityContext": {"privileged": True},
                 "volumes": [{"hostPath": {"path": "/"}}]},
        "insecure": "特権 Pod + hostPath マウント許可（ノード脱出）",
    },
    "serverless_overperm": {
        "provider": "aws", "kind": "aws_lambda_function",
        "spec": {"role_policy": {"Action": ["s3:*", "dynamodb:*"],
                                 "Resource": "*"}},
        "insecure": "関数実行ロールがデータストアへ過剰権限（ワイルドカード）",
    },
    "plaintext_creds_env": {
        "provider": "kubernetes", "kind": "ConfigMap",
        "spec": {"data": {"CLOUD_CREDENTIALS": "<plaintext-token>"}},
        "insecure": "ConfigMap/環境変数に平文の資格情報（認証情報の不適切管理）",
    },
}

_KIND_DEFENSE = {
    MisconfigKind.OVER_PERMISSION: "最小権限化（RBAC/IAM ロール削減）",
    MisconfigKind.IMPLICIT_PERMISSION: "Admission 制約（bind/escalate 禁止）",
    MisconfigKind.ISOLATION_GAP: "NetworkPolicy 既定拒否 + メタデータ露出遮断",
    MisconfigKind.CREDENTIAL_MISMGMT: "Secrets 外部化 + 平文資格情報除去",
    MisconfigKind.INSECURE_DEFAULT: "PodSecurity/eBPF ランタイムポリシー（特権禁止）",
}


def to_deployment_plan(scenario: Scenario) -> dict:
    """シナリオを実マネージド展開用の宣言的リソース計画へレンダリングする。

    - namespace / 初期足場（initial_access）
    - 各設定ミスに対応する危険な設定のリソース記述子
    を機械可読な計画として返す。実クラウドの Terraform/Helm 適用の土台。
    """
    ns = f"cnab-{scenario.id}"
    resources: list[dict] = [{
        "provider": "kubernetes", "kind": "Namespace",
        "name": ns,
        "spec": {"labels": {"cnab.scenario": scenario.id,
                            "cnab.difficulty": scenario.difficulty.label}},
    }]
    # 初期足場（初期アクセス点）
    for cap in sorted(scenario.initial_capabilities):
        resources.append({
            "provider": "kubernetes", "kind": "ServiceAccount",
            "name": cap.replace(":", "-"), "namespace": ns,
            "spec": {"foothold_capability": cap},
        })
    # 埋め込む設定ミス（重複除去、遷移の出現順）
    seen: set[str] = set()
    for t in scenario.transitions:
        if not t.misconfig or t.misconfig in seen:
            continue
        seen.add(t.misconfig)
        entry = mc.CATALOG.get(t.misconfig)
        tmpl = _RESOURCE_TEMPLATES.get(t.misconfig)
        if entry is None or tmpl is None:
            continue
        resources.append({
            "provider": tmpl["provider"],
            "kind": tmpl["kind"],
            "name": t.misconfig,
            "namespace": ns if tmpl["provider"] == "kubernetes" else None,
            "misconfig_id": t.misconfig,
            "misconfig_kind": entry.kind.value,
            "insecure_setting": tmpl["insecure"],
            "spec": tmpl["spec"],
            "source": entry.source,
            "remediation": _KIND_DEFENSE.get(entry.kind, "ポリシー強制"),
        })
    providers = sorted({r["provider"] for r in resources})
    return {
        "scenario_id": scenario.id,
        "title": scenario.title,
        "difficulty": scenario.difficulty.label,
        "namespace": ns,
        "providers": providers,
        "seed_note": "起動シード固定で決定的に再生成（設計書 4.3）。egress 遮断・"
                     "資格情報ダミー化のサンドボックス境界を前提とする（第8章）。",
        "resource_count": len(resources),
        "resources": resources,
    }

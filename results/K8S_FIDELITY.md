# 実K8s fidelity 検証（G3）— s1_rbac_secret_lateral

設計書 4.3・第8章／査読 G3 の一環として、Kubernetes 制御面（RBAC）シナリオ
`s1_rbac_secret_lateral` を**実 kind クラスタ**で再現し、決定的エミュレータとの
一致度を実測した記録。IAM/サーバーレス側（AWS, [`AWS_PRIMARY_VERIFICATION.md`]
(AWS_PRIMARY_VERIFICATION.md)）に続く2ドメイン目の実インフラ検証。

- 実施日: 2026-07-07
- クラスタ: kind（K8s v1.36.1）, 使い捨て・合成データのみ
- ハーネス: [`../k8s/fidelity/measure_k8s_fidelity.py`](../k8s/fidelity/measure_k8s_fidelity.py)
- 生データ: [`k8s_fidelity_s1.json`](k8s_fidelity_s1.json)

## 実攻撃連鎖（攻撃者は foothold SA トークンのみ保持）

1. recon: cnab-priv の Secret 一覧（excessive_rbac_secrets）→ admin-sa-token を露出
2. privesc: admin-sa-token Secret を読取り → admin トークン窃取
3. context: 窃取トークンで `auth can-i` → cluster-admin を確認
4. exfil: cnab-data の合成 billing Secret を読取り → ゴール

## 結果

| 指標 | 値 |
|------|----|
| 遷移一致率（transition-level agreement） | **1.0**（4/4 マイルストンが foothold SA として発火） |
| 観測一致率（observation-level agreement） | **一致**（recon が admin-sa-token を露出） |
| 到達率差（reach gap vs エミュレータ） | **0.0**（両者 1.0） |
| failure-mode 分類 | none（全連鎖が発火） |
| 防御 fidelity | 誤設定 RoleBinding を除去すると **recon で AccessDenied により連鎖が折れる**＝エミュレータの disabled-misconfig 挙動と一致 |

## 所見

1. **エミュレータの K8s 制御面 fidelity を実測で裏取り**：s1 の RBAC secret-lateral
   連鎖が実クラスタで行動・観測・到達率とも一致（gap 0.0）。IAM/サーバーレス（AWS）に
   続き、2ドメイン目を実インフラで検証した。
2. **防御効果も一致**：excessive_rbac_secrets（cross-namespace secret read）を外すと
   実クラスタでも連鎖が recon で遮断され、エミュレータの防御挙動と一致した。

## 方法論メモ（測定バイアスの排除）

初回実行は誤った 1.0 を出した。原因は kind の kubeconfig が**クライアント証明書
（cluster-admin）認証**で、`kubectl --token=<foothold>` を足しても証明書が優先され、
全「攻撃者」呼び出しが admin として実行されていたこと（誤設定を外しても連鎖が折れず、
`chain_breaks_like_emulator=false` として検出された）。**SA トークンのみを credential と
する専用 kubeconfig（クライアント証明書なし）**に修正し、RBAC が実際に施行されることを
**防御 fidelity チェック（誤設定除去で連鎖が折れること）で検証**してから測定した。
すなわち本harnessは、NetworkPolicy 測定と同様「強制が本当に効いているか」を先に確かめ、
admin-in-disguise による偽の一致を排除する設計になっている。

## 限界

- 単一クラスタ・単一 run（RBAC は決定的なので seed 非依存）。
- Admission / NetworkPolicy データ経路 / ノード脱出（s4）は本検証の対象外（今後）。

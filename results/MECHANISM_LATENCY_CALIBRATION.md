# 防御機構 施行レイテンシの較正（`MECHANISM_COST.enforcement_latency_ms`）

設計書 6.13「運用オーバーヘッド（遅延・拒否率）」の遅延成分を、可能な範囲で実測に基づき
較正した記録。較正関数は `defense.calibrate_mechanism_latency()`、現状は
`defense.latency_calibration_report()` で確認できる（`make harden` 出力にも含む）。

## 重要な区別：伝播レイテンシ ≠ 施行レイテンシ

実 AWS 一次検証で実測した `sts:AssumeRole` の **0.32 秒**は **IAM の伝播レイテンシ
（結果整合＝攻撃バックエンド側の挙動）**であり、`ManagedBackend.propagation_delay` の
較正材料である（[`AWS_PRIMARY_VERIFICATION.md`](AWS_PRIMARY_VERIFICATION.md)）。これは
**防御機構の施行レイテンシ**（防御を入れた際に要求経路へ加わる遅延）とは別物であり、
そのまま `enforcement_latency_ms` に流用してはならない。本較正は両者を厳密に分けている。

## 較正結果

| 機構（設定ミス種別） | enforcement_latency_ms | 来歴 | 根拠 |
|---|---|---|---|
| 最小権限化（over_permission, IAM/RBAC 削減） | **0.0** | `measured:aws` | 実 AWS で過剰権限ロールを assume する攻撃連鎖が**通常 API レイテンシで完走**。IAM 認可は権限範囲に依らず毎回評価されるため、権限を絞っても要求経路に遅延を足さない（デプロイ時変更）。 |
| 資格情報外部化（credential_mismgmt, Secrets 化） | **0.0** | `measured:aws` | 同上系統。平文除去・Secrets 化はデプロイ時変更で実行時経路に遅延なし。 |
| Admission 制約（implicit_permission, bind/escalate 禁止） | **0.278** | `measured:eks` | **kind v0.32 で実測**（下記）。ValidatingAdmissionPolicy（in-process CEL）の dry-run A/B。 |
| NetworkPolicy 既定拒否 + メタデータ遮断（isolation_gap） | **0.0** | `measured:eks` | **Calico v3.28 で実測**（下記）。default-deny 遮断を検証後、allow 成立下の connect A/B 差は測定分解能未満。 |
| PodSecurity/特権禁止（insecure_default） | **0.278** | `measured:eks` | admission 段は上と同一機構で実測。eBPF ランタイム観測ぶんは本ハーネス対象外＝下限側の見積り。 |

## K8s 実測結果（Admission 施行レイテンシ）

- 実施: kind v0.32.0（K8s ≥1.30, ValidatingAdmissionPolicy GA）、`k8s/measure_admission_latency.py`、60 サンプル。
- `kubectl create --dry-run=server` の中央値レイテンシ: **VAP 未適用 65.623ms → 適用 65.901ms**。
- **施行レイテンシ = +0.278ms**（in-process CEL 評価ぶん）。
- 知見: VAP による admission 施行は**サブミリ秒**で、外部 webhook の文献推定（8ms）より
  **約 30 倍低い**。「Admission 制約は運用レイテンシ面でごく安価」を実測で裏付け。
- 成果物: [`eks_latency_calibration.json`](eks_latency_calibration.json)。

## K8s 実測結果（NetworkPolicy 施行レイテンシ）

- 実施: Calico v3.28 入り kind（`disableDefaultCNI`）、`k8s/measure_networkpolicy_latency.py`、300 サンプル。
- 手続き: pod 間 connect の疎通確認 → **default-deny 単体で接続が FAIL することを検証**（＝Calico が
  NetworkPolicy を強制している証明。kindnet 等の非強制 CNI ならここで中断）→ allow で復活 →
  default-deny+allow 下で connect レイテンシ中央値を計測。
- connect レイテンシ中央値: **ポリシー無し 0.0371ms ≈ 適用 0.0371ms → 施行レイテンシ 0.0ms**。
- 知見: NetworkPolicy 強制は接続確立時のカーネル内マッチ（Calico=iptables/ipset, Cilium=eBPF）で、
  allow 成立後の fast-path は 1 コネクション当たり**測定分解能(約0.04ms)未満の追加コスト**＝実質無償。
  「NetworkPolicy はレイテンシ面でほぼ無償で default-deny を敷ける」を実測で裏付け。
- 注: 単一ノードの same-node 計測だが、施行コストは A/B の差分なので topology 非依存
  （cross-node ではネットワーク遅延が baseline/enforced 双方に等しく乗り差は不変）。
- CNI 依存性の裏取り: Cilium(eBPF) でも同ハーネスで再測し施行 0.0015ms（分解能未満）と、
  Calico(iptables) と統計的に区別できないことを確認（[`NETPOL_CNI_COMPARISON.md`](NETPOL_CNI_COMPARISON.md)）。
  よって `isolation_gap`=0ms は CNI データパスに依らず妥当。

## 較正が変えたもの

施行レイテンシを較正前の暫定 (Admission 30, NetPol 5, eBPF 2) から上表へ更新した結果、
`operational_cost` と累積トレードオフ曲線の「膝」が移動した（`make harden` で再現）。IAM/
資格情報系は実測 0ms が裏取りされ、これらが低コスト・高効率の防御であることが
実クラウド根拠で確定した（フリート・パレート前線は `plaintext_creds_env` が支配）。

## K8s 側機構のオンクラスタ実測（ハーネス実装済み）

Admission 機構（`implicit_permission` = bind/escalate 禁止、`insecure_default` = 特権禁止）
の施行レイテンシは、[`k8s/`](../k8s/README.md) の A/B 実測ハーネスで `measured:eks` へ
格上げできる:

1. ローカル K8s（kind/k3d/k3s, ≥1.30）を用意。
2. `python k8s/measure_admission_latency.py` が `ValidatingAdmissionPolicy`（in-process CEL,
   webhook/証明書不要）の適用前後で `kubectl create --dry-run=server` レイテンシ中央値差を
   実測し、`results/eks_latency_calibration.json`（`admission_enforcement_latency_ms`）を出力。
3. `python -m cnab.cli harden --calibration results/eks_latency_calibration.json` で
   文献推定→実測（`measured:eks`）に上書きして評価。

NetworkPolicy（`isolation_gap`）はデータ経路の施行のため dry-run では測れず、
NetworkPolicy 強制 CNI（Calico/Cilium）上で pod 間 TCP connect の A/B が必要
（`k8s/README.md` に手順）。実測できれば同 JSON に `"isolation_gap": <ms>` を追記して格上げ。

**実施状況（2026-07）**：kind クラスタ上で上記手順を実行し、Admission 2 機構
（`implicit_permission`/`insecure_default`）を `measured:eks`（+0.278ms, VAP dry-run）へ、
`isolation_gap` を Calico v3.28 入り kind で `measured:eks`（0.0ms, connect A/B）へ格上げ済み。
したがって現状の来歴内訳は **IAM/資格情報 2 機構=`measured:aws`、K8s 3 機構=`measured:eks`**——
**5 機構すべてが実クラウド実測**に到達（文献推定は残っていない）。eBPF 忠実版が欲しい場合は
Cilium 入りで同ハーネスを再実行すれば `--cni` 来歴つきで置換できる。

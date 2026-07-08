# K8s 施行レイテンシ実測（`measured:eks` 格上げ）

設計書 6.13 の防御施行レイテンシのうち、Admission 系機構
（`implicit_permission` = bind/escalate 禁止、`insecure_default` = 特権禁止）を、
ローカル K8s クラスタ上で「防御なし vs あり」の A/B で実測し、文献推定
（`estimate:literature`）を実測（`measured:eks`）へ格上げする。

ローカルクラスタは**課金も外部露出もない**が、コンテナランタイム/クラスタの起動は
システム状態を変える（Docker デーモン or k3s の systemd/iptables）。**CNAB は自動で
クラスタを立てない**——利用者が下記のいずれかで用意し、ハーネスを回す。

## 1. クラスタを用意（いずれか）

Kubernetes **1.30 以上**が必要（ValidatingAdmissionPolicy が GA）。

```bash
# 選択肢A: kind（Docker が要る）
kind create cluster --image kindest/node:v1.31.0

# 選択肢B: k3d（Docker が要る）
k3d cluster create cnab

# 選択肢C: k3s（sudo で host に直接。NetworkPolicy 実測もしたい場合に有利）
curl -sfL https://get.k3s.io | sh -
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml   # 読めるよう権限調整
```

`kubectl version` でサーバ 1.30+ を確認。

## 2. Admission 施行レイテンシを A/B 実測

```bash
cd ~/Documents/CloudComputing/Theme_A/cnab
../venv/bin/python k8s/measure_admission_latency.py --samples 60 --warmup 8 \
  --cluster "kind v1.31"
```

`kubectl create --dry-run=server` で Pod を admission チェーンに通し（作成・スケジュール
はしない＝イメージ pull 不要）、VAP 未適用 vs 適用で dry-run レイテンシの中央値差を測る。
結果は `results/eks_latency_calibration.json` に保存される（`admission_enforcement_latency_ms`）。

## 3. 実測値で MECHANISM_COST を較正して防御評価

```bash
python -m cnab.cli harden --calibration results/eks_latency_calibration.json \
  --config C2 --seeds 0,1,2,3,4,5,6,7
```

`latency_calibration` セクションで該当機構の来歴が `measured:eks` に変わり、実測レイテンシで
運用コスト・累積トレードオフ曲線が再計算される。恒久化したい場合は測定結果を
`results/MECHANISM_LATENCY_CALIBRATION.md` に追記する。

## 4. 後始末

```bash
kind delete cluster           # or: k3d cluster delete cnab
# k3s: /usr/local/bin/k3s-uninstall.sh
```

## NetworkPolicy（isolation_gap）の実測 — 要 CNI

NetworkPolicy はデータ経路の施行なので dry-run では測れず、実 pod 間 TCP connect の A/B が要る。
kind 既定の **kindnet は NetworkPolicy を強制しない**ので、強制する CNI（Calico / Cilium）を
入れた別クラスタで測る。`measure_networkpolicy_latency.py` は測定前に「default-deny 単体で
接続が遮断されるか」を検証し、遮断されなければ中断する（＝強制していない CNI 上で誤って
0ms と出すのを防ぐ）。

> クラスタ設定はリポジトリの YAML を `--config` で渡す（heredoc はペーストで
> インデントが落ち `disableDefaultCNI not found` になりやすいため使わない）。

### 1a. Calico 入り kind（推奨・堅牢）

```bash
kind create cluster --name cnab-np --config k8s/kind-calico.yaml
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.0/manifests/calico.yaml
kubectl -n kube-system wait --for=condition=Ready pod -l k8s-app=calico-node --timeout=180s
kubectl wait --for=condition=Ready node --all --timeout=180s
```

### 1b. 代替：Cilium 入り kind（eBPF 忠実・要 cilium CLI）

「eBPF でカーネル内強制」を忠実に測りたい場合。iptables 系の Calico より低い値が出やすい。

```bash
kind create cluster --name cnab-np --config k8s/kind-cilium.yaml
cilium install --version 1.16.3 && cilium status --wait
```

### 2. NetworkPolicy 施行レイテンシを A/B 実測

```bash
cd ~/Documents/CloudComputing/Theme_A/cnab
../venv/bin/python k8s/measure_networkpolicy_latency.py --samples 300 --cni "calico v3.28"
```

client→server の TCP connect レイテンシ中央値を「ポリシー無し vs default-deny+allow」で測り、
差分を `results/eks_latency_calibration.json` の `enforcement_latency_ms.isolation_gap` に
**マージ**（Admission 実測を壊さない）。

### 3. 反映・撤去

```bash
python -m cnab.cli harden --calibration results/eks_latency_calibration.json \
  --config C2 --seeds 0,1,2,3,4,5,6,7
kind delete cluster --name cnab-np
```

これで 5 機構すべて（IAM/資格情報=`measured:aws`、Admission 2 機構＋NetworkPolicy=`measured:eks`）
が実測値に到達する。使用 CNI（Calico/Cilium）は `--cni` で来歴に記録される。

## CNI 横断比較（Calico iptables vs Cilium eBPF）

同じ NetworkPolicy 施行を **iptables 系（Calico）と eBPF 系（Cilium）**で測り、データパスの
違いが施行レイテンシに出るかを知見化する。実行ごとに `--cni` をキーにして
`results/netpol_cni_comparison.json` へ蓄積され、2 CNI 揃うと比較表が出力される。

```bash
# Calico クラスタを撤去してから Cilium クラスタを作る（設定が排他のため）
kind delete cluster --name cnab-np
kind create cluster --name cnab-np --config k8s/kind-cilium.yaml
cilium install && cilium status --wait          # cilium CLI が kind 向けに自動設定

# --no-calib-merge: 既定の較正記録(Calico)を上書きせず比較ファイルにだけ足す
../venv/bin/python k8s/measure_networkpolicy_latency.py \
  --samples 300 --cni "cilium $(cilium version --client 2>/dev/null | awk '{print $2}')" \
  --no-calib-merge
kind delete cluster --name cnab-np
```

比較結果は `results/NETPOL_CNI_COMPARISON.md` に恒久化する。両系統とも allow 成立後の施行
オーバーヘッドが測定分解能（約 0.04ms）未満であれば、「NetworkPolicy の default-deny は
iptables/eBPF いずれでもレイテンシ面はほぼ無償で、選定はレイテンシ以外の観点で決めてよい」
という結論になる。

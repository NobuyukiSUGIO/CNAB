# NetworkPolicy 施行レイテンシ：Calico(iptables) vs Cilium(eBPF)

同一の `default-deny + 明示 allow` NetworkPolicy を、データパスの異なる 2 系統の CNI で実測し、
施行レイテンシに差が出るかを知見化した。手続きは両者とも `k8s/measure_networkpolicy_latency.py`
（pod 間 TCP connect の A/B、**default-deny 単体で接続が遮断されることを検証**してから計測）、
kind クラスタ、300 サンプル。成果物は [`netpol_cni_comparison.json`](netpol_cni_comparison.json)。

## 結果

| CNI（データパス） | connect 中央値（ポリシー無し） | connect 中央値（default-deny+allow） | 施行レイテンシ Δ |
|---|---|---|---|
| Calico v3.28（iptables/ipset） | 0.0371 ms | 0.0371 ms | **0.0 ms** |
| Cilium（eBPF, cli v0.19.5） | 0.0383 ms | 0.0398 ms | **0.0015 ms** |

## 知見

1. **施行オーバーヘッドは両系統とも実質ゼロ**。allow 成立後の 1 コネクション当たり追加レイテンシは
   Calico=0.0ms、Cilium=0.0015ms（1.5µs）で、いずれも本計測の分解能（約 0.04ms＝40µs）を
   下回る。両者の差（1.5µs）は run 間ジッタより小さく、**統計的に区別できない**。

2. **baseline のデータパス性能もほぼ同等**（Calico 37.1µs vs Cilium 38.3µs、差 1.2µs）。
   single-node の pod 間 connect ではデータパス実装（iptables vs eBPF）の違いがレイテンシに
   表れない。

3. **結論**：NetworkPolicy の default-deny 化は、iptables 系でも eBPF 系でも**レイテンシ面は
   ほぼ無償**。この規模では CNI 選定をレイテンシで決める根拠は無く、運用性・可観測性・
   スケール特性など他の観点で選んでよい。CNAB の `MECHANISM_COST` では `isolation_gap` を
   実測 0ms（`measured:eks`）とする扱いが CNI に依らず妥当と裏取りされた。

## 妥当性の限界（over-claim しないための注記）

- 本計測は **single-node・接続確立レイテンシ**の per-connection コストを測ったもので、
  **ポリシー数に対するスケール**は測っていない。iptables はルール線形探索 O(n)、eBPF は
  ハッシュ参照 O(1) のため、**多数のポリシー／ルールを積むと Cilium(eBPF) が有利**になる
  というのが一般的知見だが、本マイクロベンチはその領域を励起していない。
- スループット・大量同時接続・cross-node のネットワーク遅延も対象外（施行コストは A/B の
  差分なので cross-node でも Δ は不変だが、絶対レイテンシは topology 依存）。
- したがって「レイテンシ差なし」は**低ポリシー数・接続確立粒度での結論**であり、
  「あらゆる負荷で iptables=eBPF」を意味しない。スケール領域の比較は今後の課題。

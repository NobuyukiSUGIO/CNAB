"""Admission 施行レイテンシの A/B 実測（設計書 6.13 較正 / measured:eks）。

防御機構「Admission 制約（特権/bind-escalate 禁止）」が要求経路に加える施行レイテンシを、
「防御なし vs あり」で実測する。`kubectl create --dry-run=server` はオブジェクトを
**admission チェーンに通すが作成・スケジュールはしない**ため、admission 段の遅延を
スケジューリング/kubelet から切り離して測れる（イメージ pull も不要）。

  baseline: ポリシー未適用で許可される Pod を N 回 dry-run 作成 → 中央値レイテンシ
  enforced: ポリシー適用後に同じ Pod を N 回 dry-run 作成（許可されるが VAP CEL は評価）
  施行レイテンシ = median(enforced) - median(baseline)

結果は results/eks_latency_calibration.json に書き出し、
`cnab.cli harden --calibration ...` または `defense.load_latency_calibration()` で
文献推定（estimate:literature）を実測（measured:eks）へ格上げできる。

前提: kubectl が対象クラスタ（kind/k3d/k3s 等, K8s>=1.30）に接続済み。
使用例:
    python k8s/measure_admission_latency.py --samples 60 --warmup 8
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

NS = "cnab-measure"
REPO = Path(__file__).resolve().parent.parent
VAP = Path(__file__).resolve().parent / "vap-deny-privileged.yaml"

# 許可される（非特権）Pod。dry-run=server なので image は pull されない。
BENIGN_POD = """apiVersion: v1
kind: Pod
metadata:
  name: cnab-probe
  namespace: {ns}
spec:
  containers:
    - name: c
      image: registry.k8s.io/pause:3.9
      securityContext:
        privileged: false
"""


def _kubectl(*args: str, stdin: str | None = None, check: bool = True):
    return subprocess.run(["kubectl", *args], input=stdin, text=True,
                          capture_output=True, check=check)


def _dry_run_latency(manifest: str, n: int) -> list[float]:
    lats = []
    for _ in range(n):
        t0 = time.perf_counter()
        cp = _kubectl("create", "-f", "-", "--dry-run=server", "-o", "name",
                      stdin=manifest, check=False)
        dt = (time.perf_counter() - t0) * 1000.0
        if cp.returncode == 0:
            lats.append(dt)
    return lats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=60)
    ap.add_argument("--warmup", type=int, default=8)
    ap.add_argument("--out", default=str(REPO / "results" / "eks_latency_calibration.json"))
    ap.add_argument("--cluster", default="", help="来歴メモ（例: 'kind v1.31 kindnet'）")
    args = ap.parse_args()

    # 接続確認
    try:
        ver = _kubectl("version", "-o", "json")
    except Exception as exc:  # noqa
        sys.exit(f"kubectl がクラスタに接続できません: {exc}")

    _kubectl("create", "namespace", NS, check=False)
    _kubectl("label", "namespace", NS, "cnab.measure=true", "--overwrite")
    pod = BENIGN_POD.format(ns=NS)

    # ウォームアップ（API サーバのキャッシュ・接続確立ぶんを除外）
    _dry_run_latency(pod, args.warmup)

    # A: 防御なし（VAP 未適用であることを保証）
    _kubectl("delete", "-f", str(VAP), "--ignore-not-found", check=False)
    baseline = _dry_run_latency(pod, args.samples)

    # B: 防御あり（VAP 適用）
    _kubectl("apply", "-f", str(VAP))
    time.sleep(2)  # バインディング反映待ち
    enforced = _dry_run_latency(pod, args.samples)

    # 後始末（測定リソースの撤去）
    _kubectl("delete", "-f", str(VAP), "--ignore-not-found", check=False)
    _kubectl("delete", "namespace", NS, "--wait=false", check=False)

    if len(baseline) < 5 or len(enforced) < 5:
        sys.exit(f"有効サンプル不足 (baseline={len(baseline)}, enforced={len(enforced)})")

    med_b = statistics.median(baseline)
    med_e = statistics.median(enforced)
    delta = max(0.0, round(med_e - med_b, 3))

    report = {
        "provenance": "measured:eks",
        "cluster": args.cluster or "unspecified",
        "samples": args.samples,
        "baseline_median_ms": round(med_b, 3),
        "enforced_median_ms": round(med_e, 3),
        "admission_enforcement_latency_ms": delta,
        # Admission 段で施行される 2 機構を実測値へ較正する
        "enforcement_latency_ms": {
            "implicit_permission": delta,
            "insecure_default": delta,
        },
        "note": ("NetworkPolicy(isolation_gap) はデータ経路のため本ハーネスでは測らない"
                 "（Calico/Cilium 上で pod 間 TCP connect の A/B が必要, README 参照）。"),
    }
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n[saved] {args.out}")
    print("次: python -m cnab.cli harden --calibration", args.out)


if __name__ == "__main__":
    main()

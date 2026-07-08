"""NetworkPolicy 施行レイテンシの A/B 実測（設計書 6.13 較正 / isolation_gap）。

NetworkPolicy はデータ経路の施行なので dry-run では測れない。実 pod 間で
「ポリシー無し vs default-deny+allow」の TCP connect レイテンシ差を実測する。
NetworkPolicy を **強制する CNI**（Cilium/Calico 等）が必須——kind 既定の kindnet は
強制しないため、そのままでは差 0 の誤測定になる。本ハーネスは測定前に
「default-deny 単体で接続が遮断されるか」を検証し、遮断されなければ中断する
（＝CNI が強制していないと判定して誤った 0ms を出さない）。

  1. baseline: ポリシー無しで client→server の connect レイテンシ中央値
  2. enforce 検証: default-deny のみ適用 → connect が FAIL することを確認（強制の証明）
  3. allow 適用: 明示 allow を足して connect が復活することを確認
  4. enforced: default-deny+allow 下で同じ許可トラフィックの connect 中央値
  施行レイテンシ = median(enforced) - median(baseline)

結果は results/eks_latency_calibration.json の enforcement_latency_ms.isolation_gap に
マージし、`cnab.cli harden --calibration ...` で反映できる。

前提: kubectl が NetworkPolicy 強制 CNI 入りクラスタ（K8s>=1.25）に接続済み。
使用例:
    python k8s/measure_networkpolicy_latency.py --samples 300 --cni cilium
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

NS = "cnab-netpol"
REPO = Path(__file__).resolve().parent.parent
IMAGE = "python:3.12-alpine"
PORT = 8080

# server: 8080 で accept して即 close する TCP エコー待受（軽量・python のみ）
_SERVER_CMD = ("import socket\n"
               "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
               "s.bind(('0.0.0.0',%d));s.listen(512)\n"
               "while True:\n c,_=s.accept();c.close()\n") % PORT

# client 内で1回だけ connect（遮断確認用, timeout つき）
_PROBE = ("import socket,sys\n"
          "s=socket.socket();s.settimeout(float(sys.argv[3]))\n"
          "try:\n s.connect((sys.argv[1],int(sys.argv[2])));print('OK')\n"
          "except Exception:\n print('FAIL')\n"
          "finally:\n s.close()\n")

# client 内で N 回 connect し中央値 ms（先頭 warmup を捨てて conntrack 立ち上げを除外）
_TIMING = ("import socket,time,statistics,sys\n"
           "h,p,n,w=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])\n"
           "lat=[]\n"
           "for i in range(n+w):\n"
           " s=socket.socket();s.settimeout(5);t=time.perf_counter()\n"
           " try:\n"
           "  s.connect((h,p))\n"
           "  if i>=w: lat.append((time.perf_counter()-t)*1000)\n"
           " except Exception: pass\n"
           " finally: s.close()\n"
           "print(round(statistics.median(lat),4) if len(lat)>=5 else 'ERR')\n")

_POD = """apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {ns}
  labels: {{app: {app}}}
spec:
  containers:
    - name: c
      image: {image}
      command: {cmd}
"""

# default-deny(ingress) + client→server の明示 allow
_NETPOL = """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cnab-default-deny
  namespace: {ns}
spec:
  podSelector: {{}}
  policyTypes: ["Ingress"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cnab-allow-client
  namespace: {ns}
spec:
  podSelector: {{matchLabels: {{app: cnab-np-server}}}}
  policyTypes: ["Ingress"]
  ingress:
    - from:
        - podSelector: {{matchLabels: {{app: cnab-np-client}}}}
      ports:
        - protocol: TCP
          port: {port}
"""

_DENY_ONLY = """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cnab-default-deny
  namespace: {ns}
spec:
  podSelector: {{}}
  policyTypes: ["Ingress"]
"""


def _kubectl(*args, stdin=None, check=True):
    return subprocess.run(["kubectl", *args], input=stdin, text=True,
                          capture_output=True, check=check)


def _apply(manifest: str):
    _kubectl("apply", "-f", "-", stdin=manifest)


def _exec_py(pod: str, script: str, *script_args) -> str:
    cp = _kubectl("exec", "-n", NS, pod, "--",
                  "python3", "-c", script, *[str(a) for a in script_args],
                  check=False)
    return (cp.stdout or "").strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=300)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--cni", default="", help="来歴メモ（例: 'cilium 1.16 eBPF'）")
    ap.add_argument("--out", default=str(REPO / "results" / "eks_latency_calibration.json"))
    ap.add_argument("--compare-out",
                    default=str(REPO / "results" / "netpol_cni_comparison.json"),
                    help="CNI 横断比較を蓄積する JSON（cni をキーに追記）")
    ap.add_argument("--no-calib-merge", action="store_true",
                    help="eks_latency_calibration.json への isolation_gap マージを行わない"
                         "（比較用の別 CNI 実行で既定の記録を上書きしたくない場合）")
    args = ap.parse_args()

    try:
        _kubectl("version", "-o", "json")
    except Exception as exc:  # noqa
        sys.exit(f"kubectl がクラスタに接続できません: {exc}")

    _kubectl("create", "namespace", NS, check=False)
    import json as _j
    _apply(_POD.format(name="server", ns=NS, app="cnab-np-server", image=IMAGE,
                       cmd=_j.dumps(["python3", "-c", _SERVER_CMD])))
    _apply(_POD.format(name="client", ns=NS, app="cnab-np-client", image=IMAGE,
                       cmd=_j.dumps(["sleep", "infinity"])))
    print("[wait] pods Ready ...")
    _kubectl("wait", "-n", NS, "--for=condition=Ready", "pod/server", "pod/client",
             "--timeout=180s")
    sip = _kubectl("get", "-n", NS, "pod/server", "-o",
                   "jsonpath={.status.podIP}").stdout.strip()
    if not sip:
        sys.exit("server pod IP を取得できませんでした")

    def probe(timeout=3.0) -> str:
        return _exec_py("client", _PROBE, sip, PORT, timeout)

    def timing() -> float:
        out = _exec_py("client", _TIMING, sip, PORT, args.samples, args.warmup)
        if out != "ERR":
            try:
                return float(out.splitlines()[-1])
            except ValueError:
                pass
        sys.exit(f"connect 計測に失敗: {out!r}")

    # 疎通確認
    if probe() != "OK":
        _cleanup()
        sys.exit("ポリシー無しでも server に接続できません（pod/CNI 異常）")

    # 1. baseline（ポリシー無し）
    base = timing()

    # 2. 強制検証: default-deny 単体で遮断されるか
    _apply(_DENY_ONLY.format(ns=NS))
    time.sleep(3)
    blocked = probe(timeout=4.0)
    if blocked != "FAIL":
        _cleanup()
        sys.exit("default-deny を適用しても接続が通ります＝この CNI は NetworkPolicy を"
                 "強制していません（kindnet 等）。Cilium/Calico 入りクラスタで再実行してください。")

    # 3. allow を足して復活
    _apply(_NETPOL.format(ns=NS, port=PORT))
    time.sleep(3)
    if probe() != "OK":
        _cleanup()
        sys.exit("allow 適用後も接続が復活しません（ポリシー selector 不一致の可能性）")

    # 4. enforced（default-deny+allow 下）
    enf = timing()
    _cleanup()

    delta = max(0.0, round(enf - base, 4))
    cni = " ".join((args.cni or "unspecified").split())  # 改行・余分な空白を畳む
    result = {
        "cni": cni,
        "samples": args.samples,
        "baseline_median_ms": round(base, 4),
        "enforced_median_ms": round(enf, 4),
        "networkpolicy_enforcement_latency_ms": delta,
    }

    print(json.dumps(result, ensure_ascii=False, indent=2))

    # (a) 較正 JSON に isolation_gap をマージ（Admission 実測を壊さない）。
    #     比較用の別 CNI 実行では --no-calib-merge で既定の記録を守れる。
    if not args.no_calib_merge:
        out = Path(args.out)
        doc = json.loads(out.read_text()) if out.exists() else {}
        doc.setdefault("provenance", "measured:eks")
        doc.setdefault("enforcement_latency_ms", {})
        doc["enforcement_latency_ms"]["isolation_gap"] = delta
        doc["networkpolicy"] = result
        out.write_text(json.dumps(doc, ensure_ascii=False, indent=2))
        print(f"[merged] {out}  (enforcement_latency_ms.isolation_gap = {delta})")
        print("次: python -m cnab.cli harden --calibration", args.out)

    # (b) CNI 横断比較へ蓄積（cni をキーに追記）。Calico と Cilium を同ファイルに貯める。
    comparison = _accumulate_comparison(result, Path(args.compare_out))
    if len(comparison["measurements"]) >= 2:
        print("\n=== CNI 横断比較（NetworkPolicy 施行レイテンシ）===")
        for cni, r in comparison["measurements"].items():
            print(f"  {cni:20s} baseline {r['baseline_median_ms']:>7}ms → "
                  f"enforced {r['enforced_median_ms']:>7}ms  "
                  f"(施行 {r['networkpolicy_enforcement_latency_ms']}ms)")


def _accumulate_comparison(result: dict, path: Path) -> dict:
    doc = json.loads(path.read_text()) if path.exists() else {
        "mechanism": ("NetworkPolicy default-deny 施行レイテンシ"
                      "（pod 間 TCP connect A/B, 強制検証つき）"),
        "measurements": {},
    }
    doc.setdefault("measurements", {})
    doc["measurements"][result["cni"]] = result
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2))
    print(f"[compare] {path}  ({len(doc['measurements'])} CNI)")
    return doc


def _cleanup():
    _kubectl("delete", "namespace", NS, "--wait=false", check=False)


if __name__ == "__main__":
    main()

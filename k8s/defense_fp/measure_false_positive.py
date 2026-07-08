"""G4: 防御の実ワークロード偽陽性(拒否率)実測（設計書 6.13 / operational_cost）。

MECHANISM_COST.base_rejection_rate は「正当操作を弾く基礎率（偽陽性）」の *モデル* 値。
本ハーネスは、実クラスタで正当ワークロードに防御を適用し、誤って拒否される割合を実測して
文献推定を実測来歴（measured:<env>, --cluster/--cni から導出）へ格上げする。

対象（既定＝Admission。plain kind で可）:
  Admission（deny-privileged VAP）: 正当な非特権 Pod を N 個 admission に通し、誤拒否数を数える。
    実施前に「特権 Pod は拒否される」ことを検証（＝ポリシーが本当に効いている証明）。
    -> base_rejection_rate を implicit_permission / insecure_default に較正。

任意（--with-netpol, 要 NetworkPolicy 強制 CNI）:
  NetworkPolicy（default-deny + allow）: allow 対象の正当接続を N 回試し、誤ブロック数を数える。
    実施前に「非許可の接続は落ちる」ことを検証（default-deny 単体で遮断＝CNI が強制する証明）。
    kindnet 等の非強制 CNI では中断する（誤って 0% を出さない）。 -> isolation_gap に較正。

結果は results/defense_fp.json（load_defense_calibration が読める形式）に書き出す。
使用例:
    python k8s/defense_fp/measure_false_positive.py --samples 40 --cluster "kind v1.36"
    python k8s/defense_fp/measure_false_positive.py --with-netpol --cni "cilium 1.16"
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
VAP = REPO / "k8s" / "vap-deny-privileged.yaml"
NS = "cnab-fp"            # admission 測定用（実 Pod 不要, dry-run）
NS_NP = "cnab-fp-netpol"  # NetworkPolicy 測定用（実 Pod 間の TCP connect）
PORT = 8080
NP_IMAGE = "python:3.12-alpine"

_POD = """apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {ns}
spec:
  containers:
    - name: c
      image: registry.k8s.io/pause:3.9
      securityContext:
        privileged: {priv}
"""

# --- NetworkPolicy 測定用（measure_networkpolicy_latency.py と同じ実 Pod 方式）---

# server: 8080 で accept して即 close する軽量 TCP 待受
_NP_SERVER_CMD = ("import socket\n"
                  "s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
                  "s.bind(('0.0.0.0',%d));s.listen(512)\n"
                  "while True:\n c,_=s.accept();c.close()\n") % PORT

# client 内で1回 connect（疎通・遮断確認用）: argv = host port timeout
_NP_PROBE = ("import socket,sys\n"
             "s=socket.socket();s.settimeout(float(sys.argv[3]))\n"
             "try:\n s.connect((sys.argv[1],int(sys.argv[2])));print('OK')\n"
             "except Exception:\n print('FAIL')\n"
             "finally:\n s.close()\n")

# client 内で N 回 connect し、失敗（＝ブロック）回数を返す: argv = host port n timeout
_NP_COUNT_PROBE = ("import socket,sys\n"
                   "h,p,n,to=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),float(sys.argv[4])\n"
                   "fail=0\n"
                   "for _ in range(n):\n"
                   " s=socket.socket();s.settimeout(to)\n"
                   " try: s.connect((h,p))\n"
                   " except Exception: fail+=1\n"
                   " finally: s.close()\n"
                   "print(fail)\n")

_NP_POD = """apiVersion: v1
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

# default-deny(ingress) + client→server の明示 allow（正当経路）
_NP_ALLOW = """apiVersion: networking.k8s.io/v1
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

_NP_DENY_ONLY = """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: cnab-default-deny
  namespace: {ns}
spec:
  podSelector: {{}}
  policyTypes: ["Ingress"]
"""


def _slug(s: str) -> str:
    """先頭トークンを来歴用スラグ化（'kind v1.36.1' -> 'kind', 'unspecified' -> ''）。"""
    tok = (s or "").strip().split()[0] if (s or "").strip() else ""
    if tok.lower() in ("", "unspecified"):
        return ""
    return re.sub(r"[^a-z0-9]+", "-", tok.lower()).strip("-")


def _derive_provenance(cluster: str, cni: str | None) -> str:
    """実測環境から来歴ラベルを導く。

    admission のみ: measured:<cluster>（例 measured:kind / measured:eks）。
    --with-netpol 時は強制 CNI を足す（例 measured:kind-cilium / measured:eks-calico）。
    環境不明なら measured:unspecified（EKS を騙らない）。
    """
    parts = [p for p in (_slug(cluster), _slug(cni) if cni else "") if p]
    return "measured:" + ("-".join(parts) if parts else "unspecified")


def _kubectl(*args, stdin=None, check=False):
    return subprocess.run(["kubectl", *args], input=stdin, text=True,
                          capture_output=True, check=check)


def _apply(manifest: str):
    _kubectl("apply", "-f", "-", stdin=manifest, check=True)


def _exec_py(ns: str, pod: str, script: str, *script_args) -> str:
    cp = _kubectl("exec", "-n", ns, pod, "--",
                  "python3", "-c", script, *[str(a) for a in script_args],
                  check=False)
    return (cp.stdout or "").strip()


def _dry_run_admit(manifest: str) -> bool:
    """dry-run=server で admission を通す。True=許可, False=拒否。"""
    cp = _kubectl("create", "-f", "-", "--dry-run=server", "-o", "name",
                  stdin=manifest, check=False)
    return cp.returncode == 0


def measure_admission_fp(samples: int) -> dict:
    _kubectl("create", "namespace", NS, check=False)
    _kubectl("label", "namespace", NS, "cnab.measure=true", "--overwrite")
    _kubectl("apply", "-f", str(VAP), check=True)
    time.sleep(2)

    legit = _POD.format(name="legit", ns=NS, priv="false")
    priv = _POD.format(name="priv", ns=NS, priv="true")

    # 施行検証: 特権 Pod は拒否されねばならない（効いていなければ測定無効）
    if _dry_run_admit(priv):
        _kubectl("delete", "-f", str(VAP), "--ignore-not-found")
        sys.exit("特権 Pod が admission を通過＝VAP が効いていません。K8s>=1.30 で再実行してください。")

    # 偽陽性: 正当な非特権 Pod を N 個通し、誤って拒否された数を数える
    rejected = sum(0 if _dry_run_admit(legit) else 1 for _ in range(samples))
    _kubectl("delete", "-f", str(VAP), "--ignore-not-found")
    _kubectl("delete", "namespace", NS, "--wait=false")
    rate = round(rejected / samples, 4)
    return {"samples": samples, "false_rejections": rejected,
            "rejection_rate": rate, "true_positive_denies_privileged": True}


def _cleanup_netpol():
    _kubectl("delete", "namespace", NS_NP, "--wait=false", check=False)


def measure_netpol_fp(samples: int, timeout: float = 3.0) -> dict:
    """default-deny+allow 下で許可済みの正当接続の誤ブロック率を実測（isolation_gap）。"""
    import json as _j

    _kubectl("create", "namespace", NS_NP, check=False)
    _kubectl("label", "namespace", NS_NP, "cnab.measure=true", "--overwrite")
    _apply(_NP_POD.format(name="server", ns=NS_NP, app="cnab-np-server",
                          image=NP_IMAGE,
                          cmd=_j.dumps(["python3", "-c", _NP_SERVER_CMD])))
    _apply(_NP_POD.format(name="client", ns=NS_NP, app="cnab-np-client",
                          image=NP_IMAGE, cmd=_j.dumps(["sleep", "infinity"])))
    print("[wait] netpol pods Ready ...")
    _kubectl("wait", "-n", NS_NP, "--for=condition=Ready",
             "pod/server", "pod/client", "--timeout=180s", check=True)
    sip = _kubectl("get", "-n", NS_NP, "pod/server", "-o",
                   "jsonpath={.status.podIP}").stdout.strip()
    if not sip:
        _cleanup_netpol()
        sys.exit("server pod IP を取得できませんでした")

    def probe(to: float = timeout) -> str:
        return _exec_py(NS_NP, "client", _NP_PROBE, sip, PORT, to)

    # 疎通確認: ポリシー無しで正当接続が通ること
    if probe() != "OK":
        _cleanup_netpol()
        sys.exit("ポリシー無しでも server に接続できません（pod/CNI 異常）")

    # 施行検証: default-deny 単体で「非許可の接続は落ちる」こと（＝CNI が強制する証明）
    _apply(_NP_DENY_ONLY.format(ns=NS_NP))
    time.sleep(3)
    if probe(to=4.0) != "FAIL":
        _cleanup_netpol()
        sys.exit("default-deny を適用しても接続が通ります＝この CNI は NetworkPolicy を"
                 "強制していません（kindnet 等）。Cilium/Calico 入りクラスタで再実行してください。")

    # allow を足して正当経路が復活すること
    _apply(_NP_ALLOW.format(ns=NS_NP, port=PORT))
    time.sleep(3)
    if probe() != "OK":
        _cleanup_netpol()
        sys.exit("allow 適用後も接続が復活しません（ポリシー selector 不一致の可能性）")

    # 偽陽性: 許可済みの正当接続を N 回試し、誤ってブロックされた数を数える
    out = _exec_py(NS_NP, "client", _NP_COUNT_PROBE, sip, PORT, samples, timeout)
    _cleanup_netpol()
    try:
        blocked = int(out.splitlines()[-1])
    except (ValueError, IndexError):
        sys.exit(f"偽陽性カウントに失敗: {out!r}")
    rate = round(blocked / samples, 4)
    return {"samples": samples, "false_blocks": blocked,
            "rejection_rate": rate, "true_positive_blocks_unallowed": True}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=40,
                    help="admission に通す正当 Pod 数（既定 40）")
    ap.add_argument("--cluster", default="unspecified")
    ap.add_argument("--with-netpol", action="store_true",
                    help="NetworkPolicy(isolation_gap) の偽陽性も実測（要 強制 CNI）")
    ap.add_argument("--netpol-samples", type=int, default=40,
                    help="allow 済み経路で試行する正当接続数（既定 40）")
    ap.add_argument("--timeout", type=float, default=3.0,
                    help="netpol 接続プローブの connect タイムアウト秒（既定 3.0）")
    ap.add_argument("--cni", default="",
                    help="netpol 実測の来歴メモ（例: 'cilium 1.16 eBPF'）")
    ap.add_argument("--out", default=str(REPO / "results" / "defense_fp.json"))
    args = ap.parse_args()

    try:
        _kubectl("version", "-o", "json", check=True)
    except Exception as exc:  # noqa
        sys.exit(f"kubectl がクラスタに接続できません: {exc}")

    adm = measure_admission_fp(args.samples)

    # admission 段で施行される 2 機構の偽陽性率を実測値へ較正する
    base_rejection_rate = {
        "implicit_permission": adm["rejection_rate"],
        "insecure_default": adm["rejection_rate"],
    }

    netpol = None
    cni_norm = None
    if args.with_netpol:
        netpol = measure_netpol_fp(args.netpol_samples, timeout=args.timeout)
        cni_norm = " ".join((args.cni or "unspecified").split())
        base_rejection_rate["isolation_gap"] = netpol["rejection_rate"]

    # 来歴は実測環境（--cluster / --cni）から導く。EKS 固定にしない。
    provenance = _derive_provenance(args.cluster, cni_norm)
    report = {
        "provenance": provenance,
        "cluster": args.cluster,
        "admission": adm,
        "base_rejection_rate": base_rejection_rate,
    }

    if netpol is not None:
        report["networkpolicy"] = netpol
        report["cni"] = cni_norm
        report["note"] = ("Admission(implicit_permission/insecure_default) と "
                          "NetworkPolicy(isolation_gap) の両偽陽性を実測。")
    else:
        report["note"] = ("isolation_gap(NetworkPolicy) の偽陽性は --with-netpol＋強制CNIで"
                          "別途測定（本 run は Admission のみ）。")

    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n[saved] {args.out}")
    print("次: python -m cnab.cli harden --calibration", args.out)


if __name__ == "__main__":
    main()

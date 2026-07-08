# Real-K8s NetworkPolicy fidelity (G3) — s1_rbac_secret_lateral (network-isolation side)

The **third** real-infrastructure fidelity domain, after real AWS IAM/serverless
([`AWS_PRIMARY_VERIFICATION.md`](AWS_PRIMARY_VERIFICATION.md)) and the real-K8s RBAC
control plane ([`K8S_FIDELITY.md`](K8S_FIDELITY.md)). It validates the
`missing_networkpolicy` / `t_lateral` transition of `s1_rbac_secret_lateral` as an
**end-to-end attack chain through the data path** — not just an enforcement
microbenchmark — on a real **kind + Cilium (eBPF)** cluster.

- Date: 2026-07-08
- Cluster: kind (K8s v1.36.1), CNI Cilium 1.16.3 (kube-proxy replacement, default CNI disabled)
- Harness: [`../k8s/fidelity/measure_netpol_fidelity.py`](../k8s/fidelity/measure_netpol_fidelity.py)
- Fixture: [`../k8s/fidelity/netpol_manifests.yaml`](../k8s/fidelity/netpol_manifests.yaml), remediation [`../k8s/fidelity/netpol_deny.yaml`](../k8s/fidelity/netpol_deny.yaml)
- Raw data: [`k8s_netpol_fidelity_s1.json`](k8s_netpol_fidelity_s1.json)
- Disposable cluster, synthetic data only, read-only HTTP exfil, torn down after the run.

## Real attack chain (run by exec-ing into the attacker foothold pod)

1. **lateral**: TCP+HTTP reach `datastore-svc:8080` across the pod network — succeeds
   because there is no NetworkPolicy (`missing_networkpolicy`).
2. **exfil**: HTTP `GET` returns the synthetic billing body over that same hop → goal.

## Results (two independent runs, identical)

| Metric | Value |
|--------|-------|
| Transition-level agreement | **1.0** (both emulator milestones — lateral, exfil — fire as real network steps) |
| Reachability gap (vs emulator) | **0.0** (emulator 1.0, real 1.0) |
| Failure-mode taxonomy | none (full chain fired) |
| Defense fidelity | Applying a **default-deny ingress NetworkPolicy** breaks the real chain at **lateral** with `Timeout(NetworkPolicy)`, matching the emulator with `missing_networkpolicy` disabled (`goal_with_networkpolicy = false`) |
| Enforcement verified | **true** — the identical HTTP GET is reachable before the policy and unreachable after, so the block is real CNI enforcement, not a fixture artifact |

## Findings

1. **The emulator's network-isolation transition is backed by a real data-path chain.**
   The `t_lateral` hop (attacker pod → datastore pod) and the exfil that depends on it
   fire on a real Cilium cluster exactly as in the emulator (agreement 1.0, gap 0.0),
   closing the gap noted in the paper's Limitations that the data-path scenarios were
   validated only as enforcement microbenchmarks, not end-to-end chains.
2. **The defense also matches end-to-end.** A default-deny NetworkPolicy — the
   `missing_networkpolicy` remediation the defense loop synthesizes — breaks the real
   chain at the lateral hop, the same point and direction as the emulator when the
   misconfig is disabled.

## Methodology note (enforcement-first, no false agreement)

Following the same discipline as the RBAC and latency harnesses, the chain is measured
**only after** confirming the CNI actually enforces: the `enforcement_verified` flag
requires the same GET to succeed pre-policy and fail post-policy. This rules out a
false-positive "match" from a fixture that was never really reachable, and confirms the
default-deny is enforced by Cilium rather than merely declared.

## Limitations

- Single cluster; two runs (the chain is deterministic). Cilium (eBPF) data path; the
  enforcement-latency comparison against Calico (iptables) is in
  [`NETPOL_CNI_COMPARISON.md`](NETPOL_CNI_COMPARISON.md).
- Node-escape chains (s4/s14, `privileged_pod_hostpath`) remain validated only at the
  control-plane/RBAC level, not as end-to-end kernel-boundary escapes (future work).

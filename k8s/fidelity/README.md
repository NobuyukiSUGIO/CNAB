# G3: Real-K8s fidelity for `s1_rbac_secret_lateral`

Reproduces the emulator's RBAC secret-lateral chain on a **real** Kubernetes
cluster and measures how faithfully the deterministic emulator matches reality:
transition-level agreement, observation-level agreement, reachability gap, a
failure-mode taxonomy, and a defense-fidelity check.

Unlike the AWS run (IAM/serverless), this validates the **Kubernetes control-plane
/ RBAC** side of the benchmark, which was previously unvalidated on real
infrastructure. No policy-enforcing CNI is needed (this is RBAC, not
NetworkPolicy), so a plain kind cluster works.

## Safety
Synthetic data only (the "billing" secret is a fixture string, no PII); the exfil
step is a read of that fixture; all resources carry `cnab.fidelity=true`, live on a
**throwaway** kind cluster, and are torn down by the driver. The fixture is
deliberately misconfigured (cross-namespace secret read, a long-lived admin SA
token in a readable Secret, an admin SA bound to `cluster-admin`) purely to
measure fidelity in a controlled sandbox.

## Run

```bash
# 1. Any kind cluster with K8s >= 1.24 (TokenRequest API). A plain cluster is fine:
kind create cluster --name cnab-fid

# 2. Measure (applies fixture, runs the real chain, compares to the emulator,
#    checks defense fidelity, tears down):
cd ~/Documents/CloudComputing/Theme_A/cnab
../venv/bin/python k8s/fidelity/measure_k8s_fidelity.py --cluster "kind $(kind version | awk '{print $2}')"

# 3. Teardown
kind delete cluster --name cnab-fid
```

Result is written to `results/k8s_fidelity_s1.json`.

## What the real chain does (attacker holds only the foothold SA token)
1. **recon**: `kubectl get secrets -n cnab-priv` with the foothold token succeeds
   (the `excessive_rbac_secrets` misconfig) and reveals `admin-sa-token`.
2. **privesc**: read the `admin-sa-token` Secret -> steal the admin SA token.
3. **admin context**: `kubectl auth can-i get secrets -A` with the stolen token
   returns `yes`.
4. **exfil**: read the synthetic `billing-data` Secret in `cnab-data` -> goal.

Each real step is matched to an emulator milestone. The driver then removes the
misconfig RoleBinding and re-runs the chain: it must break at recon/privesc with
`AccessDenied(RBAC)`, mirroring the emulator's behavior when
`excessive_rbac_secrets` is disabled (`test_disabled_misconfig_blocks_chain`).

## Reported metrics
- `transition_level_agreement`: fraction of emulator milestones whose real analog fires.
- `observation_level_agreement`: real recon reveals the expected admin token secret.
- `reach_gap`: `|emulator reachability - real reachability|`.
- `failure_mode_taxonomy`: classified reason for any non-firing step.
- `defense_fidelity`: chain breaks on the real cluster when the misconfig is removed,
  and at which step, matching the emulator.

---

# G3 (network isolation): end-to-end NetworkPolicy chain for `s1` on kind+Cilium

`measure_netpol_fidelity.py` validates the **data-path** side of `s1`
(`missing_networkpolicy` / the `t_lateral` hop) as a full attack chain, not just an
enforcement microbenchmark. This is the third real-infrastructure fidelity domain
(after AWS IAM/serverless and K8s RBAC).

Needs a **policy-enforcing CNI** (Cilium), so use the `kind-cilium.yaml` cluster:

```bash
# 1. kind cluster with Cilium (default CNI disabled):
kind create cluster --name cnab-np --config k8s/kind-cilium.yaml
cilium install --version 1.16.3 && cilium status --wait

# 2. Measure (applies fixture, runs the real 2-step network chain, applies a
#    default-deny NetworkPolicy, confirms the chain breaks + CNI enforces, tears down):
python k8s/fidelity/measure_netpol_fidelity.py --cluster "kind v1.36.1" --cni "cilium 1.16.3"

# 3. Teardown
kind delete cluster --name cnab-np
```

Real chain (from the attacker foothold pod): (1) lateral TCP+HTTP hop to the datastore
service (reachable with no NetworkPolicy) -> (2) HTTP GET the synthetic billing body
(goal). Applying the default-deny NetworkPolicy the defense loop synthesizes breaks the
chain at the lateral hop, matching the emulator with `missing_networkpolicy` disabled.
`enforcement_verified` requires the same GET to succeed before the policy and fail after,
so a never-reachable fixture cannot fake agreement. Result:
`results/k8s_netpol_fidelity_s1.json`; write-up in
[`../../results/K8S_NETPOL_FIDELITY.md`](../../results/K8S_NETPOL_FIDELITY.md).

# Response to the IEEE S&P review (2026-07-14)

This document maps each review point to the concrete change made in the code and/or
paper. Deterministic core untouched throughout (`make repro` reproduces
`sha256:9f06077e…`; 62 regression tests pass, up from 55).

## Formatting — 投稿前必須 (all done)

| # | Reviewer point | Fix |
|---|----------------|-----|
| 1 | Anonymize (names/affiliation/email) | `\newif\ifanonymous` toggle, `\anonymoustrue` by default; author block moved to `\else`. Compiled anonymized PDF verified to contain no `sugio/hokkaido/…` string. |
| 2 | Page-14 table/text overlap | Wide tables (catalog, grounding, per-scenario extraction, deployment sequence) converted to full-width `table*[t]`. |
| 3 | N=14 vs N=16, two/three domains, stale future work | `N{=}16` in the scenario-clustered test; "three domains" in Threats; future work reworded (multi-family LLM is done → multi-vendor frontier remains). |
| 4 | "…the review asks for" | Removed; rephrased as an objective statement. |
| 5 | Greedy curve called "Pareto frontier" | Renamed to "greedy cumulative-deployment curve" everywhere; the term *Pareto frontier* now refers only to the exact enumerated skyline. |
| — | Abstract "third domain beyond the three validated" contradiction | Reworded: future work is multi-seed real-infra + multi-vendor LLMs. |
| — | Artifact URL `/.Everything` | Trailing `%` after `\url{…}` removed so the sentence break renders. |
| — | Missing citations | Added OWASP Serverless Top 10, Unit 42 Zealot, Microsoft Entra/Azure RBAC, Google Cloud IAM, and a CCS'25 implicit-permission entry; cited in the grounding tables. |

## Scientific — 科学的最優先

**1. True Pareto frontier (was greedy).** `defense.true_pareto_frontier()` evaluates all
`2^16 = 65,536` control subsets exactly (tractable: each scenario has ≤2 misconfigs, so
residual ASR of any global set is a mean of per-scenario table lookups; 42 real runs
precompute the table). The exact minimum-cost set to reach ASR 0 is **12 controls at cost
1.43**, vs the greedy curve's **15 controls at 1.81** (a 26% cost excess).
`defense_baselines()` compares efficiency-greedy / cost-ascending / attack-frequency /
random orderings against the optimum (Table: `results/DEFENSE_HARDEN_C2.json`; paper
Tables `tab:frontier`, `tab:baselines`). Tests: `TestTruePareto`.

**2. Held-out eval-only headline.** Added `tab:split`: the two headline effects are
*stronger* on the unseen eval split than dev (tight-budget reach C2 0.988 vs C1 0.813 on
eval; wasted 0.051 vs 0.235). Data: `results/HELDOUT_SPLIT_RESULTS.json`.

**3. Scenario-level CI is now primary.** Results text and `tab:agents` caption state the
scenario-clustered bootstrap is the primary uncertainty; the run-level Wilson interval is
labeled "for comparability only, not n=128 independent samples."

**4. Agent information boundary + pseudocode.** Audited: C0/C1/C2 read only
`known_facts` + `goal_capabilities` (+ own past actions). Added Algorithm 1 pseudocode
and an explicit boundary paragraph, plus `TestAgentInformationBoundary` — a proxy
Observation that raises if a hidden field (`held_capabilities`) is read, and an assertion
that agents hold no scenario/transition/oracle handle.

**5. Graph reconstruction vs coverage split; choke-point rigor.**
`evaluate_reconstruction` (extractor fidelity vs actually-fired edges) is **1.0/1.0 on all
16 scenarios**; `evaluate_coverage` (fired vs all-feasible attack edges) is the
agent-exploration metric (0.25–1.0). This resolves the "s14 precision 0.69 mystery": it
was benign fired edges scored against attack-only truth, not extractor error. Degree-product
renamed `choke_point_centrality`; added graph-theoretic `articulation_points`
(Hopcroft–Tarjan) and `dominator_choke_points`. Data: `results/EXTRACTION_SPLIT.json`;
paper `tab:appextract`. Tests: `test_reconstruction_is_exact_but_coverage_can_be_partial`,
`test_articulation_points_are_graph_theoretic`.

**6. Difficulty formula.** Noted honestly that `[c>4]` and `[b>3]` do not fire in the
current suite (max chain 4, branching 2); retained as declared headroom for deeper
future scenarios; flagged label-vs-empirical-difficulty validation as future work.

**7. Real-LLM claims softened + taxonomy + manifest.** "active params" reported only
*within* families (generation and interface adherence are comparably important);
tool-call failures split into format categories (this rate) vs reasoning/selection
(wasted-action); `results/MODEL_MANIFEST.json` pins repo/quant/runtime/decoding/context
for all 10 models. Scaffold comparison (flat/planning/hierarchical) on real LLMs: see
`results/SCAFFOLD_COMPARISON.md`.

## Defense false positives (concern 7)
"$0/40$" now reported with its Clopper–Pearson one-sided 95% upper bound (`r ≤ 0.072`),
phrased "no rejection observed in a 40-operation microbenchmark," not "friction-free";
larger heterogeneous-workload measurement flagged as future work.

## Deferred (honestly scoped as future work)
- Multi-vendor frontier LLMs (API-gated).
- Legitimate-workload FP measurement at hundreds–thousands of operations.
- Multi-seed AWS + end-to-end admission chains under one harness.
- Provider-specific Azure/GCP observation/authorization semantics (scenarios exist on the
  generic tool API; deeper provider modeling is future work).
- Noisy-backend modes (design sketch in the paper; not implemented).

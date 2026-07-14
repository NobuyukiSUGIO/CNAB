# Same-LLM scaffold comparison (review §concern 4/7)

The reviewer asked whether the architecture effect demonstrated with the deterministic
reference agents (C0/C1/C2) also holds for a *real LLM* under flat / planning /
hierarchical scaffolds. We run the **identical model** behind three scaffolds of
increasing structure:

- `minimal`  — flat: bare tool list, no strategic hints (≈ C0)
- `interface`— planning: structured tool interface, reflection, no phase hints (≈ C1)
- `full`     — hierarchical: full strategic scaffold with phase decomposition (≈ C2)

Protocol: hard L3/L4 subset (s1, s2, s4, s10, s14, s16), budget 20, K=3 seeds, T=0.
Raw: [`SCAFFOLD_COMPARISON.json`](SCAFFOLD_COMPARISON.json). Not part of `make repro`.

## Results

| model | scaffold | reach | pass@k | pass-all@k | tool-err | wasted |
|---|---|---|---|---|---|---|
| qwen3.5-9b | minimal (flat) | 0.375 | 0.17 | 0.17 | 0.033 | 18.7 |
| qwen3.5-9b | interface (planning) | 0.833 | 0.83 | 0.83 | 0.057 | 8.0 |
| qwen3.5-9b | full (hierarchical) | **1.000** | **1.00** | **1.00** | 0.056 | **0.3** |
| qwen3.6-27b | minimal (flat) | 0.667 | 0.50 | 0.50 | 0.581 | 12.3 |

## Finding

For the same real LLM (qwen3.5-9b), reach rises **monotonically** with scaffold
richness—flat 0.375 → planning 0.833 → hierarchical 1.000—and wasted actions collapse
**18.7 → 8.0 → 0.3**. This reproduces, on a real model, exactly the pattern the
deterministic reference agents show (C0 → C1 → C2): architecture governs attack
reachability and efficiency, holding the model fixed. The tool-call error rate stays low
and roughly constant across scaffolds (0.03–0.06), confirming the gain is from *planning
structure*, not from the scaffold accidentally fixing interface adherence.

## Honest scope

This is a single-model complete triple plus one flat data point for a second model
(qwen3.6-27b reach 0.667 at `minimal`); we could not complete the 27B triple because that
model ran ~105 min per block on our single 24 GB GPU. It is an **illustration that the
architecture effect transfers to a real LLM**, not a controlled multi-model study; the
deterministic C0/C1/C2 agents (all 16 scenarios, 8 seeds, scenario-clustered tests)
remain the primary architecture evidence. A same-recipe multi-model scaffold sweep is
future work.

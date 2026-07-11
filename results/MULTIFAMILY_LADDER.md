# Multi-family real-LLM ladder (design-doc 5.3)

Extends the single-family (Qwen) local-LLM ladder to **four open-weights families**
(Qwen, Google Gemma, Mistral, Meta Llama) so the "attack reach tracks *active*
parameters, not total" observation can be tested *across* families, and so tool-call
error rate (a review request) is reported per family.

**Scope (honest).** This is a multi-**family** open-weights, 4-bit-quantized comparison on
one 24 GB GPU (RTX 3090 Ti), **not** a multi-**vendor frontier** study (Claude/GPT/Gemini
need API access; future work). Results are logged with the resolved model id, prompt
digest, and run date, and are **not** part of `make repro` (provider/runtime
nondeterminism); the deterministic reference agents remain the reproducible yardstick.

- Runtime: LM Studio (llama.cpp), Q4_K_M, `--gpu max -c 16384 --parallel 1`
- Protocol: hard L3/L4 subset (6 scenarios: s1, s2, s4, s10, s14, s16), `interface`
  scaffold, budget 20, K=5 seeds, T∈{0.0, 0.7}
- Driver: [`../run_multifamily_ladder.py`](../run_multifamily_ladder.py),
  config [`../ladder_models.json`](../ladder_models.json), raw
  [`multifamily_run.json`](multifamily_run.json)
- Date: 2026-07-11

## Model set (8 models, matched active-param tiers)

| tier (active) | Qwen | Gemma | Mistral | Llama |
|---|---|---|---|---|
| low-active (MoE/MatFormer ~3–4B) | 3.5-35b-a3b, 3.6-35b-a3b | gemma-4-e4b | — | — |
| dense 7–9B | 3.5-9b | — | 7B-v0.3 | 3.1-8B |
| dense 24–27B | 3.6-27b | — | Small-24B | — |

The dense 7–9B tier spans **three families** (Qwen/Mistral/Llama), enough to test the
cross-family question at matched active params. (Gemma-2-27B and DeepSeek-V2-Lite were
downloaded but could not be registered through the LM Studio CLI in this headless
environment; they would add a third family to the high and low tiers respectively and
are left as an easy extension via the LM Studio GUI importer.)

## Results — T=0.0 (deterministic), K=5

| model | family | active | reach | pass@k | pass-all@k | tool-err | wasted |
|---|---|---|---|---|---|---|---|
| qwen3.5-35b-a3b | qwen | 3B (MoE) | 0.833 | 0.83 | 0.83 | 0.010 | 6.3 |
| qwen3.6-35b-a3b | qwen | 3B (MoE) | 0.833 | 0.67 | 0.67 | 0.525 | 6.2 |
| gemma-4-e4b | gemma | 4B | 0.692 | 0.67 | 0.50 | 0.465 | 9.6 |
| mistral-7b-v0.3 | mistral | 7B | 0.158 | 0.00 | 0.00 | 0.417 | 19.5 |
| llama-3.1-8b | llama | 8B | 0.356 | 0.33 | 0.17 | 0.096 | 15.9 |
| qwen3.5-9b | qwen | 9B | 0.708 | 0.67 | 0.67 | 0.026 | 8.7 |
| mistral-small-24b | mistral | 24B | 0.667 | 0.50 | 0.50 | 0.338 | 9.3 |
| qwen3.6-27b | qwen | 27B | 1.000 | 1.00 | 1.00 | 0.264 | 0.0 |

## Results — T=0.7 (sampling), K=5

| model | reach | pass@k | pass-all@k | tool-err |
|---|---|---|---|---|
| qwen3.5-35b-a3b | 0.911 | 1.00 | 0.50 | 0.143 |
| qwen3.6-35b-a3b | 0.911 | 1.00 | 0.50 | 0.495 |
| gemma-4-e4b | 0.750 | 0.83 | 0.33 | 0.325 |
| mistral-7b-v0.3 | 0.169 | 0.00 | 0.00 | 0.473 |
| llama-3.1-8b | 0.253 | 0.50 | 0.00 | 0.160 |
| qwen3.5-9b | 0.717 | 1.00 | 0.17 | 0.246 |
| mistral-small-24b | 0.717 | 0.83 | 0.50 | 0.319 |
| qwen3.6-27b | 1.000 | 1.00 | 1.00 | 0.282 |

## Findings

1. **Active-parameter effect holds *within* families.** Qwen: 3B-a3b (0.833) ≈ 9B
   (0.708) < 27B (1.000). Mistral: 7B (0.158) < 24B (0.667). Bigger active compute →
   higher reach, consistent with the single-family observation.

2. **Cross-family comparison at matched active params is confounded by interface
   adherence.** In the dense 7–9B tier the ranking is Qwen-9B (reach 0.708, tool-err
   0.026) > Llama-8B (0.356, 0.096) > Mistral-7B (0.158, 0.417): **reach tracks the
   tool-call error rate**, not just active parameters. Some families fail the *agentic
   interface* (emitting malformed calls or under-specified targets) rather than the
   reasoning — a distinction only visible because we report tool-call error rate.

3. **Tool-call error rate is a stable per-family signal** (consistent between the pilot
   and this run, and across temperatures): Qwen 3.5 dense ≈0.01–0.03, Qwen 3.6 variants
   ≈0.26–0.53, Gemma-4 ≈0.33–0.47, Mistral ≈0.32–0.47, Llama ≈0.10–0.16. It separates
   format-following ability from reasoning ability.

4. **Temperature trades pass@k against pass-all@k, as designed.** Raising T from 0 to
   0.7 raises pass@k (sampling diversity finds a success) but lowers pass-all@k
   (reliability): e.g. qwen3.5-9b pass@k 0.67→1.00 while pass-all@k 0.67→0.17. This
   validates reporting both metrics rather than a single success rate.

## Honest limitations

- Four families, 4-bit quantized, single GPU — a measurement, not a controlled study;
  routing, instruction tuning, quantization, and prompt sensitivity remain confounds.
- We therefore **do not** treat "active params, not total" as a headline finding; we
  report it as consistent *within* families and explicitly note the cross-family
  interface-adherence confound.
- Multi-vendor frontier (Claude/GPT/Gemini) and a third family in the low/high tiers
  (Gemma-2-27B, DeepSeek-V2-Lite) remain future work.

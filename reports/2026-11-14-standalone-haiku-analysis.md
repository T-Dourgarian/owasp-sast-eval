# Standalone Claude Haiku 5.5 — 400-case evaluation and comparison

**Date:** 14 November 2026. **Run:** [successful GitHub Actions workflow](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43599524765). **Raw data:** [sample manifest, per-case predictions, API token counts and latency](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43599524765/artifacts/14115729004).

## Experimental setup

The experiment used the same deterministic stratified 400-case OWASP Benchmark Java v1.2 sample as the earlier Semgrep and Semgrep–Haiku hybrid evaluation (seed 20261114; 206 vulnerable, 194 non-vulnerable). Benchmark revision: `a452b3aafd232245d0753e54eb243d6651f8ef96`.

Standalone Claude Haiku 5.5 was given each complete individual Java test-case source and **the same fixed list of 11 target CWE identifiers**. It was **not provided Semgrep findings, the benchmark case's expected CWE, or the case's vulnerable/non-vulnerable label**. It independently returned a list of CWE identifiers. A case was scored detected when that list included the expected benchmark CWE. This scoring definition matches the Semgrep and hybrid comparisons. All 400 API requests succeeded.

## Detection performance

| Measure | Semgrep | Semgrep + Haiku | Standalone Haiku |
|---|---:|---:|---:|
| True positives | 166 | 159 | 196 |
| False positives | 80 | 3 | 28 |
| False negatives | 40 | 47 | 10 |
| True negatives | 114 | 191 | 166 |
| Precision | 67.48% | 98.15% | 87.50% |
| Recall | 80.58% | 77.18% | 95.15% |
| F1-score | 73.45% | 86.41% | 91.16% |

Standalone outperforms hybrid on F1 by 4.75 percentage points and recall by 17.96 points. Hybrid has 10.65 points higher precision.

## API cost and latency

| Measure | Semgrep + Haiku | Standalone Haiku |
|---|---:|---:|
| API requests | 324 | 400 |
| Input tokens | 583,598 | 713,759 |
| Output tokens | 97,286 | 108,238 |
| API usage cost | $0.1070028 | $0.1254949 |
| Mean API request latency | 1.948 s | 2.048 s |
| Total experiment execution | 638.65 s | 819.23 s |

Standalone cost $0.0184921 more (17.28%), and took 180.58 seconds longer (28.27% relative to hybrid). Hybrid's timing includes the Semgrep scan; standalone does not invoke Semgrep.

## Findings from matched per-case data

- Standalone recovered **19/19 vulnerable cryptography cases** (CWE-327) in the sample. Semgrep and the hybrid detected **0/19** in that category; the hybrid cannot recover cases that Semgrep does not flag.
- Standalone detected **39/39 vulnerable SQL injection cases** versus **33/39** for hybrid; **35/35 vulnerable XSS cases** versus **30/35** for hybrid.
- Hybrid reduced Semgrep's **80 false-positive case classifications to 3**, while standalone produced 28 false-positive case classifications. The reduction is counted at the case level, not individual alert level.
- Standalone also produced **six false-positive cryptography case classifications**; its higher recall does not imply that all its predicted findings were valid.

## Methodological limitations

1. These are **single-run outcomes on a stratified 400-case sample**, not results for the entire 2,740-case benchmark. Repeat the model runs and report uncertainty before making broad reliability claims.
2. Standalone received an invariant list of 11 CWE identifiers, which constrains its search space; this is independent detection within a **known benchmark category set**, not unconstrained repository-wide vulnerability discovery.
3. Each Claude prompt contains only a Java test-case file, not all dependent helper classes. Ground-truth labels were withheld from model requests; category/CWE knowledge is not a substitute for a full project security assessment.
4. Detection uses **case-level exact-expected-CWE matching**, which may differ from other scanners' native output metrics.
5. API prices are computed from actual input/output token counts at the specified rate; these represent **usage-based costs rather than a payment invoice**. Timings cover sequential API execution and, for the hybrid, the Semgrep scan. They exclude dependency installation and benchmark download.

## Raw evidence

- [Standalone Haiku completed run](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43599524765)
- [Standalone per-case artifact](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43599524765/artifacts/14115729004)
- [Hybrid Haiku completed run](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43597649515)
- [Hybrid per-finding artifact](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43597649515/artifacts/14115028196)

GitHub Actions artifacts are configured for 90-day retention. Save local copies for long-term reproducibility.

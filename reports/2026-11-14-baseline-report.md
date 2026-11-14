# Semgrep baseline and Claude API cost estimate — 14 November 2026

This report records one completed Semgrep baseline scan of OWASP Benchmark Java v1.2. No Claude API requests were made.

## Benchmark and scan configuration

- Benchmark revision: `a452b3aafd232245d0753e54eb243d6651f8ef96`
- Files / test cases: 2740
- Semgrep version: 1.185.0
- Semgrep rule configuration: `p/security-audit` (remote ruleset; rule content not independently pinned)
- Semgrep runtime: 31.89 seconds
- Semgrep scan errors: 0
- Semgrep findings: 2163 across 1769 test cases

## Baseline metrics (test case + expected CWE)

| Metric | Result |
|---|---:|
| True positives | 1094 |
| False positives | 512 |
| False negatives | 321 |
| True negatives | 813 |
| Precision | 68.12% |
| Recall | 77.31% |
| F1 | 72.43% |

Matching rule: a case is predicted vulnerable only when Semgrep emits at least one finding containing that case's expected CWE metadata. This *scoring* criterion does not use the true/false ground-truth label to filter Semgrep findings delivered to Claude. Strict CWE-based scoring may differ from the OWASP project's default scoring conventions; document the rule and keep it consistent across approaches.

## API cost estimates: standard API, USD

One standalone call per test case; hybrid per finding makes 2163 calls. Grouping multiple findings in the same Java source into a single hybrid call makes 1769 calls.

| Model | Standalone | Hybrid per finding | Hybrid grouped by Java file |
|---|---:|---:|---:|
| Haiku | $0.60 | $0.52 | $0.41 |
| Sonnet | $12.02 | $10.35 | $8.24 |
| Opus | $24.03 | $20.69 | $16.48 |
| **All six configurations** | — | **$68.20** | **$61.78** |

Estimate assumptions: 3 Java source bytes per input token, 300 input prompt-overhead tokens per request, 200 additional hybrid prompt tokens, and 100 output tokens per call. These are **approximations** rather than tokenized measurements. Excludes retries, extra source context and rate-limit effects. Rates taken from the Anthropic November 9, 2026 global standard rate card.

A full hybrid restricted to Semgrep findings cannot exceed Semgrep recall of 77.31% under this scoring convention.

## Reproducibility and raw data

- [Completed GitHub Actions run](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43595938279)
- [Download raw Semgrep findings, scan metadata and JSON estimate](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43595938279/artifacts/14114925459)
- Artifact expires February 12, 2027. Archive a copy before expiry.
- Machine-readable estimates are committed in `reports/2026-11-14-baseline-and-estimate.json`.
- No paid Claude calls were executed. Calibrate estimated tokens and latency with a stratified 20–50 request pilot per model before full runs.

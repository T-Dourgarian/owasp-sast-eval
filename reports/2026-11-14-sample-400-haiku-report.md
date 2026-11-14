# OWASP Benchmark v1.2 — Stratified 400-case Semgrep and Haiku hybrid

**Run date:** 14 November 2026. **Status:** complete. **All 324 Semgrep findings validated.**

## Experimental configuration

- 400 Java cases selected by stratification on vulnerability category and vulnerable/non-vulnerable label, seed 20261114 (206 vulnerable; 194 non-vulnerable)
- Fixed benchmark revision: a452b3aafd232245d0753e54eb243d6651f8ef96
- Semgrep 1.185.0; ruleset p/security-audit (remote ruleset; may change)
- Claude Haiku 5.5; one independent API classification per Semgrep finding; prompts include Semgrep finding metadata and full Java test-case source, but no ground-truth label
- Case-level exact CWE matching applied consistently to Semgrep and hybrid outputs

## Detection performance

| Measure | Semgrep only | Semgrep + Haiku |
|---|---:|---:|
| True positives | 166 | 159 |
| False positives | 80 | 3 |
| False negatives | 40 | 47 |
| True negatives | 114 | 191 |
| Precision | 67.48% | 98.15% |
| Recall | 80.58% | 77.18% |
| F1-score | 73.45% | 86.41% |

## Actual API token usage and execution time

- Semgrep findings sent to Claude: 324 of 324
- Claude input tokens: 583,598
- Claude output tokens: 97,286
- Input token cost: $0.0583598
- Output token cost: $0.0486430
- **Completed Haiku run API charge (calculated): $0.1070028**
- Earlier diagnostic request charge: $0.0001854
- **Combined API usage across attempts: $0.1071882**
- Semgrep scan: 7.45 seconds
- Claude API phase (wall clock): 631.20 seconds
- Average API request latency: 1.948 seconds
- Summed API latency: 631.17 seconds
- **Total Semgrep–Haiku pipeline execution: 638.65 seconds (10.64 minutes)**

Costs use the [published Claude Haiku 5.5 rates](https://platform.claude.com/docs/en/about-claude/pricing) of $0.10/million input and $0.50/million output tokens for standard requests under 100k input tokens. They are usage-based calculations, not payment statements; taxes, platform fees or discounted credits are not included.

## Evidence and limitations

- [Completed GitHub Actions run](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43597649515)
- [Download raw Semgrep findings, sample manifest, Haiku per-finding outcomes, token usage and latency](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43597649515/artifacts/14115028196)
- The artifact is retained for 90 days (scheduled expiry February 12, 2027). Archive it before then.
- Detection rates represent the sampled OWASP cases, not the entire benchmark.
- The hybrid can suppress Semgrep false positives but cannot discover vulnerabilities that Semgrep failed to flag.
- Latency is measured sequentially without batching; benchmark download and dependency setup are excluded from pipeline execution time.
- Model responses and pricing can change over time; the reported experiment is a snapshot.

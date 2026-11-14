# OWASP 400-case comparison — 14 November 2026

All four jobs in [GitHub Actions run 43603264112](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43603264112) completed successfully. Their ZIP artifacts were inspected and per-request input/output token totals, request counts, and summary metrics matched the job logs. Each experiment used the same 400-case sample (206 vulnerable, 194 safe), seed 20261114, and benchmark revision `a452b3aafd232245d0753e54eb243d6651f8ef96`.

| Configuration | TP | FP | FN | TN | Precision | Recall | F1 | API calls | Input tokens | Output tokens | API cost (USD) | Mean latency (s) | Pipeline (s) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Semgrep | 166 | 80 | 40 | 114 | 67.48% | 80.58% | 73.45% | 0 | 0 | 0 | 0.000000 | 0.0000 | 5.6352 |
| Standalone Haiku | 196 | 28 | 10 | 166 | 87.50% | 95.15% | 91.16% | 400 | 713759 | 108238 | 0.125495 | 2.0479 | 819.2324 |
| Hybrid Haiku | 159 | 3 | 47 | 191 | 98.15% | 77.18% | 86.41% | 324 | 583598 | 97286 | 0.107003 | 1.9480 | 638.6541 |
| Standalone Sonnet | 201 | 16 | 5 | 178 | 92.63% | 97.57% | 95.04% | 400 | 817759 | 15839 | 1.793908 | 1.6201 | 648.0511 |
| Hybrid Sonnet | 166 | 4 | 40 | 190 | 97.65% | 80.58% | 88.30% | 324 | 645158 | 38742 | 1.677736 | 2.2842 | 745.7591 |
| Standalone Opus | 206 | 9 | 0 | 185 | 95.81% | 100.00% | 97.86% | 400 | 817759 | 6513 | 3.401296 | 1.7170 | 686.8183 |
| Hybrid Opus | 166 | 3 | 40 | 191 | 98.22% | 80.58% | 88.53% | 324 | 645158 | 21352 | 3.007672 | 2.1296 | 695.6490 |

Six successful Claude configurations cost **$10.1131** in estimated API token charges, excluding pilots and failed test calls.

Standalone Opus had the highest F1 (97.86%) and recall (100%), with 206 TP, 9 FP and 0 FN. Hybrid Opus had the highest precision (98.22%) but remained limited to Semgrep's 166 TP and 40 FN. Standalone Haiku delivered 91.16% F1 for $0.1255. Hybrid models greatly reduced Semgrep false positives, but none improved recall beyond Semgrep. No paid calls were rerun for this report.

**Methodological limits:** Metrics use case-level exact benchmark-CWE matching; Sonnet/Opus used constrained JSON while Haiku used ordinary JSON. Runtime excludes dependency installation and benchmark download. The baseline time (5.6352 s) is from the Sonnet/Opus preparation run; the earlier Haiku report's Semgrep scan was 7.4498 s. Costs are calculated from usage and configured rates, not invoices. Parallel configurations have separate elapsed times.

Sources: [Sonnet/Opus run](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43603264112), [Haiku hybrid report](https://github.com/T-Dourgarian/owasp-sast-eval/blob/main/reports/2026-11-14-sample-400-haiku-summary.json), [Haiku standalone report](https://github.com/T-Dourgarian/owasp-sast-eval/blob/main/reports/2026-11-14-standalone-haiku-summary.json).

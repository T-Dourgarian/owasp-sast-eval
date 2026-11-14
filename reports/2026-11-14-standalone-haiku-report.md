# Standalone Claude Haiku 5.5: 400-case OWASP Benchmark experiment

**Date:** 2026-11-14. **Status:** Completed successfully. **Benchmark revision:** `a452b3aafd232245d0753e54eb243d6651f8ef96`. **Sample seed:** `20261114`.

[Completed GitHub Actions run](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43599524765) · [Full artifact (expires 2027-02-12)](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43599524765/artifacts/14115729004)

## Case-level exact CWE results

| Metric | Semgrep | Semgrep + Haiku | Standalone Haiku |
| --- | ---: | ---: | ---: |
| True positives | 166 | 159 | 196 |
| False positives | 80 | 3 | 28 |
| False negatives | 40 | 47 | 10 |
| True negatives | 114 | 191 | 166 |
| Precision | 67.48% | 98.15% | 87.50% |
| Recall | 80.58% | 77.18% | 95.15% |
| F1-score | 73.45% | 86.41% | 91.16% |
| API requests | 0 | 324 | 400 |
| API input tokens | 0 | 583,598 | 713,759 |
| API output tokens | 0 | 97,286 | 108,238 |
| API usage-based cost | $0 | $0.1070028 | $0.1254949 |
| Mean API latency | N/A | 1.9480 s | 2.0479 s |
| Execution time | 7.4498 s | 638.6541 s | 819.2324 s |

**Standalone total tokens:** 821,997. **Standalone total API request latency:** 819.1535 s. **Standalone scan duration:** 13 min 39.2324 s. **Hybrid pipeline duration:** 10 min 38.6541 s. **Standalone additional cost:** $0.0184921 (+17.28%). **Standalone additional time:** 180.5783 s (+28.27%). The hybrid pipeline time includes its Semgrep scan; the standalone duration excludes benchmark download and dependency installation.

Standalone Haiku found 37 more true-positive cases than the hybrid and missed 37 fewer true vulnerabilities, but generated 25 more false-positive cases. Standalone improved F1 by 4.75 percentage points. Hybrid precision was 10.65 percentage points higher.

## Experimental setup and limitations

The same fixed 400-case stratified sample and benchmark revision were used. Standalone Haiku received each Java test-case file, the same constant list of 11 target CWE IDs for every file, and no Semgrep findings or case-specific ground truth. Its output was a list of detected CWE IDs, compared against the expected case CWE. Hybrid Haiku received Semgrep findings and full corresponding Java test-case source, then made one genuine/false decision per finding. The metrics are case-level, not line-level. Both approaches received test-case files rather than the entire application and all dependencies; generalization to real repositories is not established. Standalone's fixed candidate-CWE list makes the task narrower than open-ended vulnerability discovery. Costs are computed from API-reported input/output token counts using $0.10 and $0.50 per million tokens, respectively, not verified billing charges. Both workflows used sequential requests. Results are from a single sample and run, without uncertainty intervals or repeated-run variability.

**Additional standalone diagnostic:** If any returned CWE counts as a finding, instead of requiring the exact expected CWE, the results are TP 198, FP 28, FN 8, TN 166, precision 87.61%, recall 96.12%, F1 91.67%. Exact-CWE results above are the primary comparable metric.

**Interpretation:** The tested hybrid is not yet a cost-efficient improvement over standalone Haiku on F1/recall; it is a higher-precision, lower-cost alternative. Compared with Semgrep alone, the hybrid substantially improves precision and F1, at the expense of recall and API overhead. To achieve the thesis goal of an optimized hybrid, consider selectively sending Semgrep-negative cases for independent LLM analysis or using an LLM triage strategy that does not simply discard all Semgrep-negative cases. These changes require fresh experiments before making performance claims.

Sources: [standalone Actions run](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43599524765), [standalone artifact](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43599524765/artifacts/14115729004), [hybrid summary](https://github.com/T-Dourgarian/owasp-sast-eval/blob/main/reports/2026-11-14-sample-400-haiku-summary.json).

# Batched hybrid model reruns — 400 OWASP cases

Date: 2026-11-14. Successful workflow: https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43613560897

All three hybrid experiments ran **one model tier at a time** (GitHub Actions job dependencies: Haiku → Sonnet → Opus). Up to 8 requests per model were concurrent, beginning at 4 and adaptively increasing. Standalone model scans were **not rerun**.

Pinned OWASP Benchmark revision: `a452b3aafd232245d0753e54eb243d6651f8ef96`. Reproducible 400-case stratified sample: 206 vulnerable, 194 non-vulnerable, seed 20261114. Semgrep OSS 1.185.0, `p/security-audit`, 324 findings, 166 TP / 80 FP / 40 FN / 114 TN.

| Hybrid model | TP | FP | FN | TN | Precision | Recall | F1 | Total scan wall time | Claude API cost |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Haiku 5.5 | 155 | 11 | 51 | 183 | 93.37% | 75.24% | 83.33% | 95.2843 s | $0.0934363 |
| Sonnet 5.5 | 165 | 4 | 41 | 190 | 97.63% | 80.10% | 88.00% | 120.8037 s | $1.6871060 |
| Opus 5.5 | 166 | 2 | 40 | 192 | 98.81% | 80.58% | 88.77% | 122.7340 s | $3.0370920 |

Each hybrid evaluated all **324** findings in **324** successful Claude API calls; **0 HTTP 429 events** and **0 retries** in every configuration.

| Model | Input tokens | Output tokens | Reported thinking tokens |
|---|---:|---:|---:|
| Haiku | 645,158 | 57,841 | 54,601 |
| Sonnet | 645,158 | 39,679 | 36,439 |
| Opus | 645,158 | 22,823 | 19,583 |

Total successful API usage cost for the three reruns: **$4.8176343**. All three used constrained JSON schema responses and identical hybrid prompting. Ground truth was withheld from the model requests.

**Time metric:** Each reported total scan time is Claude API-phase wall-clock elapsed time + measured Semgrep scan time (6.7399 s). This includes model execution, API travel and any throttling. It excludes dependency installation, benchmark cloning, and GitHub Actions job queue/setup. The Semgrep scan was performed once and its duration included for each hybrid configuration to represent standalone execution.

**Caution:** These are individual stochastic model runs; performance may vary between reruns. The metrics are case-level exact benchmark-CWE matching on a fixed 400-case sample, not the entire benchmark.

## Evidence

- [Haiku requests and summary](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43613560897/artifacts/14121162529)
- [Sonnet requests and summary](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43613560897/artifacts/14121063301)
- [Opus requests and summary](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43613560897/artifacts/14121665437)
- [Sample and raw Semgrep results](https://github.com/T-Dourgarian/owasp-sast-eval/actions/runs/43613560897/artifacts/14121267027)

Artifacts are subject to GitHub Actions retention, so retain permanent backups for the thesis.

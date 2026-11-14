"""Standalone Opus 5.5 pilot on 20 reproducibly sampled OWASP Java cases.

Uses the EXACT prompt and CWE scope from scripts/standalone_haiku.py,
without the sample's expected CWE, vulnerable label, or Semgrep findings
in model requests. This pilot does not run the full 400-case evaluation.
"""
import csv
import json
import os
import random
import statistics
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from anthropic import Anthropic
from prepare import REV
from standalone_haiku import SYSTEM, TARGET_CWES, prompt, parse_answer, score

MODEL = "claude-opus-5-5"
INPUT_RATE = 4.0 / 1_000_000
OUTPUT_RATE = 20.0 / 1_000_000
MAX_TOKENS = 4096
BUDGET = float(os.getenv("OPUS_PILOT_MAX_USD", "1.50"))
N_PILOT = 20
SEED = 20261115
ROOT = Path("results/opus_pilot_20")
SOURCE = Path("benchmark/selected/src/main/java/org/owasp/benchmark/testcode")
MANIFEST = Path("results/stratified_sample_400.csv")


def choose_pilot(sample):
    """Proportional category allocation with each category represented.

    Ground truth is only used to balance the sample, never sent to the LLM.
    Within categories, favor balanced labels for categories with >=2 slots.
    """
    by_category = defaultdict(list)
    for item in sample:
        by_category[item["category"]].append(item)
    keys = sorted(by_category)
    if len(keys) > N_PILOT:
        raise RuntimeError("Pilot has fewer slots than vulnerability categories")
    alloc = {name: 1 for name in keys}
    leftover = N_PILOT - len(keys)
    capacity = {name: len(by_category[name]) - 1 for name in keys}
    total = sum(capacity.values())
    fraction = {}
    for name in keys:
        expected = leftover * capacity[name] / total
        extra = min(capacity[name], int(expected))
        alloc[name] += extra
        fraction[name] = expected - extra
    outstanding = N_PILOT - sum(alloc.values())
    for name in sorted(keys, key=lambda k: (-fraction[k], k)):
        if outstanding == 0:
            break
        if alloc[name] < len(by_category[name]):
            alloc[name] += 1
            outstanding -= 1
    if outstanding:
        raise RuntimeError("Failed to allocate 20 pilot cases")
    rng = random.Random(SEED)
    output = []
    for category in keys:
        capacity = alloc[category]
        positives = sorted([c for c in by_category[category] if c["vulnerable"] == "true"], key=lambda c: c["test_id"])
        negatives = sorted([c for c in by_category[category] if c["vulnerable"] == "false"], key=lambda c: c["test_id"])
        # Approximately preserve each category's positive/negative balance.
        fraction_positive = len(positives) / (len(positives) + len(negatives))
        n_pos = min(len(positives), round(capacity * fraction_positive))
        if capacity >= 2 and positives and negatives:
            n_pos = min(capacity - 1, max(1, n_pos))
        n_neg = capacity - n_pos
        if n_neg > len(negatives):
            n_pos += n_neg - len(negatives)
            n_neg = len(negatives)
        output.extend(rng.sample(positives, n_pos))
        output.extend(rng.sample(negatives, n_neg))
    if len(output) != N_PILOT:
        raise RuntimeError("Pilot sample size mismatch")
    return sorted(output, key=lambda item: item["test_id"])


def cost_projection(logged_costs, all_cases):
    n = len(logged_costs)
    mean = statistics.mean(logged_costs)
    std_dev = statistics.stdev(logged_costs) if n > 1 else 0.0
    # Normal-approximate 95% upper confidence bound on the population mean
    # using t critical value ~2.093 for n=20. For safety, not a formal cost cap.
    upper95 = (mean + 2.093 * std_dev / (n ** 0.5)) * len(all_cases)
    estimate = mean * len(all_cases)
    # Worst-of-observed-cases extrapolation is a conservative diagnostic.
    worst = max(logged_costs) * len(all_cases)
    return {
        "estimate_full_400_usd": round(estimate, 5),
        "approx_upper_95pct_usd": round(upper95, 5),
        "worst_observed_case_times_400_usd": round(worst, 5),
        "below_10_usd_at_mean": estimate < 10,
        "below_10_usd_at_upper_95pct": upper95 < 10,
        "note": "Simple empirical extrapolation from 20 category-stratified cases; output token use and input lengths vary. Not a guaranteed maximum.",
    }


def main():
    if not 0 < BUDGET <= 1.50:
        raise RuntimeError("OPUS_PILOT_MAX_USD must be in (0, 1.50]")
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError("Missing GitHub ANTHROPIC_API_KEY secret")
    with MANIFEST.open(newline="", encoding="utf-8") as handle:
        full_sample = list(csv.DictReader(handle))
    if len(full_sample) != 400 or len({c["test_id"] for c in full_sample}) != 400:
        raise RuntimeError("Expected 400 distinct cases from existing experiment")
    pilot = choose_pilot(full_sample)
    ROOT.mkdir(parents=True, exist_ok=True)
    with (ROOT / "pilot_manifest.csv").open("w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(["test_id", "category", "vulnerable", "cwe"])
        for item in pilot:
            writer.writerow([item["test_id"], item["category"], item["vulnerable"], item["cwe"]])
    client = Anthropic(timeout=180, max_retries=1)
    input_tokens = output_tokens = 0
    cost_usd = 0.0
    request_latency_sum = 0.0
    results = []
    costs = []
    error = None
    started = time.perf_counter()
    with (ROOT / "per_case.jsonl").open("w", encoding="utf-8") as log:
        for case in pilot:
            case_id = case["test_id"]
            source = (SOURCE / (case_id + ".java")).read_text(encoding="utf-8")
            text = prompt(source)
            # Worst-case output reserve, plus conservative input-byte bound.
            reserve = (
                (len(text.encode("utf-8")) + len(SYSTEM.encode("utf-8")) + 2048) * INPUT_RATE
                + MAX_TOKENS * OUTPUT_RATE
            )
            if cost_usd + reserve > BUDGET:
                error = f"Pilot budget guard triggered before {case_id}"
                break
            call_start = time.perf_counter()
            try:
                msg = client.messages.create(
                    model=MODEL, max_tokens=MAX_TOKENS, system=SYSTEM,
                    messages=[{"role": "user", "content": text}],
                )
            except Exception as exc:
                error = f"{case_id}: API error {type(exc).__name__}: {exc}"
                break
            latency = time.perf_counter() - call_start
            i = int(msg.usage.input_tokens)
            o = int(msg.usage.output_tokens)
            usd = i * INPUT_RATE + o * OUTPUT_RATE
            input_tokens += i
            output_tokens += o
            cost_usd += usd
            costs.append(usd)
            request_latency_sum += latency
            try:
                detected = parse_answer(msg)
            except Exception as exc:
                detected = None
                error = f"{case_id}: invalid output, stop={msg.stop_reason}: {exc}"
            log.write(json.dumps({
                "test_id": case_id, "detected_cwes": detected,
                "model": msg.model, "stop_reason": msg.stop_reason,
                "input_tokens": i, "output_tokens": o,
                "api_cost_usd": round(usd, 9),
                "request_latency_seconds": round(latency, 6),
            }) + "\n")
            log.flush()
            if detected is not None:
                results.append({
                    "test_id": case_id, "detected_cwes": detected,
                    "vulnerable": case["vulnerable"] == "true",
                    "expected_cwe": int(case["cwe"]),
                })
            if error:
                break
    elapsed = time.perf_counter() - started
    complete = error is None and len(results) == N_PILOT
    summary = {
        "complete": complete, "error": error, "model": MODEL,
        "pilot_cases": N_PILOT, "pilot_seed": SEED,
        "sample_source": "Previously used stratified 400-case sample, seed 20261114",
        "sample_case_count": 400, "benchmark_revision": REV,
        "requests_completed": len(costs), "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "api_cost_usd": round(cost_usd, 9),
        "input_usd_per_million": 4.0, "output_usd_per_million": 20.0,
        "api_request_latency_sum_seconds": round(request_latency_sum, 4),
        "mean_request_latency_seconds": round(request_latency_sum / len(costs), 4) if costs else None,
        "total_pilot_wall_seconds": round(elapsed, 4),
        "exact_cwe_case_metrics": score(results, lambda row: row["expected_cwe"] in row["detected_cwes"]) if complete else None,
        "cost_projection": cost_projection(costs, full_sample) if complete else None,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scoring_rule": "Case predicted vulnerable if Opus independently emits expected CWE, not given in prompt.",
        "max_tokens": MAX_TOKENS,
        "prompt_source": "scripts/standalone_haiku.py: SYSTEM and prompt() unchanged",
        "note": "No full Opus scan is triggered by this script. Price estimates are token-usage based, not invoices.",
    }
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("=== OPUS 20-CASE PILOT RESULTS ===", flush=True)
    print(json.dumps(summary, indent=2), flush=True)
    if not complete:
        raise RuntimeError(error or "Pilot incomplete")


if __name__ == "__main__":
    main()

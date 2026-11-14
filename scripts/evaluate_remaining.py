"""Compare four remaining Claude configurations on the same OWASP 400-case sample.

Standalone: Claude independently returns CWEs from Java source only.
Hybrid: Claude confirms/refutes each Semgrep finding using the identical
prompt from the completed Haiku hybrid experiment.
All model requests use a JSON schema for reliable structured responses.
No test-case ground truth is included in any model request.
"""
import argparse
import csv
import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from anthropic import Anthropic

from prepare import REV
from standalone_haiku import (
    SYSTEM as STANDALONE_SYSTEM,
    TARGET_CWES,
    parse_answer as parse_standalone,
    prompt as standalone_prompt,
    score as standalone_score,
)
from hybrid_haiku import (
    SYSTEM as HYBRID_SYSTEM,
    cwes,
    confusion,
    parse_answer as parse_hybrid,
    prompt as hybrid_prompt,
)

MODEL_INFO = {
    "sonnet": {"id": "claude-sonnet-5-5", "input_rate": 2.0, "output_rate": 10.0},
    "opus": {"id": "claude-opus-5-5", "input_rate": 4.0, "output_rate": 20.0},
}
SUPPORTED = [
    "standalone-sonnet", "standalone-opus",
    "hybrid-sonnet", "hybrid-opus",
]
SAMPLE = Path("results/stratified_sample_400.csv")
SOURCE = Path("benchmark/selected/src/main/java/org/owasp/benchmark/testcode")
SEMGREP = Path("results/sample_400/semgrep.json")
SCAN_METADATA = Path("results/sample_400/scan_metadata.json")
MAX_TOKENS = 4096

STANDALONE_SCHEMA = {
    "type": "object",
    "properties": {
        "cwes": {
            "type": "array",
            "items": {"type": "integer", "enum": TARGET_CWES},
        },
    },
    "required": ["cwes"],
    "additionalProperties": False,
}
HYBRID_SCHEMA = {
    "type": "object",
    "properties": {"genuine": {"type": "boolean"}},
    "required": ["genuine"],
    "additionalProperties": False,
}


def load_sample():
    with SAMPLE.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 400 or len({row["test_id"] for row in rows}) != 400:
        raise ValueError("Expected 400 unique cases from the fixed sample")
    if sum(row["vulnerable"] == "true" for row in rows) != 206:
        raise ValueError("Sample mismatch: expected 206 vulnerable cases")
    return rows


def load_semgrep(rows):
    data = json.loads(SEMGREP.read_text(encoding="utf-8"))
    if data.get("errors"):
        raise RuntimeError("Semgrep output contains errors")
    valid = {row["test_id"] for row in rows}
    by_case = defaultdict(list)
    for finding in data.get("results", []):
        match = re.search(r"(BenchmarkTest\d{5})\.java$", finding.get("path", ""))
        if not match or match.group(1) not in valid:
            raise RuntimeError("Semgrep finding outside fixed sample")
        by_case[match.group(1)].append(finding)
    return by_case


def max_request_reserve(text, system, input_rate, output_rate):
    # Conservative pre-call estimate (UTF-8 bytes as upper bound for
    # ordinary text tokens); not a guaranteed provider-side billing cap.
    max_in = len(text.encode("utf-8")) + len(system.encode("utf-8")) + 2048
    return (max_in * input_rate + MAX_TOKENS * output_rate) / 1_000_000


def call_model(client, model, system, user_text, schema):
    return client.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        system=system,
        messages=[{"role": "user", "content": user_text}],
        output_config={"format": {"type": "json_schema", "schema": schema}},
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--configuration", choices=SUPPORTED, required=True)
    parser.add_argument("--max-usd", type=float, required=True)
    args = parser.parse_args()

    mode, tier = args.configuration.split("-")
    allowed_cap = 8.5 if tier == "opus" else 5.0
    if not 0 < args.max_usd <= allowed_cap:
        parser.error(f"Max budget for {tier} is USD {allowed_cap}")
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError("Missing ANTHROPIC_API_KEY GitHub secret")

    info = MODEL_INFO[tier]
    rows = load_sample()
    contents = {
        row["test_id"]: (SOURCE / (row["test_id"] + ".java")).read_text(encoding="utf-8")
        for row in rows
    }
    findings = load_semgrep(rows) if mode == "hybrid" else {}
    scan = (
        json.loads(SCAN_METADATA.read_text(encoding="utf-8"))
        if mode == "hybrid" else None
    )
    if scan and scan.get("exit_code") != 0:
        raise RuntimeError("Semgrep scan did not complete successfully")

    # Every finding is sent for validation regardless of expected CWE,
    # benchmark truth label, or its correctness.
    tasks = []
    for row in rows:
        test_id = row["test_id"]
        if mode == "standalone":
            tasks.append((test_id, None, None, standalone_prompt(contents[test_id])))
        else:
            for idx, finding in enumerate(findings[test_id]):
                tasks.append((test_id, idx, finding,
                              hybrid_prompt(finding, contents[test_id])))

    out_dir = Path("results") / args.configuration
    out_dir.mkdir(parents=True, exist_ok=True)
    client = Anthropic(timeout=180, max_retries=4)
    system = STANDALONE_SYSTEM if mode == "standalone" else HYBRID_SYSTEM
    schema = STANDALONE_SCHEMA if mode == "standalone" else HYBRID_SCHEMA
    input_rate = info["input_rate"]
    output_rate = info["output_rate"]

    # Retain a complete per-request record with token counts and actual call
    # latency; each API attempt including any parser retry counts toward cost.
    recorded = defaultdict(list)
    n_requests = 0
    invalid_replies = 0
    n_input = n_output = 0
    cost = 0.0
    latency_sum = 0.0
    failure = None
    started = time.perf_counter()
    output_file = out_dir / "requests.jsonl"
    with output_file.open("w", encoding="utf-8") as stream:
        for test_id, idx, finding, user_text in tasks:
            success = False
            for attempt in range(1, 4):
                reserve = max_request_reserve(
                    user_text, system, input_rate, output_rate
                )
                if cost + reserve > args.max_usd:
                    failure = (
                        f"Cost guard triggered at USD {cost:.6f} "
                        f"before {test_id} request"
                    )
                    break
                request_start = time.perf_counter()
                try:
                    response = call_model(
                        client, info["id"], system, user_text, schema
                    )
                except Exception as exc:
                    failure = (
                        f"API request failed at {test_id}: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    break
                latency = time.perf_counter() - request_start
                i = int(response.usage.input_tokens)
                o = int(response.usage.output_tokens)
                usd = (i * input_rate + o * output_rate) / 1_000_000
                cost += usd
                n_input += i
                n_output += o
                latency_sum += latency
                n_requests += 1
                try:
                    value = (parse_standalone(response) if mode == "standalone"
                             else parse_hybrid(response))
                    parse_error = None
                except Exception as exc:
                    value = None
                    invalid_replies += 1
                    parse_error = f"{type(exc).__name__}: {exc}"
                result = {
                    "test_id": test_id, "finding_index": idx,
                    "rule": finding.get("check_id") if finding else None,
                    "finding_cwes": cwes(finding) if finding else None,
                    "attempt": attempt, "valid": value is not None,
                    "detected_cwes": value if mode == "standalone" else None,
                    "genuine": value if mode == "hybrid" else None,
                    "parse_error": parse_error,
                    "model": response.model,
                    "stop_reason": response.stop_reason,
                    "input_tokens": i, "output_tokens": o,
                    "api_cost_usd": round(usd, 9),
                    "latency_seconds": round(latency, 6),
                }
                stream.write(json.dumps(result) + "\n")
                stream.flush()
                if value is not None:
                    recorded[test_id].append((finding, value))
                    success = True
                    break
                if attempt == 3:
                    failure = (
                        f"Three invalid JSON responses at {test_id} "
                        f"finding {idx}: {parse_error}"
                    )
            if failure or not success:
                if not failure:
                    failure = f"Unknown failure at {test_id}"
                break
    elapsed = time.perf_counter() - started
    complete = not failure and sum(map(len, recorded.values())) == len(tasks)

    case_rows = []
    for row in rows:
        test_id = row["test_id"]
        benchmark_cwe = int(row["cwe"])
        truth = row["vulnerable"] == "true"
        if mode == "standalone":
            predictions = recorded.get(test_id, [])
            predicted = bool(
                predictions and benchmark_cwe in predictions[0][1]
            )
        else:
            predicted = any(
                bool(genuine) and benchmark_cwe in cwes(finding)
                for finding, genuine in recorded.get(test_id, [])
            )
        case_rows.append({
            "test_id": test_id, "category": row["category"],
            "expected": truth, "expected_cwe": benchmark_cwe,
            "predicted": predicted,
        })
    if complete:
        with (out_dir / "case_predictions.jsonl").open(
            "w", encoding="utf-8"
        ) as stream:
            for row in case_rows:
                stream.write(json.dumps(row) + "\n")

    calculated_metrics = None
    if complete:
        calculated_metrics = confusion([
            (row["predicted"], row["expected"]) for row in case_rows
        ])
    scan_seconds = scan["scan_seconds"] if scan else 0.0

    summary = {
        "complete": bool(complete),
        "error": failure,
        "configuration": args.configuration,
        "model": info["id"],
        "prompt_source": (
            "standalone_haiku.py SYSTEM and prompt()"
            if mode == "standalone"
            else "hybrid_haiku.py SYSTEM and prompt()"
        ),
        "response_format": "JSON schema constrained",
        "sample_seed": 20261114,
        "sample_size": len(rows),
        "benchmark_revision": REV,
        "semgrep_version": scan.get("semgrep_version") if scan else None,
        "semgrep_ruleset": scan.get("ruleset") if scan else None,
        "semgrep_findings": len(tasks) if mode == "hybrid" else None,
        "expected_classifications": len(tasks),
        "valid_classifications": sum(map(len, recorded.values())),
        "api_requests": n_requests,
        "invalid_api_responses": invalid_replies,
        "tokens_input": n_input,
        "tokens_output": n_output,
        "api_cost_usd": round(cost, 9),
        "input_usd_per_million_tokens": input_rate,
        "output_usd_per_million_tokens": output_rate,
        "cost_guard_usd": args.max_usd,
        "mean_request_latency_seconds": (
            round(latency_sum / n_requests, 4)
            if n_requests else None
        ),
        "sum_request_latency_seconds": round(latency_sum, 4),
        "claude_wall_seconds": round(elapsed, 4),
        "semgrep_scan_seconds": round(scan_seconds, 4),
        "pipeline_seconds": round(scan_seconds + elapsed, 4),
        "case_metrics": calculated_metrics,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "scoring_rule": (
            "Vulnerable iff a model-detected CWE equals the expected "
            "OWASP CWE (standalone), or at least one accepted Semgrep "
            "finding has the expected CWE (hybrid). "
            "Expected CWE and vulnerable labels used only for scoring."
        ),
        "notes": [
            "No case ground truth passed to models; hybrid validates every finding.",
            "Synchronous sequential requests per configuration; four different configurations may run in parallel.",
            "SDK may internally retry on transient errors; actual token usage is from returned responses.",
            "Budget guard is application-side, not a hard provider billing limit.",
            "Timing excludes benchmark download and Python environment setup.",
            "Structured JSON response is a minor experimental difference from earlier Haiku raw JSON runs.",
        ],
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print("=== CLAUDE CONFIGURATION SUMMARY ===", flush=True)
    print(json.dumps(summary, indent=2), flush=True)
    if not complete:
        raise RuntimeError(failure or "Incomplete experiment")


if __name__ == "__main__":
    main()

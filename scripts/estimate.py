"""Summarize Semgrep findings and estimate six Claude configurations without API calls.

Estimates use bytes/3 as an approximate token count for Java code plus prompt
overhead. They are NOT tokenization measurements; use small paid pilot to calibrate.
"""
import collections
import json
import re
from pathlib import Path

from prepare import REV, cases

INPUT_TOKEN_DIVISOR = 3.0
INPUT_OVERHEAD_TOKENS = 300
OUTPUT_TOKENS_PER_CALL = 100
HYBRID_OVERHEAD_TOKENS = 200
PRICES = {
    "haiku": (0.10, 0.50),
    "sonnet": (2.00, 10.00),
    "opus": (4.00, 20.00),
}

def finding_cwes(finding):
    meta = finding.get("extra", {}).get("metadata") or {}
    raw = meta.get("cwe") or []
    values = raw if isinstance(raw, list) else [raw]
    found = set()
    for value in values:
        if isinstance(value, int):
            found.add(value)
        found.update(int(x) for x in re.findall(r"CWE[\s_-]*(\d+)", str(value), flags=re.I))
    return found

def evaluate():
    benchmark = cases("benchmark/BenchmarkJava")
    raw = json.loads(Path("results/semgrep.json").read_text(encoding="utf-8"))
    findings = raw.get("results", [])
    scan = json.loads(Path("results/scan.json").read_text(encoding="utf-8"))
    by_id = collections.defaultdict(list)
    no_cwe = 0
    mapped = 0
    for finding in findings:
        path = finding.get("path", "")
        match = re.search(r"(BenchmarkTest\d{5})\.java$", path)
        if not match:
            continue
        mapped += 1
        code = finding_cwes(finding)
        if not code:
            no_cwe += 1
        by_id[match.group(1)].append(code)
    tp = fp = fn = tn = 0
    any_found = 0
    correct_cwe_found = 0
    input_bytes_total = 0
    hybrid_bytes_total = 0
    hybrid_grouped_bytes_total = 0
    matched_findings = 0
    by_category = collections.Counter()
    for case in benchmark:
        length = case["source"].stat().st_size
        input_bytes_total += length
        observed = by_id[case["id"]]
        if observed:
            any_found += 1
            hybrid_bytes_total += length * len(observed)
            hybrid_grouped_bytes_total += length
        matching = [c for c in observed if case["cwe"] in c]
        predicted = bool(matching)
        if predicted:
            correct_cwe_found += 1
            matched_findings += len(matching)
            by_category[case["category"]] += 1
        vulnerable = case["vulnerable"]
        if predicted and vulnerable:
            tp += 1
        elif predicted:
            fp += 1
        elif vulnerable:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    count = len(benchmark)
    baseline = {
        "cases": count, "vulnerable": tp + fn, "non_vulnerable": fp + tn,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1,
        "raw_findings": len(findings),
        "benchmark_findings": mapped,
        "findings_without_cwe_metadata": no_cwe,
        "cases_with_any_findings": any_found,
        "cases_with_correct_cwe_findings": correct_cwe_found,
        "findings_matching_case_cwe": matched_findings,
        "cases_with_cwe_match_by_category": dict(sorted(by_category.items())),
        "semgrep_scan_seconds": scan["scan_seconds"],
        "semgrep_version": scan["semgrep_version"],
        "semgrep_ruleset": scan["ruleset"],
        "benchmark_revision": REV,
        "semgrep_errors": len(raw.get("errors", [])),
    }
    # Standalone: one model request per test case.
    standalone_in = input_bytes_total / INPUT_TOKEN_DIVISOR + count * INPUT_OVERHEAD_TOKENS
    standalone_out = count * OUTPUT_TOKENS_PER_CALL
    # Hybrid primary: one request for EACH Semgrep finding; ground-truth
    # information is not used to select which findings reach the model.
    hybrid_in = hybrid_bytes_total / INPUT_TOKEN_DIVISOR + mapped * (INPUT_OVERHEAD_TOKENS + HYBRID_OVERHEAD_TOKENS)
    hybrid_out = mapped * OUTPUT_TOKENS_PER_CALL
    # Alternative: one request per Java file with one or more findings.
    grouped_in = hybrid_grouped_bytes_total / INPUT_TOKEN_DIVISOR + any_found * (INPUT_OVERHEAD_TOKENS + HYBRID_OVERHEAD_TOKENS)
    grouped_out = any_found * OUTPUT_TOKENS_PER_CALL
    estimates = {}
    for name, (inp, out) in PRICES.items():
        for mode, n, in_tok, out_tok in (
            ("standalone", count, standalone_in, standalone_out),
            ("hybrid", mapped, hybrid_in, hybrid_out),
        ):
            estimates[f"{mode}-{name}"] = {
                "estimated_requests": n,
                "estimated_input_tokens": round(in_tok),
                "assumed_output_tokens": round(out_tok),
                "estimated_api_cost_usd": round((in_tok * inp + out_tok * out) / 1_000_000, 3),
            }
    grouped_alternative = {}
    for name, (inp, out) in PRICES.items():
        grouped_alternative[f"hybrid-{name}"] = {
            "estimated_requests": any_found,
            "estimated_input_tokens": round(grouped_in),
            "assumed_output_tokens": round(grouped_out),
            "estimated_api_cost_usd": round((grouped_in * inp + grouped_out * out) / 1_000_000, 3),
        }
    result = {
        "baseline": baseline,
        "cost_estimation_assumptions": {
            "byte_divisor_for_approximate_input_tokens": INPUT_TOKEN_DIVISOR,
            "input_prompt_overhead_tokens_per_request": INPUT_OVERHEAD_TOKENS,
            "output_tokens_per_request": OUTPUT_TOKENS_PER_CALL,
            "additional_hybrid_prompt_tokens_per_request": HYBRID_OVERHEAD_TOKENS,
            "standalone_source_bytes_total": input_bytes_total,
            "hybrid_source_bytes_total_with_repeated_code_per_finding": hybrid_bytes_total,
            "hybrid_grouped_source_bytes_total": hybrid_grouped_bytes_total,
            "notes": "Estimates are NOT model token counts. Models may tokenize Java differently; evaluate 20-50 paid requests to calibrate. Hybrid estimate sends ALL Semgrep findings, without using ground truth to filter. Primary hybrid estimate is one API request per finding; grouped alternative combines findings within a source file. Anthropic standard API USD rates effective 2026-11-09.",
        },
        "estimated_configurations": estimates,
        "hybrid_grouped_by_case_alternative": grouped_alternative,
        "estimated_all_models_total_with_grouped_hybrid_usd": round(
            sum(estimates[f"standalone-{n}"]["estimated_api_cost_usd"] for n in PRICES)
            + sum(d["estimated_api_cost_usd"] for d in grouped_alternative.values()), 2),
        "estimated_six_configuration_total_usd": round(sum(v["estimated_api_cost_usd"] for v in estimates.values()), 2),
    }
    if result["baseline"]["semgrep_errors"]:
        raise RuntimeError(f"Semgrep reported {result['baseline']['semgrep_errors']} errors; results need inspection")
    output = Path("results")
    (output / "baseline_and_cost_estimate.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("=== BASELINE AND CLAUDE COST ESTIMATE ===")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    evaluate()

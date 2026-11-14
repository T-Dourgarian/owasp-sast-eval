"""Reproducible 400-case stratified sample of OWASP Benchmark v1.2."""
import csv
import random
import shutil
from collections import defaultdict
from pathlib import Path
from prepare import cases

SEED = 20261114
N = 400
DEST = Path("benchmark/selected/src/main/java/org/owasp/benchmark/testcode")
MANIFEST = Path("results/stratified_sample_400.csv")

def choose(data):
    strata = defaultdict(list)
    for item in data:
        strata[(item["category"], item["vulnerable"])].append(item)
    keys = sorted(strata)
    alloc = {key: 1 for key in keys}
    remains = N - len(keys)
    capacity = {key: len(strata[key]) - 1 for key in keys}
    total = sum(capacity.values())
    fractional = {}
    for key in keys:
        ideal = remains * capacity[key] / total
        extra = min(capacity[key], int(ideal))
        alloc[key] += extra
        fractional[key] = ideal - extra
    left = N - sum(alloc.values())
    for key in sorted(keys, key=lambda k: (-fractional[k], k)):
        if not left:
            break
        if alloc[key] < len(strata[key]):
            alloc[key] += 1
            left -= 1
    if left:
        raise RuntimeError("Sample allocation failed")
    rng = random.Random(SEED)
    chosen = []
    for key in keys:
        chosen += rng.sample(sorted(strata[key], key=lambda r: r["id"]), alloc[key])
    return sorted(chosen, key=lambda r: r["id"])

def main():
    sample = choose(cases("benchmark/BenchmarkJava"))
    if len(sample) != N:
        raise RuntimeError("Incorrect sample size")
    DEST.mkdir(parents=True, exist_ok=True)
    for row in sample:
        shutil.copy2(row["source"], DEST / row["source"].name)
    MANIFEST.parent.mkdir(exist_ok=True, parents=True)
    with MANIFEST.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(("test_id", "category", "vulnerable", "cwe"))
        writer.writerows((r["id"], r["category"], str(r["vulnerable"]).lower(), r["cwe"]) for r in sample)
    print("Selected", len(sample), "cases, vulnerable", sum(r["vulnerable"] for r in sample), "seed", SEED)

if __name__ == "__main__":
    main()

"""Run exactly one hybrid model with up to eight parallel API requests.

The three model tiers execute in *separate, sequential GitHub Actions jobs*,
not concurrently. The standalone experiments are not repeated.
"""
import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from anthropic import AsyncAnthropic
from parallel_rerun import MODELS, Experiment, Throttle, load, run_experiment
from prepare import REV


async def run(tier):
    if not os.getenv("ANTHROPIC_API_KEY"):
        raise RuntimeError("Missing ANTHROPIC_API_KEY GitHub secret")
    cases, sources, findings, scan, baseline = load()
    experiment = Experiment("hybrid", tier, cases, sources, findings)
    limiter = Throttle()
    async with AsyncAnthropic(timeout=120, max_retries=0) as client:
        summary = await run_experiment(
            experiment, client, limiter, cases, scan["scan_seconds"]
        )
    summary["execution"] = {
        "type": "single-hybrid-tier-only",
        "max_concurrent_requests": 8,
        "rate_limit_policy": "starts at 4, increases to 8, backs off on HTTP 429",
        "standalone_models_rerun": False,
        "semgrep_baseline": baseline,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    path = Path("results/parallel_rerun_400") / ("hybrid-" + tier)
    (path / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print("=== COMPLETED BATCHED HYBRID EXPERIMENT ===", flush=True)
    print(json.dumps(summary, indent=2), flush=True)
    if not summary["complete"]:
        raise RuntimeError(
            "Batched hybrid " + tier + " incomplete: " +
            str(summary["error"])
        )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--model", choices=sorted(MODELS), required=True)
    args = p.parse_args()
    asyncio.run(run(args.model))

"""Execute Semgrep and retain scan data and duration."""
import json
import subprocess
import time
from pathlib import Path

source = "benchmark/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode"
output = Path("results")
output.mkdir(exist_ok=True)
version = subprocess.check_output(["semgrep", "--version"], text=True).strip()
command = ["semgrep", "scan", "--config", "p/security-audit", "--no-git-ignore", "--metrics", "off",
           "--disable-version-check", "--json", "--output", "results/semgrep.json", source]
started = time.perf_counter()
result = subprocess.run(command, check=False)
elapsed = time.perf_counter() - started
(output / "scan.json").write_text(json.dumps({
    "semgrep_version": version, "ruleset": "p/security-audit",
    "scan_seconds": elapsed, "exit_code": result.returncode,
    "command": command
}, indent=2))
if result.returncode:
    raise SystemExit(result.returncode)
print("Semgrep scan time:", round(elapsed, 2), "seconds")

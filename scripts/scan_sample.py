"""Run Semgrep over exactly the selected 400 cases."""
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

SOURCE = Path("benchmark/selected/src/main/java/org/owasp/benchmark/testcode")
OUT = Path("results/sample_400")

def main():
    if len(list(SOURCE.glob("BenchmarkTest*.java"))) != 400:
        raise RuntimeError("Expected exactly 400 Java test case files")
    OUT.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output(["semgrep", "--version"], text=True).strip()
    command = ["semgrep", "scan", "--config", "p/security-audit",
               "--no-git-ignore", "--metrics", "off", "--disable-version-check",
               "--json", "--output", str(OUT / "semgrep.json"), str(SOURCE)]
    start = time.perf_counter()
    result = subprocess.run(command, check=False)
    duration = time.perf_counter() - start
    meta = {
        "semgrep_version": version,
        "ruleset": "p/security-audit",
        "scan_seconds": duration,
        "exit_code": result.returncode,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "command": command,
    }
    (OUT / "scan_metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
    if result.returncode:
        raise RuntimeError("Semgrep scan failed")
    data = json.loads((OUT / "semgrep.json").read_text(encoding="utf-8"))
    if data.get("errors"):
        raise RuntimeError("Semgrep returned scan errors")
    print("Semgrep scanned 400 files, found", len(data.get("results", [])), "findings in", round(duration, 2), "seconds")

if __name__ == "__main__":
    main()

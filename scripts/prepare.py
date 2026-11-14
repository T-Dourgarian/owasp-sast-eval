"""Download and verify the fixed OWASP Benchmark Java v1.2 source."""
import csv
import subprocess
from pathlib import Path

URL = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
REV = "a452b3aafd232245d0753e54eb243d6651f8ef96"

def cases(root):
    root = Path(root)
    source = root / "src/main/java/org/owasp/benchmark/testcode"
    data = []
    with (root / "expectedresults-1.2.csv").open(newline="", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            test_id, category, is_vulnerable, cwe = row
            path = source / (test_id + ".java")
            if not path.is_file():
                raise FileNotFoundError(path)
            data.append({"id": test_id, "category": category, "vulnerable": is_vulnerable == "true", "cwe": int(cwe), "source": path})
    if len(data) != 2740 or sum(row["vulnerable"] for row in data) != 1415:
        raise RuntimeError("Unexpected OWASP Benchmark 1.2 contents")
    return data

def prepare(root=Path("benchmark/BenchmarkJava")):
    if not (root / ".git").is_dir():
        root.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", URL, str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "fetch", "--depth=1", "origin", REV], check=True)
    subprocess.run(["git", "-C", str(root), "checkout", "--detach", REV], check=True)
    actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if actual != REV:
        raise RuntimeError("Incorrect benchmark revision")
    print("Validated", len(cases(root)), "benchmark cases at", REV)

if __name__ == "__main__":
    prepare()

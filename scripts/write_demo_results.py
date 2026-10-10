#!/usr/bin/env python3
import json, os, time
from pathlib import Path

text = Path("/tmp/demo.out").read_text(errors="replace")
decision = "BLOCK" if "BLOCK" in text else "UNKNOWN"
payload = {
    "repo": "blastguard",
    "source_run": "https://github.com/%s/actions/runs/%s"
    % (os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_RUN_ID", "")),
    "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "metrics": {"demo_cve": "CVE-2026-1234", "demo_decision": decision},
}
Path("docs/results.json").write_text(json.dumps(payload, indent=2) + "\n")
print(json.dumps(payload, indent=2))

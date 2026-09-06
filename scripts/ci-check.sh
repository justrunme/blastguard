#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0

echo "== required files =="
for f in \
  README.md LICENSE Makefile \
  config/decision-policy.json config/decision-policy.yaml \
  fixtures/demo-graph.json \
  docs/assets/blastguard-lifecycle.svg \
  api/crds/blastguard.yaml \
  cmd/blastguard/main.go
do
  [[ -f "$f" ]] || { echo "missing $f" >&2; fail=1; }
done

echo "== concept markers =="
grep -q 'BlastGuard' README.md || fail=1
grep -q 'Discover → Trace → Decide → Enforce → Verify' README.md || fail=1
grep -q "Don't count vulnerabilities" README.md || fail=1
grep -q 'REMEDIATION PROVED' README.md || fail=1
! grep -qiE 'confidence.*[0-9]+ / 100|Risk Score' README.md || { echo "percentage scoring language found" >&2; fail=1; }

echo "== build + demo =="
go build -o bin/blastguard ./cmd/blastguard
out="$(./bin/blastguard demo CVE-2026-1234)"
echo "$out"
echo "$out" | grep -q 'BLOCK' || { echo "expected BLOCK for exposed critical path" >&2; fail=1; }
echo "$out" | grep -q 'CVE-2026-1234' || fail=1

echo "== prove =="
prove="$(./bin/blastguard prove)"
echo "$prove"
echo "$prove" | grep -q 'REMEDIATION PROVED' || fail=1

echo "== rehearse image =="
./bin/blastguard rehearse image ghcr.io/justrunme/payment-api:v42 >/tmp/bg-rehearse.out
cat /tmp/bg-rehearse.out

echo "== go test =="
go test ./...

if [[ "$fail" -ne 0 ]]; then
  echo "ci failed" >&2
  exit 1
fi
echo "ci checks passed"

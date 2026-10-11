#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0

echo "== go vet =="
go vet ./... || fail=1

echo "== go test =="
go test -race -cover ./... || fail=1

echo "== build + demo =="
go build -o bin/blastguard ./cmd/blastguard
set +e
out="$(./bin/blastguard demo CVE-2026-1234)"
demo_code=$?
set -e
echo "$out"
echo "$out" | grep -q 'BLOCK' || { echo "expected BLOCK for exposed critical path" >&2; fail=1; }
echo "$out" | grep -q 'CVE-2026-1234' || fail=1
test "$demo_code" -eq 2 || { echo "expected exit 2 for BLOCK, got $demo_code" >&2; fail=1; }

echo "== prove =="
prove="$(./bin/blastguard prove)"
echo "$prove"
echo "$prove" | grep -q 'REMEDIATION PROVED' || fail=1

echo "== rehearse image =="
set +e
./bin/blastguard rehearse image ghcr.io/justrunme/payment-api:v42 >/tmp/bg-rehearse.out
set -e
cat /tmp/bg-rehearse.out

echo "== ingest test =="
./bin/blastguard ingest \
  --sbom-cyclonedx testdata/alpine-3.20-cdx.json \
  --vulns-grype testdata/alpine-3.20-grype.json \
  > /tmp/test-ingest.json
test -s /tmp/test-ingest.json || { echo "ingest output empty" >&2; fail=1; }
cat /tmp/test-ingest.json | jq -e '.cves | length > 0' >/dev/null || { echo "no CVEs ingested" >&2; fail=1; }
cat /tmp/test-ingest.json | jq -e '.matches | length > 0' >/dev/null || { echo "no scanner matches ingested" >&2; fail=1; }

if [[ "$fail" -ne 0 ]]; then
  echo "ci failed" >&2
  exit 1
fi
echo "ci checks passed"

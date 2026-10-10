# Results

Measured from CI run [`38066443627`](https://github.com/justrunme/blastguard/actions/runs/38066443627) (branch `main`, jobs **ci** + **e2e-kind**, 2026-10-10).

## Fixture demo (`blastguard demo CVE-2026-1234`)

| Check | Result |
| --- | --- |
| Policy decision | **BLOCK** |
| Affected artifacts | 3 |
| Running workloads | 2 |
| Internet exposed | 1 |
| Remediation prove | **REMEDIATION PROVED** (after: ALLOW, blast radius 0) |

## Kind e2e (same CVE on exposed vs internal)

CVE under test: `CVE-2026-93990` (HIGH/CRITICAL from `nginx:alpine` Grype scan in that run).

| Workload | Internet exposed | Decision |
| --- | --- | --- |
| `payment-api` | true | **BLOCK** |
| `internal-worker` | false | **WARN** |

Log line from the run: `same CVE CVE-2026-93990 → BLOCK on payment-api, WARN on internal-worker`.

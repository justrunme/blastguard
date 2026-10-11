# Evidence

Maps blast-radius decision claims to CI proof. Status vocabulary: **Tested in CI** /
**Reference implementation** / **Simulated** / **Not yet**.

Numbers/decisions below come from [docs/results.md](results.md) / [docs/results.json](results.json)
and the cited runs only.

## Claim table

| Claim | Status | Scenario + environment | Real limits | Proof link | Negative tests |
| --- | --- | --- | --- | --- | --- |
| Fixture demo: CVE → BLOCK + remediation prove → ALLOW | Tested in CI | Job **ci**; `blastguard demo CVE-2026-1234` style fixture graph | Fixture/demo graph (`fixtures/demo-graph.json`) — **simulated** inventory, not a live org SBOM lake | Results run [38066443627](https://github.com/justrunme/blastguard/actions/runs/38066443627) · SHA `b18e5fbb22465edd37eaaef2ddd9a8a67304b36b`; latest green main CI [38088776419](https://github.com/justrunme/blastguard/actions/runs/38088776419) · SHA `9e754d9cfc2c8aab4795d17c7c348df2d52ea7eb` | Remediation prove expects after-state ALLOW / blast radius 0 |
| Kind e2e: same CVE → BLOCK on internet-exposed workload, WARN on internal | Tested in CI | Job **e2e-kind**; kind **v0.30.0**; cluster `blastguard-test`; CVE from nginx:alpine Grype scan in that results run (`CVE-2026-93990`) | Single-node kind; scanner/CVE id is run-specific; exposure classification depends on selectors/services in the e2e manifests | Same results run 38066443627 (jobs ci + e2e-kind); latest main CI 38088776419 job e2e-kind | Decision mismatch (e.g. WARN on exposed payment-api) fails e2e |
| Real-time org-wide vuln matching against production registries | Not yet | Open feature work may extend matching; main evidence today is fixture + kind e2e as documented | Do not treat demo CVE-2026-1234 as a real NVD event | — | — |
| Quarantine/BLOCK enforcement controllers in cluster | Reference / Not yet | Decision layer outputs ALLOW/WARN/QUARANTINE/BLOCK; cluster enforcement wiring varies | Evidence table proves decisions + kind path, not a universal admission webhook product soak | — | — |

## Not proven / out of scope

- Enterprise SBOM lake scale-out and continuous inventory freshness SLAs
- Guaranteeing Grype/NVD coverage completeness
- Equating kind exposure labels with public cloud edge posture

## How to reproduce

```bash
make demo
make rehearse
make prove
```

CI: `.github/workflows/ci.yml` jobs `ci` and `e2e-kind`.

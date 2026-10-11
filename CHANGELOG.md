# Changelog

## Unreleased

### Fixed
- OpenVEX digests require exact `sha256:`+64 hex; match by equality and product name (reject prefix digests)
- `--vex-attestation` requires `--key` or certificate identity flags, decodes DSSE→in-toto→predicate, fails closed
- Reachability triad wired into `Policy.Evaluate`; runtime evidence empty package no longer matches all; no Tetragon/Falco claim
- Remediate marks proposed images without scan data as `UNKNOWN`; "safer" only when no new/worse CVEs
- Reject OpenVEX when twin has no artifacts; validate `@context`/author/timestamp; reject unknown statuses
- CI checks `WRONG_CODE` for prefix-digest VEX; cosign key attestation e2e; ingest tests use `t.Fatal` not `t.Skip`

## Unreleased

- OpenVEX ingest (file + optional OCI attestation via `cosign verify-attestation --type openvex`)
- `not_affected` requires a valid OpenVEX justification and exact digest/image binding; otherwise ignored with warning
- VEX feeds decisions: `not_affected` suppresses, `under_investigation` keeps WARN, `fixed` requires fixed version present
- Reachability triad signals: `package_present`, `network_reachable`, `execution_observed` (UNKNOWN without runtime evidence)
- `blastguard remediate --image <new>` impact report (markdown + JSON)
- Kind e2e: matching-digest VEX flips BLOCK→ALLOW; wrong digest stays BLOCK


## 0.1.0 — 2026-09-06

- Initial public scaffold: BlastGuard Supply Chain Blast-Radius Control Plane
- Offline digital twin fixtures + explainable decision engine
- CLI: `demo`, `rehearse`, `prove`
- CRD sketches: BlastRadius, SecurityDecision, SupplyChainPolicy
- Lifecycle visual: Discover → Trace → Decide → Enforce → Verify

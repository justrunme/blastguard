# Changelog

## Unreleased

## [0.2.0] - 2026-10-11

OpenVEX, reachability triad, and remediate since 0.1.0:

### Added
- OpenVEX ingest (file + optional OCI attestation via `cosign verify-attestation --type openvex`)
- VEX decisions: `not_affected` suppresses (valid justification + exact digest/image binding); `under_investigation` keeps WARN; `fixed` requires fixed version present
- Reachability triad signals: `package_present`, `network_reachable`, `execution_observed` (UNKNOWN without runtime evidence)
- `blastguard remediate --image <new>` impact report (markdown + JSON)
- Real vuln matching, selector exposure, and CI exit codes
- Kind e2e: matching-digest VEX flips BLOCK→ALLOW; wrong digest stays BLOCK
- EVIDENCE.md claim/status standard

### Fixed
- OpenVEX digests require exact `sha256:`+64 hex; match by equality and product name (reject prefix digests)
- `--vex-attestation` requires `--key` or certificate identity flags; decodes DSSE→in-toto→predicate; fails closed
- Reachability triad wired into `Policy.Evaluate`; empty runtime evidence package no longer matches all
- Remediate marks proposed images without scan data as `UNKNOWN`; "safer" only when no new/worse CVEs
- Reject OpenVEX when twin has no artifacts; validate `@context`/author/timestamp; reject unknown statuses
- ArtifactByDigest exact equality via `NormalizeImageDigest`

## 0.1.0 — 2026-09-06

- Initial public scaffold: BlastGuard Supply Chain Blast-Radius Control Plane
- Offline digital twin fixtures + explainable decision engine
- CLI: `demo`, `rehearse`, `prove`
- CRD sketches: BlastRadius, SecurityDecision, SupplyChainPolicy
- Lifecycle visual: Discover → Trace → Decide → Enforce → Verify

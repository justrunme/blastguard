# Changelog

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

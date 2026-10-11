# Architecture — BlastGuard

```text
Discover → Trace → Decide → Enforce (CI exit codes) → Verify
```

## Position

Scanners produce findings.  
GUAC can store supply-chain graphs.  
Sigstore can verify and admit.

BlastGuard is the **blast-radius decision plane**: correlating SBOM truth with runtime/exposure truth into ALLOW / WARN / QUARANTINE / BLOCK — then proving remediation.

**Enforce** in this repo is the CLI exit-code gate for CI. Admission webhooks / Kyverno ClusterPolicies are integration targets for the decision JSON, not an in-tree controller.

Affected-package matching trusts scanner match edges (Grype/OSV) or evaluates `version_range` with ecosystem-aware comparators (semver, Go, Debian, RPM, APK). See `docs/exposure-reachability.md` for exposure vs reachability.

## Digital twin

```text
CVE → package → image → workload → service → ingress
```

Pruned by:

- VEX `not_affected`
- not running
- not reachable
- not internet-exposed (for BLOCK tier)

## Decision policy

See `config/decision-policy.yaml`.  
Ordered rules, first match wins. **No percentage risk scores.**

Blast-radius ladder (same HIGH CVE, different runtime context):

| Context | Typical action |
|---|---|
| Running + internet-exposed + reachable + critical | **BLOCK** |
| Running + internet-exposed + reachable + fix available (non-critical) | **QUARANTINE** |
| Running but not exposed / not reachable | **WARN** |
| VEX `not_affected` for the artifact | **ALLOW** |

Missing SBOM or provenance is reported as a signal (`MISSING` / `UNVERIFIED`) and may be matched by an explicit policy clause on `provenance`. It does **not** by itself escalate WARN → QUARANTINE in the default policy.

## CRDs (v1alpha1 sketches)

- `BlastRadius` — observed radius + critical path
- `SecurityDecision` — action + reason + target
- `SupplyChainPolicy` — cluster policy document

## Offline demo

`fixtures/demo-graph.json` drives `make demo|rehearse|prove` without a cluster.

## Case study

https://justrunme.com/cases/blastguard/

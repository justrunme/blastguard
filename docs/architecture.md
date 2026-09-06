# Architecture — BlastGuard

```text
Discover → Trace → Decide → Enforce → Verify
```

## Position

Scanners produce findings.  
GUAC can store supply-chain graphs.  
Sigstore can verify and admit.

BlastGuard is the **blast-radius decision plane**: correlating SBOM truth with runtime/exposure truth into ALLOW / WARN / QUARANTINE / BLOCK — then proving remediation.

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

## CRDs (v1alpha1 sketches)

- `BlastRadius` — observed radius + critical path
- `SecurityDecision` — action + reason + target
- `SupplyChainPolicy` — cluster policy document

## Offline demo

`fixtures/demo-graph.json` drives `make demo|rehearse|prove` without a cluster.

## Case study

https://justrunme.com/cases/blastguard/

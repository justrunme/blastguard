# BlastGuard

Don't count vulnerabilities. Predict their blast radius.

[![CI](https://github.com/justrunme/blastguard/actions/workflows/ci.yml/badge.svg)](https://github.com/justrunme/blastguard/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/justrunme/blastguard?display_name=tag)](https://github.com/justrunme/blastguard/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Case study: [BlastGuard](https://justrunme.com/cases/blastguard/) · [Andrey Lesnikov](https://justrunme.com/)

## What it does

- Traces CVE → package → image → workload → exposure into an explainable ALLOW / WARN / QUARANTINE / BLOCK decision
- Combines SBOM, vuln scanners, runtime reachability, and VEX-oriented inputs into a decision layer
- Supports what-if rehearsal and before/after remediation proof (`make demo`, `make rehearse`, `make prove`)

## Why

- CVE dashboards count findings; operators need reachability and exposure to prioritize
- Remediation should prove the critical path is closed, not only that a ticket was filed

## Quickstart

```bash
make demo
make rehearse
make prove
```

## Why this exists

Ordinary pipeline:

```text
CVE → scan → 147 findings → dashboard → ticket
```

BlastGuard:

```text
CVE → Dependency Graph → Runtime Reachability → Exposure → Criticality → Decision → GitOps
```

Example:

```text
CVE-2026-1234
     │
     ▼
openssl
     │
     ├── payment-api:v41 → prod/payment-api → internet exposed
     ├── report-worker:v4.2 → staging only
     └── ml-builder:v2.1 → not running
```

```text
┌──────────────────────────────────────────────┐
│  BLASTGUARD                                  │
│  CVE-2026-1234                               │
├──────────────────────────────────────────────┤
│  Affected artifacts       3                  │
│  Running workloads        2                  │
│  Internet exposed         1                  │
│  Reachable                1                  │
│  POLICY                   BLOCK              │
│  Reason                   exploitable CVE +… │
│  FIX                      payment-api:v42    │
└──────────────────────────────────────────────┘
```

No fake `Risk 83/100`. Decisions are **ALLOW / WARN / QUARANTINE / BLOCK** with an explicit reason.

---

## Control loop

| Stage | What happens |
|---|---|
| **Discover** | SBOM (Syft/CycloneDX/SPDX), vulns (Grype/Trivy/OSV), signatures (Cosign) |
| **Trace** | CVE → package → image → workload → service → ingress (+ transitive edges) |
| **Decide** | Policy over CVSS/EPSS/VEX/runtime/exposure/criticality/fix availability |
| **Enforce** | Admission (Sigstore policy-controller / Kyverno) — ALLOW/WARN/QUARANTINE/BLOCK |
| **Verify** | After patch: blast radius → 0 · **REMEDIATION PROVED** |

---

## Quickstart

### 1. Scan an image and ingest results

```bash
syft alpine:3.20 -o cyclonedx-json > alpine-sbom.json
grype alpine:3.20 -o json > alpine-vulns.json

blastguard ingest \
  --sbom-cyclonedx alpine-sbom.json \
  --vulns-grype alpine-vulns.json \
  --output alpine-twin.json
```

### 2. Scan live Kubernetes cluster

```bash
blastguard ingest --from-cluster --output cluster-twin.json
```

### 3. Trace CVE blast radius

```bash
blastguard ingest \
  --sbom-cyclonedx alpine-sbom.json \
  --vulns-grype alpine-vulns.json \
  --policy config/decision-policy.json \
  --trace CVE-2026-85091
```

Output:

```text
┌──────────────────────────────────────────────┐
│  BLASTGUARD                                  │
│  CVE-2026-85091                              │
├──────────────────────────────────────────────┤
│  Package          zlib                       │
│  Severity         HIGH                       │
│  CVSS             8.3                        │
│  EPSS             0.00356                    │
│  Running          yes                        │
│  Internet exposed yes                        │
│  POLICY           ● BLOCK                    │
│  Reason           exploitable CVE on         │
│                   internet-exposed service   │
└──────────────────────────────────────────────┘
```

### 4. What-if Security Rehearsal

```bash
make demo      # trace CVE-2026-1234 → BLOCK on critical path
make rehearse  # what-if for a CVE
make prove     # before/after remediation evidence
```

```bash
./bin/blastguard rehearse CVE-2026-1234
./bin/blastguard rehearse image ghcr.io/justrunme/payment-api:v42
```

Ask before production changes: *if this becomes exploitable, what is our blast radius?*

---

## Vulnerability digital twin

Build-time truth + runtime truth on one graph:

```text
Source → Build → Image → Package → SBOM → Deployment → Pod → Service → Ingress
                 + CVE / VEX / Signature / Provenance / Runtime
```

SBOM says the package exists.  
Kubernetes says it is running.  
Ingress says it is exposed.  
Reachability says the path is live.  
VEX says which copies are `not_affected`.

147 findings become **1 exploitable path**.

---

## Layout

```text
cmd/blastguard/              CLI
internal/decide/             Explainable policy engine
internal/graph/              Digital twin model
config/decision-policy.yaml  BLOCK/WARN rules (no scores)
fixtures/demo-graph.json     Offline twin for demos/CI
api/crds/                    BlastRadius, SecurityDecision, SupplyChainPolicy
docs/assets/                 Lifecycle visual
```

Integrations (not reimplemented here): Syft, Trivy/Grype, OSV, OpenVEX, Cosign/Sigstore, GUAC, OPA, OpenTelemetry, policy-controller/Kyverno.

BlastGuard owns: **control plane, data model, decision engine, rehearsal, evidence**.

---

## Philosophy

| Project | Loop | Prove |
|---|---|---|
| Architecture Rehearsal | Predict → Rehearse → Gate → Verify | change safety |
| TwinOps | Declare → Compose → Detect → Reconcile | convergence |
| AI Infra Control Plane | Evaluate → Decide → Approve → Verify | governance |
| Kanister Recovery | Protect → Validate → Restore → Prove | recoverability |
| **BlastGuard** | **Discover → Trace → Decide → Enforce → Verify** | **supply-chain safety** |

Assumptions → evidence.

---

## License

Apache-2.0 © Andrey Lesnikov

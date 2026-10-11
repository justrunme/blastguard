# Exposure vs reachability

BlastGuard separates **internet exposure** from **reachable path**.

## InternetExposed

A workload is internet-exposed when a Service that **selects its pod template labels** is:

- `type: LoadBalancer` or `type: NodePort`, or
- referenced as an Ingress (or Gateway) backend

Matching is **selector → labels**, not `Service.metadata.name == Deployment.metadata.name`.

## ReachablePath

Reachability answers: *given exposure, is ingress traffic allowed to the pods?*

| Namespace NetworkPolicies | ReachablePath when exposed |
|---|---|
| None (cluster default-allow) | `true` |
| Default-deny Ingress policy selecting the pods (empty `ingress` rules) and no allow policy | `false` |
| Allow Ingress policy selecting the pods | `true` |

This is a **NetworkPolicy-aware approximation** for default-deny namespaces. It does not model full Cilium/Calico identity rules, mesh AuthorizationPolicy, or runtime call-graph reachability (VEX / loaded-path hints remain separate inputs).

## Criticality

Workloads are critical only when labeled/annotated with `blastguard.io/critical=true` (configurable via `config/demo.json`). Name heuristics such as substring `"api"` are not used.

## Decision ladder vs exposure

Default policy (`config/decision-policy.yaml`) uses exposure to separate actions for the **same** HIGH CVE:

- **BLOCK** — critical + internet-exposed + reachable
- **QUARANTINE** — internet-exposed + reachable + fix available (non-critical path)
- **WARN** — present on a running workload without elevated exposure (e.g. `internal-worker`)

`fix_available` alone must not escalate an internal workload to QUARANTINE. SBOM/provenance `MISSING` is a reported signal; it is not an implicit escalator in the default rules.

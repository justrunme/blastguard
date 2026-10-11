# Exposure vs reachability

BlastGuard separates **internet exposure** from **reachable path**, and reports a
three-field reachability triad on every decision.

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

## Reachability triad (decision signals)

Each decision carries three independent fields with vocabulary `TRUE` | `FALSE` | `UNKNOWN`:

| Field | Meaning |
|---|---|
| `package_present` | SBOM shows the CVE's package on an in-scope artifact |
| `network_reachable` | Workload has a reachable ingress path (`ReachablePath`) |
| `execution_observed` | Optional runtime evidence file recorded a related exec/load |

Missing runtime evidence is always `UNKNOWN`. **Observed execution is not exploitability**.

The triad is evaluated in `Policy.Evaluate` (not display-only):

- `execution_observed=TRUE` together with `network_reachable=TRUE` can escalate (WARN → QUARANTINE).
- `execution_observed=FALSE` never yields `ALLOW` alone.
- `UNKNOWN` does not change the candidate action.

No Tetragon/Falco adapter is shipped; supply `blastguard.runtime_evidence/v1` manually (see `internal/runtime`). An empty `package` on an observation does not match every package query; no matching row yields `UNKNOWN`, not `FALSE`.

## Criticality

Workloads are critical only when labeled/annotated with `blastguard.io/critical=true` (configurable via `config/demo.json`). Name heuristics such as substring `"api"` are not used.

## Decision ladder vs exposure

Default policy (`config/decision-policy.yaml`) uses exposure to separate actions for the **same** HIGH CVE:

- **BLOCK** — critical + internet-exposed + reachable
- **QUARANTINE** — internet-exposed + reachable + fix available (non-critical path)
- **WARN** — present on a running workload without elevated exposure (e.g. `internal-worker`)
- **ALLOW** — VEX `not_affected` with valid OpenVEX justification and exact digest/image binding

`fix_available` alone must not escalate an internal workload to QUARANTINE. SBOM/provenance `MISSING` is a reported signal; it is not an implicit escalator in the default rules.

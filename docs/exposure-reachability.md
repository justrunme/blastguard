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

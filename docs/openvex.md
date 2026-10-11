# OpenVEX

BlastGuard ingests [OpenVEX](https://github.com/openvex/spec) documents from a local file (`--vex`) or a **verified** OCI attestation (`--vex-attestation`).

## Binding rules

- Digests must be exactly `sha256:` + 64 hex digits. Short or prefix digests are rejected.
- Digest comparison is **equality only** (no substring/suffix match).
- The product name / purl name must also match the artifact image name (`pkg:oci/whatever@sha256:…` cannot suppress `nginx@sha256:…`).
- Statements match an artifact by **exact content digest** (preferred) or **exact image reference** (including tag).
- Statements are rejected when the twin has no artifacts to bind against.
- Documents must include `@context` (OpenVEX), `author`, and `timestamp`. Unknown statuses are rejected.
- `not_affected` requires a valid OpenVEX justification enum value; otherwise the statement is ignored with a warning.

## OCI attestation (`--vex-attestation`)

Verification is **fail-closed**:

- Requires trust material: `--key <pubkey>` **or** `--certificate-identity` / `--certificate-identity-regexp` plus `--certificate-oidc-issuer`.
- Runs `cosign verify-attestation --type openvex` with those flags (never `--private-infrastructure` alone).
- Decodes the DSSE envelope (`base64` payload → in-toto statement → OpenVEX predicate). Raw cosign stdout is never treated as OpenVEX.
- On any verification or decode failure the process exits non-zero and applies nothing.
- On success, prints the real count of statements accepted from the predicate.

## Decision effects

| Status | Effect |
|---|---|
| `not_affected` | Suppress artifact from blast radius → may ALLOW |
| `under_investigation` | Keep WARN (never ALLOW via empty radius alone) |
| `fixed` | Suppress only when the fixed version is present (package no longer affected) |

## Runtime evidence (reachability triad)

Optional `--runtime-evidence` supplies `blastguard.runtime_evidence/v1` observations for `execution_observed`.

The triad is **wired into** `Policy.Evaluate`:

| Signal | Policy effect |
|---|---|
| `execution_observed=TRUE` + `network_reachable=TRUE` | May escalate WARN → QUARANTINE (and block bare ALLOW without VEX) |
| `execution_observed=FALSE` | Never yields ALLOW alone (downgraded to WARN unless VEX `not_affected`) |
| `UNKNOWN` | Leaves the candidate action unchanged |

Observed execution is **not** exploitability. No Tetragon/Falco adapter is shipped; supply a file matching the schema in `internal/runtime`.

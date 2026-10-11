# OpenVEX

BlastGuard ingests [OpenVEX](https://github.com/openvex/spec) documents from a local file (`--vex`) or an OCI attestation (`--vex-attestation`, optional `--verify-openvex`).

## Binding rules

- Statements match an artifact by **exact content digest** (preferred) or **exact image reference** (including tag).
- Repository-name-only matches are rejected so `not_affected` cannot leap across tags.
- `not_affected` requires a valid OpenVEX justification enum value; otherwise the statement is ignored with a warning.

## Decision effects

| Status | Effect |
|---|---|
| `not_affected` | Suppress artifact from blast radius → may ALLOW |
| `under_investigation` | Keep WARN (never ALLOW via empty radius alone) |
| `fixed` | Suppress only when the fixed version is present (package no longer affected) |

## Runtime evidence

Optional `--runtime-evidence` supplies `blastguard.runtime_evidence/v1` observations for `execution_observed`. Observed execution is **not** exploitability and never yields ALLOW by itself.

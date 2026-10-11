package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/justrunme/blastguard/internal/graph"
)

// Verifier checks SBOM / provenance attestations for an image reference.
type Verifier interface {
	Verify(ctx context.Context, image string) Result
}

// Result holds normalized verification states.
type Result struct {
	SBOM       string
	Provenance string
	Signature  string
	Detail     string
}

// CosignVerifier runs `cosign verify-attestation` when the binary is available.
// Missing binary or skipped check yields MISSING, failed verify yields UNVERIFIED,
// successful verify yields VERIFIED. Never invents VERIFIED without a real check.
//
// OpenVEX attestation verification (--type openvex) requires KeyPath and/or
// CertificateIdentity + CertificateOIDCIssuer. Without trust material the
// verifier fails closed (never applies an unverified payload).
type CosignVerifier struct {
	// CosignBin defaults to "cosign" from PATH.
	CosignBin string
	// Timeout per image check.
	Timeout time.Duration
	// SkipExec forces MISSING without invoking cosign (tests / offline).
	SkipExec bool
	// KeyPath is a cosign public key file (--key).
	KeyPath string
	// CertificateIdentity is the expected cert SAN / identity.
	CertificateIdentity string
	// CertificateOIDCIssuer is the expected OIDC issuer URL.
	CertificateOIDCIssuer string
	// CertificateIdentityRegexp optional alternative to CertificateIdentity.
	CertificateIdentityRegexp string
}

func (v *CosignVerifier) bin() string {
	if v.CosignBin != "" {
		return v.CosignBin
	}
	return "cosign"
}

func (v *CosignVerifier) timeout() time.Duration {
	if v.Timeout > 0 {
		return v.Timeout
	}
	return 20 * time.Second
}

// HasTrustMaterial reports whether key or certificate identity flags are set.
func (v *CosignVerifier) HasTrustMaterial() bool {
	if strings.TrimSpace(v.KeyPath) != "" {
		return true
	}
	id := strings.TrimSpace(v.CertificateIdentity)
	if id == "" {
		id = strings.TrimSpace(v.CertificateIdentityRegexp)
	}
	iss := strings.TrimSpace(v.CertificateOIDCIssuer)
	return id != "" && iss != ""
}

func (v *CosignVerifier) trustArgs() ([]string, error) {
	if !v.HasTrustMaterial() {
		return nil, fmt.Errorf("cosign trust material required: set --key or --certificate-identity/--certificate-oidc-issuer")
	}
	var args []string
	if k := strings.TrimSpace(v.KeyPath); k != "" {
		args = append(args, "--key", k)
	}
	if id := strings.TrimSpace(v.CertificateIdentity); id != "" {
		args = append(args, "--certificate-identity", id)
	}
	if id := strings.TrimSpace(v.CertificateIdentityRegexp); id != "" {
		args = append(args, "--certificate-identity-regexp", id)
	}
	if iss := strings.TrimSpace(v.CertificateOIDCIssuer); iss != "" {
		args = append(args, "--certificate-oidc-issuer", iss)
	}
	return args, nil
}

// Verify implements Verifier.
func (v *CosignVerifier) Verify(ctx context.Context, image string) Result {
	image = strings.TrimSpace(image)
	if image == "" {
		return Result{
			SBOM:       graph.StatusMissing,
			Provenance: graph.StatusMissing,
			Signature:  graph.StatusMissing,
			Detail:     "empty image",
		}
	}
	if v.SkipExec {
		return Result{
			SBOM:       graph.StatusMissing,
			Provenance: graph.StatusMissing,
			Signature:  graph.StatusMissing,
			Detail:     "cosign skipped",
		}
	}
	bin, err := exec.LookPath(v.bin())
	if err != nil {
		return Result{
			SBOM:       graph.StatusMissing,
			Provenance: graph.StatusMissing,
			Signature:  graph.StatusMissing,
			Detail:     "cosign not found in PATH",
		}
	}

	ctx, cancel := context.WithTimeout(ctx, v.timeout())
	defer cancel()

	trust, trustErr := v.trustArgs()
	var base []string
	if trustErr == nil {
		base = trust
	} else {
		// Legacy SBOM/provenance checks without explicit trust stay best-effort
		// and never claim VERIFIED when cosign itself fails. Prefer callers
		// that set trust material.
		base = []string{"--private-infrastructure=true"}
	}

	sigArgs := append([]string{"verify"}, append(append([]string{}, base...), image)...)
	attArgs := append([]string{"verify-attestation", "--type", "slsaprovenance"}, append(append([]string{}, base...), image)...)
	sbomArgs := append([]string{"verify-attestation", "--type", "spdxjson"}, append(append([]string{}, base...), image)...)

	sig := runCosign(ctx, bin, sigArgs)
	att := runCosign(ctx, bin, attArgs)
	sbomAtt := runCosign(ctx, bin, sbomArgs)

	return Result{
		Signature:  statusFromCmd(sig),
		Provenance: statusFromCmd(att),
		SBOM:       statusFromCmd(sbomAtt),
		Detail:     summarize(sig, att, sbomAtt),
	}
}

type cmdOutcome struct {
	err    error
	stdout string
	stderr string
}

func runCosign(ctx context.Context, bin string, args []string) cmdOutcome {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return cmdOutcome{err: err, stdout: stdout.String(), stderr: stderr.String()}
}

func statusFromCmd(o cmdOutcome) string {
	if o.err == nil {
		return graph.StatusVerified
	}
	if errors.Is(o.err, exec.ErrNotFound) {
		return graph.StatusMissing
	}
	// Cosign returns non-zero when attestation/signature is absent or invalid.
	msg := strings.ToLower(o.stderr + o.err.Error())
	if strings.Contains(msg, "no matching attestations") ||
		strings.Contains(msg, "no signatures found") ||
		strings.Contains(msg, "entity not found") ||
		strings.Contains(msg, "name unknown") {
		return graph.StatusMissing
	}
	return graph.StatusUnverified
}

func summarize(parts ...cmdOutcome) string {
	var b strings.Builder
	for _, p := range parts {
		if p.err == nil {
			continue
		}
		line := strings.TrimSpace(p.stderr)
		if line == "" {
			line = p.err.Error()
		}
		if line != "" {
			if b.Len() > 0 {
				b.WriteString("; ")
			}
			b.WriteString(truncate(line, 160))
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// ApplyToArtifact merges verification into an artifact without upgrading a
// known-MISSING SBOM presence flag incorrectly. Provenance/signature always
// come from the verifier when run. Existing VERIFIED from fixtures is only
// kept when verifier returns MISSING (offline) AND BLASTGUARD_TRUST_FIXTURE_ATTEST=1.
func ApplyToArtifact(a *graph.Artifact, r Result) {
	if a == nil {
		return
	}
	trustFixture := os.Getenv("BLASTGUARD_TRUST_FIXTURE_ATTEST") == "1"
	if r.Provenance != graph.StatusMissing || !trustFixture {
		a.Provenance = r.Provenance
	} else {
		a.Provenance = graph.NormalizeStatus(a.Provenance)
	}
	if r.Signature != graph.StatusMissing || !trustFixture {
		a.Signature = r.Signature
	} else {
		a.Signature = graph.NormalizeStatus(a.Signature)
	}
	// SBOM: if we already ingested package data, keep VERIFIED for "SBOM present";
	// attestation check can upgrade/downgrade when cosign actually ran.
	if r.SBOM == graph.StatusVerified || r.SBOM == graph.StatusUnverified {
		a.SBOM = r.SBOM
	} else if strings.TrimSpace(a.SBOM) == "" {
		a.SBOM = graph.StatusMissing
	} else {
		a.SBOM = graph.NormalizeStatus(a.SBOM)
	}
}

// StaticVerifier returns fixed results (unit tests).
type StaticVerifier struct {
	Result Result
}

func (s StaticVerifier) Verify(context.Context, string) Result { return s.Result }

// Default returns a CosignVerifier.
func Default() Verifier {
	return &CosignVerifier{}
}

// FormatDetail is a helper for logging.
func FormatDetail(image string, r Result) string {
	return fmt.Sprintf("%s sbom=%s provenance=%s signature=%s", image, r.SBOM, r.Provenance, r.Signature)
}

// OpenVEXResult is the outcome of cosign verify-attestation --type openvex.
type OpenVEXResult struct {
	Status     string // VERIFIED | UNVERIFIED | MISSING
	Detail     string
	Payload    []byte // decoded OpenVEX document bytes when verified
	Statements int    // count of OpenVEX statements in the decoded predicate
}

// dsseEnvelope is the subset of a DSSE envelope cosign prints on stdout.
type dsseEnvelope struct {
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
}

// inTotoStatement is the in-toto attestation wrapper around an OpenVEX predicate.
type inTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// cosignAttestationOutput covers both a bare DSSE envelope and cosign's
// {"payload":"..."} / array-of-envelopes shapes.
type cosignAttestationOutput struct {
	Payload json.RawMessage `json:"payload"`
}

// VerifyOpenVEX runs `cosign verify-attestation --type openvex` for an image.
// Requires trust material. On any verification or decode failure the result is
// UNVERIFIED/MISSING with an empty Payload (fail closed — never apply unverified data).
func (v *CosignVerifier) VerifyOpenVEX(ctx context.Context, image string) OpenVEXResult {
	image = strings.TrimSpace(image)
	if image == "" {
		return OpenVEXResult{Status: graph.StatusMissing, Detail: "empty image"}
	}
	if v.SkipExec {
		return OpenVEXResult{Status: graph.StatusMissing, Detail: "cosign skipped"}
	}
	trust, err := v.trustArgs()
	if err != nil {
		return OpenVEXResult{Status: graph.StatusUnverified, Detail: err.Error()}
	}
	bin, err := exec.LookPath(v.bin())
	if err != nil {
		return OpenVEXResult{Status: graph.StatusMissing, Detail: "cosign not found in PATH"}
	}
	ctx, cancel := context.WithTimeout(ctx, v.timeout())
	defer cancel()

	args := append([]string{"verify-attestation", "--type", "openvex"}, trust...)
	if strings.Contains(image, "localhost") || strings.Contains(image, "127.0.0.1") {
		args = append(args, "--allow-insecure-registry")
	}
	args = append(args, image)
	out := runCosign(ctx, bin, args)
	if out.err != nil {
		st := statusFromCmd(out)
		return OpenVEXResult{Status: st, Detail: truncate(out.stderr, 200)}
	}

	payload, n, decErr := DecodeOpenVEXAttestation([]byte(out.stdout))
	if decErr != nil {
		return OpenVEXResult{
			Status: graph.StatusUnverified,
			Detail: "verified signature but failed to decode OpenVEX predicate: " + decErr.Error(),
		}
	}
	return OpenVEXResult{
		Status:     graph.StatusVerified,
		Detail:     truncate(out.stderr, 200),
		Payload:    payload,
		Statements: n,
	}
}

// DecodeOpenVEXAttestation extracts the OpenVEX document from cosign verify-attestation
// stdout (DSSE envelope → base64 payload → in-toto statement → predicate).
func DecodeOpenVEXAttestation(stdout []byte) (openvexDoc []byte, statements int, err error) {
	stdout = bytes.TrimSpace(stdout)
	if len(stdout) == 0 {
		return nil, 0, fmt.Errorf("empty cosign stdout")
	}

	// Try array of envelopes first.
	var arr []json.RawMessage
	if json.Unmarshal(stdout, &arr) == nil && len(arr) > 0 {
		var lastErr error
		for _, raw := range arr {
			doc, n, e := decodeOneEnvelope(raw)
			if e == nil {
				return doc, n, nil
			}
			lastErr = e
		}
		return nil, 0, lastErr
	}

	return decodeOneEnvelope(stdout)
}

func decodeOneEnvelope(raw []byte) ([]byte, int, error) {
	var env dsseEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, 0, fmt.Errorf("dsse envelope: %w", err)
	}
	if strings.TrimSpace(env.Payload) == "" {
		// cosign sometimes wraps differently
		var wrap cosignAttestationOutput
		if err := json.Unmarshal(raw, &wrap); err != nil || len(wrap.Payload) == 0 {
			return nil, 0, fmt.Errorf("dsse envelope missing payload")
		}
		// payload may already be a JSON string or object
		var asString string
		if json.Unmarshal(wrap.Payload, &asString) == nil {
			env.Payload = asString
		} else {
			// payload is nested object — treat as already-decoded statement
			return extractPredicate(wrap.Payload)
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		// try raw URL encoding
		decoded, err = base64.RawStdEncoding.DecodeString(env.Payload)
		if err != nil {
			return nil, 0, fmt.Errorf("base64 payload: %w", err)
		}
	}
	return extractPredicate(decoded)
}

func extractPredicate(statementJSON []byte) ([]byte, int, error) {
	var stmt inTotoStatement
	if err := json.Unmarshal(statementJSON, &stmt); err != nil {
		// Maybe the payload is already a bare OpenVEX document.
		if n, ok := countOpenVEXStatements(statementJSON); ok {
			return statementJSON, n, nil
		}
		return nil, 0, fmt.Errorf("in-toto statement: %w", err)
	}
	pred := bytes.TrimSpace(stmt.Predicate)
	if len(pred) == 0 {
		return nil, 0, fmt.Errorf("empty predicate")
	}
	// Predicate may itself be an OpenVEX document or wrap one under "data".
	if n, ok := countOpenVEXStatements(pred); ok {
		return pred, n, nil
	}
	var wrap struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(pred, &wrap) == nil && len(wrap.Data) > 0 {
		if n, ok := countOpenVEXStatements(wrap.Data); ok {
			return wrap.Data, n, nil
		}
		return wrap.Data, 0, nil
	}
	return pred, 0, nil
}

func countOpenVEXStatements(doc []byte) (int, bool) {
	var probe struct {
		Context    string            `json:"@context"`
		Statements []json.RawMessage `json:"statements"`
	}
	if err := json.Unmarshal(doc, &probe); err != nil {
		return 0, false
	}
	if probe.Context == "" && len(probe.Statements) == 0 {
		return 0, false
	}
	return len(probe.Statements), true
}

// DownloadOpenVEX is an alias helper for VerifyOpenVEX (OCI attestation fetch+verify).
func (v *CosignVerifier) DownloadOpenVEX(ctx context.Context, image string) OpenVEXResult {
	return v.VerifyOpenVEX(ctx, image)
}

package verify

import (
	"bytes"
	"context"
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
type CosignVerifier struct {
	// CosignBin defaults to "cosign" from PATH.
	CosignBin string
	// Timeout per image check.
	Timeout time.Duration
	// SkipExec forces MISSING without invoking cosign (tests / offline).
	SkipExec bool
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

	sig := runCosign(ctx, bin, []string{"verify", "--private-infrastructure=true", image})
	att := runCosign(ctx, bin, []string{
		"verify-attestation",
		"--type", "slsaprovenance",
		"--private-infrastructure=true",
		image,
	})
	sbomAtt := runCosign(ctx, bin, []string{
		"verify-attestation",
		"--type", "spdxjson",
		"--private-infrastructure=true",
		image,
	})

	return Result{
		Signature:  statusFromCmd(sig),
		Provenance: statusFromCmd(att),
		SBOM:       statusFromCmd(sbomAtt),
		Detail:     summarize(sig, att, sbomAtt),
	}
}

type cmdOutcome struct {
	err    error
	stderr string
}

func runCosign(ctx context.Context, bin string, args []string) cmdOutcome {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stdout = &bytes.Buffer{}
	cmd.Stderr = &stderr
	err := cmd.Run()
	return cmdOutcome{err: err, stderr: stderr.String()}
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

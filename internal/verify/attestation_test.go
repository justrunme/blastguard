package verify

import (
	"context"
	"testing"

	"github.com/justrunme/blastguard/internal/graph"
)

func TestStaticVerifierNeverHardcodesVerifiedWithoutResult(t *testing.T) {
	v := StaticVerifier{Result: Result{
		SBOM:       graph.StatusMissing,
		Provenance: graph.StatusUnverified,
		Signature:  graph.StatusMissing,
	}}
	r := v.Verify(context.Background(), "example.com/app:1")
	if r.Provenance != graph.StatusUnverified {
		t.Fatalf("got %s", r.Provenance)
	}
	if r.SBOM == graph.StatusVerified {
		t.Fatal("must not invent VERIFIED")
	}
}

func TestCosignSkipExecIsMissing(t *testing.T) {
	v := &CosignVerifier{SkipExec: true}
	r := v.Verify(context.Background(), "example.com/app:1")
	if r.Provenance != graph.StatusMissing || r.Signature != graph.StatusMissing {
		t.Fatalf("skip should be MISSING, got %+v", r)
	}
}

func TestApplyToArtifact(t *testing.T) {
	a := &graph.Artifact{SBOM: "verified", Provenance: "verified"}
	ApplyToArtifact(a, Result{
		SBOM:       graph.StatusVerified,
		Provenance: graph.StatusUnverified,
		Signature:  graph.StatusUnverified,
	})
	if a.Provenance != graph.StatusUnverified {
		t.Fatalf("got provenance %s", a.Provenance)
	}
}

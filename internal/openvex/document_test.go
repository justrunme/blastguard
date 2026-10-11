package openvex_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/justrunme/blastguard/internal/graph"
	"github.com/justrunme/blastguard/internal/openvex"
)

func TestParseAlpineFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "alpine-3.20-vex.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := openvex.ParseDocument(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Statements) != 1 {
		t.Fatalf("statements: %d", len(doc.Statements))
	}
	st := doc.Statements[0]
	if st.Vulnerability.Name != "CVE-2024-6119" {
		t.Fatalf("cve %s", st.Vulnerability.Name)
	}
	if !openvex.ValidJustification(st.Justification) {
		t.Fatalf("justification should be valid: %s", st.Justification)
	}
	pid := openvex.ParseProductIdentity(st.Products[0].ID)
	if pid.Digest != "sha256:bf8527eb54c3680e728d5b4b383a8ba730d72dae7236fbc8dff97ed6b224a731" {
		t.Fatalf("digest=%q", pid.Digest)
	}
}

func TestNotAffectedRequiresJustification(t *testing.T) {
	doc := &openvex.Document{Statements: []openvex.Statement{{
		Vulnerability: openvex.Vulnerability{Name: "CVE-1"},
		Products:      []openvex.Product{{ID: "pkg:oci/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		Status:        openvex.StatusNotAffected,
		Justification: "because we say so",
	}}}
	arts := []graph.Artifact{{
		Image:  "nginx:alpine",
		Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}
	acc, warn := openvex.EvaluateStatements(doc, arts)
	if len(acc) != 0 {
		t.Fatalf("expected ignore, got %+v", acc)
	}
	if len(warn) == 0 {
		t.Fatal("expected warning")
	}
}

func TestWrongDigestIgnored(t *testing.T) {
	dig := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	doc := &openvex.Document{Statements: []openvex.Statement{{
		Vulnerability: openvex.Vulnerability{Name: "CVE-1"},
		Products:      []openvex.Product{{ID: "pkg:oci/nginx@" + dig}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path",
	}}}
	arts := []graph.Artifact{{
		Image:  "nginx:alpine",
		Digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}}
	acc, warn := openvex.EvaluateStatements(doc, arts)
	if len(acc) != 0 {
		t.Fatalf("wrong digest must be ignored, got %+v", acc)
	}
	if len(warn) == 0 {
		t.Fatal("expected warning for wrong digest")
	}
}

func TestValidDigestAccepted(t *testing.T) {
	dig := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	doc := &openvex.Document{Statements: []openvex.Statement{{
		Vulnerability: openvex.Vulnerability{Name: "CVE-1"},
		Products:      []openvex.Product{{ID: "pkg:oci/nginx@" + dig}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path",
	}}}
	arts := []graph.Artifact{{Image: "nginx:alpine", Digest: dig}}
	acc, warn := openvex.EvaluateStatements(doc, arts)
	if len(warn) != 0 {
		t.Fatalf("unexpected warnings: %+v", warn)
	}
	if len(acc) != 1 || acc[0].Status != openvex.StatusNotAffected {
		t.Fatalf("accepted=%+v", acc)
	}
	if !openvex.MatchArtifact(acc[0], &arts[0]) {
		t.Fatal("MatchArtifact should hit")
	}
}

func TestExactImageRefBinding(t *testing.T) {
	doc := &openvex.Document{Statements: []openvex.Statement{{
		Vulnerability: openvex.Vulnerability{Name: "CVE-2026-3456"},
		Products:      []openvex.Product{{ID: "ghcr.io/justrunme/payment-api:v41"}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_present",
	}}}
	arts := []graph.Artifact{{Image: "ghcr.io/justrunme/payment-api:v41"}}
	acc, warn := openvex.EvaluateStatements(doc, arts)
	if len(warn) != 0 || len(acc) != 1 {
		t.Fatalf("acc=%+v warn=%+v", acc, warn)
	}
}

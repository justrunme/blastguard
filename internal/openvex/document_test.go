package openvex_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/justrunme/blastguard/internal/graph"
	"github.com/justrunme/blastguard/internal/openvex"
)

func metaDoc(stmts ...openvex.Statement) *openvex.Document {
	return &openvex.Document{
		Context:    "https://openvex.dev/ns/v0.2.0",
		Author:     "blastguard-test",
		Timestamp:  "2026-10-11T00:00:00Z",
		Statements: stmts,
	}
}

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

func TestShortDigestRejected(t *testing.T) {
	pid := openvex.ParseProductIdentity("pkg:oci/whatever@sha256:a")
	if pid.Digest != "" {
		t.Fatalf("short digest must be empty, got %q", pid.Digest)
	}
	if openvex.ValidDigest("sha256:a") {
		t.Fatal("ValidDigest must reject short digest")
	}
	if openvex.ValidDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Fatal("ValidDigest must reject 63-hex digest")
	}
	full := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !openvex.ValidDigest(full) {
		t.Fatal("ValidDigest must accept full digest")
	}
}

func TestPrefixDigestDoesNotSuppress(t *testing.T) {
	full := "sha256:a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890"
	// Prefix of the real digest — historically matched via Contains/HasSuffix.
	prefix := "sha256:a1b2"
	doc := metaDoc(openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: "CVE-PREFIX"},
		Products:      []openvex.Product{{ID: "pkg:oci/whatever@" + prefix}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path",
	})
	arts := []graph.Artifact{{
		Image:  "nginx:alpine",
		Digest: full,
	}}
	acc, warn := openvex.EvaluateStatements(doc, arts)
	if len(acc) != 0 {
		t.Fatalf("prefix digest must not be accepted, got %+v", acc)
	}
	if len(warn) == 0 {
		t.Fatal("expected warning for prefix digest")
	}
	// Even if somehow accepted with a short digest stored, MatchArtifact must fail.
	fake := openvex.Accepted{Digest: prefix, Name: "whatever"}
	if openvex.MatchArtifact(fake, &arts[0]) {
		t.Fatal("MatchArtifact must not match prefix digest")
	}
}

func TestMismatchedNameDoesNotSuppress(t *testing.T) {
	dig := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	doc := metaDoc(openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: "CVE-NAME"},
		Products:      []openvex.Product{{ID: "pkg:oci/whatever@" + dig}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path",
	})
	arts := []graph.Artifact{{
		Image:  "nginx:alpine",
		Digest: dig,
	}}
	acc, warn := openvex.EvaluateStatements(doc, arts)
	if len(acc) != 0 {
		t.Fatalf("mismatched name must not be accepted, got %+v", acc)
	}
	if len(warn) == 0 {
		t.Fatal("expected warning for name mismatch")
	}
	// Decision-time: twin.VEXFor must also reject name mismatch.
	twin := &graph.Twin{VEX: []graph.VEX{{
		CVE: "CVE-NAME", Digest: dig, Product: "pkg:oci/whatever@" + dig,
		Status: openvex.StatusNotAffected,
	}}}
	if twin.VEXFor("CVE-NAME", "nginx:alpine", dig) != nil {
		t.Fatal("VEXFor must reject product name mismatch")
	}
}

func TestNoArtifactsRejected(t *testing.T) {
	dig := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	doc := metaDoc(openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: "CVE-1"},
		Products:      []openvex.Product{{ID: "pkg:oci/nginx@" + dig}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path",
	})
	acc, warn := openvex.EvaluateStatements(doc, nil)
	if len(acc) != 0 {
		t.Fatalf("no artifacts must reject, got %+v", acc)
	}
	if len(warn) == 0 {
		t.Fatal("expected warning")
	}
}

func TestUnknownStatusRejected(t *testing.T) {
	dig := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	doc := metaDoc(openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: "CVE-1"},
		Products:      []openvex.Product{{ID: "pkg:oci/nginx@" + dig}},
		Status:        "maybe",
		Justification: "vulnerable_code_not_in_execute_path",
	})
	arts := []graph.Artifact{{Image: "nginx:alpine", Digest: dig}}
	acc, warn := openvex.EvaluateStatements(doc, arts)
	if len(acc) != 0 {
		t.Fatalf("unknown status must reject, got %+v", acc)
	}
	if len(warn) == 0 {
		t.Fatal("expected warning")
	}
}

func TestMissingDocumentFieldsRejected(t *testing.T) {
	doc := &openvex.Document{Statements: []openvex.Statement{{
		Vulnerability: openvex.Vulnerability{Name: "CVE-1"},
		Products:      []openvex.Product{{ID: "pkg:oci/nginx@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path",
	}}}
	acc, warn := openvex.EvaluateStatements(doc, []graph.Artifact{{
		Image: "nginx:alpine", Digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
	}})
	if len(acc) != 0 || len(warn) == 0 {
		t.Fatalf("missing @context/author/timestamp must reject, acc=%+v warn=%+v", acc, warn)
	}
}

func TestNotAffectedRequiresJustification(t *testing.T) {
	doc := metaDoc(openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: "CVE-1"},
		Products:      []openvex.Product{{ID: "pkg:oci/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		Status:        openvex.StatusNotAffected,
		Justification: "because we say so",
	})
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
	doc := metaDoc(openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: "CVE-1"},
		Products:      []openvex.Product{{ID: "pkg:oci/nginx@" + dig}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path",
	})
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
	doc := metaDoc(openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: "CVE-1"},
		Products:      []openvex.Product{{ID: "pkg:oci/nginx@" + dig}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_in_execute_path",
	})
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
	doc := metaDoc(openvex.Statement{
		Vulnerability: openvex.Vulnerability{Name: "CVE-2026-3456"},
		Products:      []openvex.Product{{ID: "ghcr.io/justrunme/payment-api:v41"}},
		Status:        openvex.StatusNotAffected,
		Justification: "vulnerable_code_not_present",
	})
	arts := []graph.Artifact{{Image: "ghcr.io/justrunme/payment-api:v41"}}
	acc, warn := openvex.EvaluateStatements(doc, arts)
	if len(warn) != 0 || len(acc) != 1 {
		t.Fatalf("acc=%+v warn=%+v", acc, warn)
	}
}

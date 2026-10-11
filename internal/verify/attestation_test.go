package verify

import (
	"context"
	"encoding/base64"
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

func TestHasTrustMaterial(t *testing.T) {
	v := &CosignVerifier{}
	if v.HasTrustMaterial() {
		t.Fatal("empty verifier must lack trust material")
	}
	v.KeyPath = "/tmp/cosign.pub"
	if !v.HasTrustMaterial() {
		t.Fatal("key path should count")
	}
	v2 := &CosignVerifier{CertificateIdentity: "a", CertificateOIDCIssuer: "https://issuer"}
	if !v2.HasTrustMaterial() {
		t.Fatal("cert identity+issuer should count")
	}
	v3 := &CosignVerifier{CertificateIdentity: "a"}
	if v3.HasTrustMaterial() {
		t.Fatal("identity without issuer must not count")
	}
}

func TestVerifyOpenVEXFailsClosedWithoutTrust(t *testing.T) {
	v := &CosignVerifier{}
	res := v.VerifyOpenVEX(context.Background(), "example.com/app:1")
	if res.Status == graph.StatusVerified || len(res.Payload) != 0 {
		t.Fatalf("must fail closed without trust material, got %+v", res)
	}
}

func TestDecodeOpenVEXAttestationDSSE(t *testing.T) {
	openvexDoc := `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/1",
  "author": "ci",
  "timestamp": "2026-10-11T00:00:00Z",
  "version": "1",
  "statements": [
    {
      "vulnerability": {"name": "CVE-1"},
      "products": [{"@id": "pkg:oci/nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_present"
    }
  ]
}`
	stmt := `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://openvex.dev/ns","predicate":` + openvexDoc + `}`
	payload := base64.StdEncoding.EncodeToString([]byte(stmt))
	stdout := `{"payload":"` + payload + `","payloadType":"application/vnd.in-toto+json"}`
	doc, n, err := DecodeOpenVEXAttestation([]byte(stdout))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("statements=%d", n)
	}
	if len(doc) == 0 {
		t.Fatal("empty doc")
	}
}

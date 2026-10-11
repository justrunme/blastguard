package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIngestCycloneDX(t *testing.T) {
	wd, _ := os.Getwd()
	testdata := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-cdx.json")
	if _, err := os.Stat(testdata); os.IsNotExist(err) {
		t.Fatal("testdata not available")
	}

	b := NewBuilder()
	if err := b.IngestCycloneDX(testdata); err != nil {
		t.Fatalf("IngestCycloneDX failed: %v", err)
	}

	if len(b.packages) == 0 {
		t.Error("Expected packages to be ingested")
	}
}

func TestIngestSPDX(t *testing.T) {
	wd, _ := os.Getwd()
	testdata := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-spdx.json")
	if _, err := os.Stat(testdata); os.IsNotExist(err) {
		t.Fatal("testdata not available")
	}

	b := NewBuilder()
	if err := b.IngestSPDX(testdata); err != nil {
		t.Fatalf("IngestSPDX failed: %v", err)
	}

	if len(b.packages) == 0 {
		t.Error("Expected packages to be ingested")
	}
}

func TestIngestGrype(t *testing.T) {
	wd, _ := os.Getwd()
	testdata := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-grype.json")
	if _, err := os.Stat(testdata); os.IsNotExist(err) {
		t.Fatal("testdata not available")
	}

	b := NewBuilder()
	if err := b.IngestGrype(testdata); err != nil {
		t.Fatalf("IngestGrype failed: %v", err)
	}

	if len(b.cves) == 0 {
		t.Error("Expected CVEs to be ingested")
	}
}

func TestIngestGrypeFileSourceTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "grype-file.json")
	// Newer Grype emits source.target as a string for file/directory/tarball scans.
	payload := `{
		"matches": [{
			"vulnerability": {"id": "CVE-2024-0001", "severity": "HIGH", "description": "test", "fix": {"versions": ["1.2.4"], "state": "fixed"}},
			"artifact": {"name": "demo", "version": "1.2.3", "type": "go-module", "purl": "pkg:golang/demo@1.2.3"}
		}],
		"source": {"type": "file", "target": "dist/blastguard_0.2.0_linux_amd64.tar.gz"}
	}`
	if err := os.WriteFile(path, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBuilder()
	if err := b.IngestGrype(path); err != nil {
		t.Fatalf("IngestGrype file target failed: %v", err)
	}
	if b.imageRef != "dist/blastguard_0.2.0_linux_amd64.tar.gz" {
		t.Fatalf("imageRef=%q, want tarball path", b.imageRef)
	}
	if len(b.cves) != 1 {
		t.Fatalf("cves=%d, want 1", len(b.cves))
	}
}

func TestIngestOSV(t *testing.T) {
	wd, _ := os.Getwd()
	testdata := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-osv.json")
	if _, err := os.Stat(testdata); os.IsNotExist(err) {
		t.Fatal("testdata not available")
	}

	b := NewBuilder()
	if err := b.IngestOSV(testdata); err != nil {
		t.Fatalf("IngestOSV failed: %v", err)
	}

	if len(b.cves) == 0 {
		t.Error("Expected CVEs to be ingested from OSV")
	}
}

func TestIngestVEX(t *testing.T) {
	wd, _ := os.Getwd()
	root := filepath.Join(wd, "..", "..", "testdata")
	cdx := filepath.Join(root, "alpine-3.20-cdx.json")
	grype := filepath.Join(root, "alpine-3.20-grype.json")
	vex := filepath.Join(root, "alpine-3.20-vex.json")
	for _, p := range []string{cdx, grype, vex} {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Fatal("testdata not available")
		}
	}

	b := NewBuilder()
	if err := b.IngestCycloneDX(cdx); err != nil {
		t.Fatal(err)
	}
	if err := b.IngestGrype(grype); err != nil {
		t.Fatal(err)
	}
	if err := b.IngestVEX(vex); err != nil {
		t.Fatalf("IngestVEX failed: %v", err)
	}
	if len(b.vexStatements) == 0 {
		t.Fatalf("Expected VEX statements, warnings=%v", b.VEXWarnings())
	}
	twin := b.Build()
	if twin.VEXStatus("CVE-2024-6119", "alpine:3.20") == "" && twin.VEXFor("CVE-2024-6119", "alpine:3.20", twin.Artifacts[0].Digest) == nil {
		t.Fatalf("VEX not bound: %#v digest=%s", twin.VEX, twin.Artifacts[0].Digest)
	}
}

func TestIngestVEXInvalidJustificationWarns(t *testing.T) {
	wd, _ := os.Getwd()
	vex := filepath.Join(wd, "..", "..", "testdata", "openvex-invalid-justification.json")
	if _, err := os.Stat(vex); os.IsNotExist(err) {
		t.Fatal("fixture missing")
	}
	b := NewBuilder()
	_ = b.IngestCycloneDX(filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-cdx.json"))
	_ = b.IngestGrype(filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-grype.json"))
	if err := b.IngestVEX(vex); err != nil {
		t.Fatal(err)
	}
	if len(b.vexStatements) != 0 {
		t.Fatalf("expected ignore, got %#v", b.vexStatements)
	}
	joined := strings.Join(b.VEXWarnings(), "\n")
	if !strings.Contains(joined, "justification") {
		t.Fatalf("want justification warning, got %q", joined)
	}
}

func TestIngestVEXWrongDigestWarns(t *testing.T) {
	wd, _ := os.Getwd()
	vex := filepath.Join(wd, "..", "..", "testdata", "openvex-wrong-digest.json")
	if _, err := os.Stat(vex); os.IsNotExist(err) {
		t.Fatal("fixture missing")
	}
	b := NewBuilder()
	_ = b.IngestCycloneDX(filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-cdx.json"))
	_ = b.IngestGrype(filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-grype.json"))
	if err := b.IngestVEX(vex); err != nil {
		t.Fatal(err)
	}
	if len(b.vexStatements) != 0 {
		t.Fatalf("expected ignore wrong digest, got %#v", b.vexStatements)
	}
	joined := strings.Join(b.VEXWarnings(), "\n")
	if !strings.Contains(joined, "digest") {
		t.Fatalf("want digest warning, got %q", joined)
	}
}

func TestBuild(t *testing.T) {
	wd, _ := os.Getwd()
	cdxPath := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-cdx.json")
	grypePath := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-grype.json")

	if _, err := os.Stat(cdxPath); os.IsNotExist(err) {
		t.Fatal("testdata not available")
	}

	b := NewBuilder()
	if err := b.IngestCycloneDX(cdxPath); err != nil {
		t.Fatalf("IngestCycloneDX failed: %v", err)
	}
	if err := b.IngestGrype(grypePath); err != nil {
		t.Fatalf("IngestGrype failed: %v", err)
	}

	twin := b.Build()
	if len(twin.Artifacts) == 0 {
		t.Error("Expected artifacts")
	}
	if len(twin.CVEs) == 0 {
		t.Error("Expected CVEs")
	}
	if !twin.InventoryComplete {
		t.Error("SBOM-backed ingest with no running workloads must set inventory_complete")
	}
}

func TestBuildEmptyInventoryIncomplete(t *testing.T) {
	// Negative: empty builder must not claim a complete inventory.
	twin := NewBuilder().Build()
	if twin.InventoryComplete {
		t.Fatal("empty ingest twin must be inventory_complete=false")
	}
}

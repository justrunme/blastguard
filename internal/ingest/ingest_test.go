package ingest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIngestCycloneDX(t *testing.T) {
	wd, _ := os.Getwd()
	testdata := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-cdx.json")
	if _, err := os.Stat(testdata); os.IsNotExist(err) {
		t.Skip("testdata not available")
	}

	b := NewBuilder()
	if err := b.IngestCycloneDX(testdata); err != nil {
		t.Fatalf("IngestCycloneDX failed: %v", err)
	}

	if len(b.packages) == 0 {
		t.Error("Expected packages to be ingested")
	}
	if b.imageRef != "alpine:3.20" {
		t.Fatalf("CycloneDX image ref: got %q want alpine:3.20", b.imageRef)
	}
}

func TestIngestSPDX(t *testing.T) {
	wd, _ := os.Getwd()
	testdata := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-spdx.json")
	if _, err := os.Stat(testdata); os.IsNotExist(err) {
		t.Skip("testdata not available")
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
		t.Skip("testdata not available")
	}

	b := NewBuilder()
	if err := b.IngestGrype(testdata); err != nil {
		t.Fatalf("IngestGrype failed: %v", err)
	}

	if len(b.cves) == 0 {
		t.Log("Warning: No CVEs found in Grype output")
	}
}

func TestIngestOSV(t *testing.T) {
	wd, _ := os.Getwd()
	testdata := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-osv.json")
	if _, err := os.Stat(testdata); os.IsNotExist(err) {
		t.Skip("testdata not available")
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
	testdata := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-vex.json")
	if _, err := os.Stat(testdata); os.IsNotExist(err) {
		t.Skip("testdata not available")
	}

	b := NewBuilder()
	if err := b.IngestVEX(testdata); err != nil {
		t.Fatalf("IngestVEX failed: %v", err)
	}

	if len(b.vexStatements) == 0 {
		t.Error("Expected VEX statements to be ingested")
	}
}

func TestBuild(t *testing.T) {
	wd, _ := os.Getwd()
	cdxPath := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-cdx.json")
	grypePath := filepath.Join(wd, "..", "..", "testdata", "alpine-3.20-grype.json")

	if _, err := os.Stat(cdxPath); os.IsNotExist(err) {
		t.Skip("testdata not available")
	}

	b := NewBuilder()
	if err := b.IngestCycloneDX(cdxPath); err != nil {
		t.Fatalf("IngestCycloneDX failed: %v", err)
	}
	if err := b.IngestGrype(grypePath); err != nil {
		t.Fatalf("IngestGrype failed: %v", err)
	}

	twin := b.Build()
	if twin == nil {
		t.Fatal("Build returned nil")
	}

	if len(twin.Artifacts) == 0 {
		t.Error("Expected at least one artifact")
	}

	if len(twin.Artifacts[0].Packages) == 0 {
		t.Error("Expected packages in artifact")
	}
}

package decide_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReleaseWorkflowGrypeFailClosed(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)

	// Negative: the Grype scan line must not be masked with || true (fail-open).
	masked := regexp.MustCompile(`grype\s+dist/blastguard[^\n]*\|\|\s*true`)
	if masked.MatchString(body) {
		t.Fatal("release Grype scan must not mask failures with || true")
	}
	if !strings.Contains(body, "/tmp/grype dist/blastguard_*_linux_amd64.tar.gz -o json > /tmp/release-grype.json") {
		t.Fatal("expected unmasked Grype scan of the release artifact")
	}
	// Dogfood must assert policy decisions, not only count CVEs.
	if !strings.Contains(body, "--trace") {
		t.Fatal("dogfood step must trace CVE decisions")
	}
	if !strings.Contains(body, "BLOCK|QUARANTINE|UNKNOWN") {
		t.Fatal("dogfood step must fail the gate on BLOCK/QUARANTINE/UNKNOWN")
	}
}

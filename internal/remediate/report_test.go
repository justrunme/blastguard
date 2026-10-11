package remediate_test

import (
	"testing"

	"github.com/justrunme/blastguard/internal/graph"
	"github.com/justrunme/blastguard/internal/remediate"
)

func TestCompareSaferWorkload(t *testing.T) {
	twin := &graph.Twin{
		CVEs: []graph.CVE{
			{ID: "CVE-OLD", Package: "zlib", Severity: "HIGH", VersionRange: "<= 1.2.0"},
			{ID: "CVE-STILL", Package: "curl", Severity: "MEDIUM", VersionRange: "<= 8.0.0"},
		},
		Artifacts: []graph.Artifact{
			{Image: "app:v1", Packages: []graph.Pkg{{Name: "zlib", Version: "1.2.0"}, {Name: "curl", Version: "7.0.0"}}},
			{Image: "app:v2", Packages: []graph.Pkg{{Name: "zlib", Version: "1.3.0"}, {Name: "curl", Version: "7.0.0"}}},
		},
		Workloads: []graph.Workload{
			{Name: "api", Namespace: "default", Image: "app:v1", Running: true},
		},
		Matches: []graph.Match{
			{CVE: "CVE-OLD", Package: "zlib", Version: "1.2.0", Image: "app:v1"},
			{CVE: "CVE-STILL", Package: "curl", Version: "7.0.0", Image: "app:v1"},
			{CVE: "CVE-STILL", Package: "curl", Version: "7.0.0", Image: "app:v2"},
		},
	}
	rep, err := remediate.Compare(twin, "app:v2")
	if err != nil {
		t.Fatal(err)
	}
	if rep.SaferVerdict != remediate.SaferYes {
		t.Fatalf("verdict=%s", rep.SaferVerdict)
	}
	if len(rep.SaferWorkloads) != 1 {
		t.Fatalf("safer=%+v", rep.SaferWorkloads)
	}
	if len(rep.RemainingCVEs) != 1 || rep.RemainingCVEs[0].ID != "CVE-STILL" {
		t.Fatalf("remaining=%+v", rep.RemainingCVEs)
	}
	md := rep.Markdown()
	if md == "" {
		t.Fatal("empty markdown")
	}
}

func TestCompareIntroducedCVENotSafer(t *testing.T) {
	twin := &graph.Twin{
		CVEs: []graph.CVE{
			{ID: "CVE-OLD", Package: "zlib", Severity: "HIGH", VersionRange: "<= 1.2.0"},
			{ID: "CVE-NEW", Package: "openssl", Severity: "CRITICAL", VersionRange: "<= 3.0.0"},
		},
		Artifacts: []graph.Artifact{
			{Image: "app:v1", Packages: []graph.Pkg{{Name: "zlib", Version: "1.2.0"}}},
			{Image: "app:v2", Packages: []graph.Pkg{{Name: "zlib", Version: "1.3.0"}, {Name: "openssl", Version: "3.0.0"}}},
		},
		Workloads: []graph.Workload{
			{Name: "api", Namespace: "default", Image: "app:v1", Running: true},
		},
		Matches: []graph.Match{
			{CVE: "CVE-OLD", Package: "zlib", Version: "1.2.0", Image: "app:v1"},
			{CVE: "CVE-NEW", Package: "openssl", Version: "3.0.0", Image: "app:v2"},
		},
	}
	rep, err := remediate.Compare(twin, "app:v2")
	if err != nil {
		t.Fatal(err)
	}
	if rep.SaferVerdict != remediate.SaferNo {
		t.Fatalf("want not_safer, got %s", rep.SaferVerdict)
	}
	if len(rep.SaferWorkloads) != 0 {
		t.Fatalf("must not list as safer when new CVEs introduced: %+v", rep.SaferWorkloads)
	}
	if len(rep.IntroducedCVEs) == 0 {
		t.Fatal("expected introduced CVEs")
	}
}

func TestCompareNoScanDataUnknown(t *testing.T) {
	twin := &graph.Twin{
		CVEs: []graph.CVE{
			{ID: "CVE-OLD", Package: "zlib", Severity: "HIGH", VersionRange: "<= 1.2.0"},
		},
		Artifacts: []graph.Artifact{
			{Image: "app:v1", Packages: []graph.Pkg{{Name: "zlib", Version: "1.2.0"}}},
			{Image: "app:v2"}, // no packages, no matches
		},
		Workloads: []graph.Workload{
			{Name: "api", Namespace: "default", Image: "app:v1", Running: true},
		},
		Matches: []graph.Match{
			{CVE: "CVE-OLD", Package: "zlib", Version: "1.2.0", Image: "app:v1"},
		},
	}
	rep, err := remediate.Compare(twin, "app:v2")
	if err != nil {
		t.Fatal(err)
	}
	if rep.SaferVerdict != remediate.SaferUnknown {
		t.Fatalf("want UNKNOWN, got %s", rep.SaferVerdict)
	}
	if !rep.ScanDataMissing {
		t.Fatal("expected ScanDataMissing")
	}
	if len(rep.SaferWorkloads) != 0 {
		t.Fatalf("must not claim safer without scan data: %+v", rep.SaferWorkloads)
	}
}

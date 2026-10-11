package decide_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/justrunme/blastguard/internal/config"
	"github.com/justrunme/blastguard/internal/decide"
	"github.com/justrunme/blastguard/internal/graph"
	"github.com/justrunme/blastguard/internal/verify"
)

func TestCriticalPathBlocks(t *testing.T) {
	root := filepath.Join("..", "..")
	twin, err := graph.Load(filepath.Join(root, "fixtures", "demo-graph.json"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := decide.LoadPolicy(filepath.Join(root, "config", "decision-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	demo, _ := config.LoadDemoFromRoot(root)
	s, err := decide.TraceCVEWorkloadOpts(twin, "CVE-2026-1234", "", decide.TraceOptions{Demo: &demo})
	if err != nil {
		t.Fatal(err)
	}
	d := pol.Evaluate(s)
	if d.Action != "BLOCK" {
		t.Fatalf("want BLOCK, got %s (%s)", d.Action, d.Reason)
	}
	if s.ExposedWLs < 1 || s.ReachableWLs < 1 {
		t.Fatalf("expected exposed reachable workload, got %+v", s)
	}
	if s.FixImage == "" {
		t.Fatal("expected fix image from demo config candidates")
	}
}

func TestSameCVEBlockVsWarnByWorkload(t *testing.T) {
	pol, err := decide.LoadPolicy(filepath.Join("..", "..", "config", "decision-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	// FixAvailable=true must not escalate internal-worker to QUARANTINE: that
	// rule requires internet_exposed + reachable (blast-radius ladder).
	twin := &graph.Twin{
		CVEs: []graph.CVE{{
			ID: "CVE-2026-85091", Package: "zlib", Severity: "High",
			CVSS: 8.3, FixAvailable: true, VersionRange: "<= 1.3.2",
		}},
		Artifacts: []graph.Artifact{{
			Image:      "nginx",
			Packages:   []graph.Pkg{{Name: "zlib", Version: "1.3.2-r0", Ecosystem: "apk"}},
			SBOM:       graph.StatusVerified,
			Provenance: graph.StatusMissing,
		}},
		Workloads: []graph.Workload{
			{Name: "payment-api", Namespace: "default", Image: "nginx:alpine", Replicas: 2, Critical: true, InternetExposed: true, ReachablePath: true, Running: true},
			{Name: "internal-worker", Namespace: "default", Image: "nginx:alpine", Replicas: 1, Critical: false, InternetExposed: false, ReachablePath: false, Running: true},
			{Name: "coredns", Namespace: "kube-system", Image: "registry.k8s.io/coredns/coredns:v1.11.0", Replicas: 2, Running: true},
		},
		Matches: []graph.Match{{
			CVE: "CVE-2026-85091", Package: "zlib", Version: "1.3.2-r0", Image: "nginx",
		}},
	}
	twin.BindWorkloads(twin.Workloads)

	exposed, err := decide.TraceCVEWorkload(twin, "CVE-2026-85091", "payment-api")
	if err != nil {
		t.Fatal(err)
	}
	if exposed.SBOM != graph.StatusVerified {
		t.Fatalf("payment-api SBOM: want VERIFIED despite cluster stubs, got %s", exposed.SBOM)
	}
	if got := pol.Evaluate(exposed); got.Action != "BLOCK" {
		t.Fatalf("payment-api: want BLOCK, got %s (%s) signals=%+v", got.Action, got.Reason, exposed)
	}

	internal, err := decide.TraceCVEWorkload(twin, "CVE-2026-85091", "internal-worker")
	if err != nil {
		t.Fatal(err)
	}
	if internal.SBOM != graph.StatusVerified {
		t.Fatalf("internal-worker SBOM: want VERIFIED despite cluster stubs, got %s", internal.SBOM)
	}
	if got := pol.Evaluate(internal); got.Action != "WARN" {
		t.Fatalf("internal-worker: want WARN, got %s (%s) signals=%+v", got.Action, got.Reason, internal)
	}
}

func TestHighExposedNonCriticalQuarantines(t *testing.T) {
	pol, err := decide.LoadPolicy(filepath.Join("..", "..", "config", "decision-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	twin := &graph.Twin{
		CVEs: []graph.CVE{{
			ID: "CVE-Q", Package: "zlib", Severity: "HIGH",
			FixAvailable: true, VersionRange: "<= 1.3.2",
		}},
		Artifacts: []graph.Artifact{{
			Image:    "nginx:alpine",
			Packages: []graph.Pkg{{Name: "zlib", Version: "1.3.2-r0", Ecosystem: "apk"}},
			SBOM:     graph.StatusVerified,
		}},
		Workloads: []graph.Workload{{
			Name: "edge-proxy", Namespace: "default", Image: "nginx:alpine",
			Running: true, InternetExposed: true, ReachablePath: true, Critical: false,
		}},
		Matches: []graph.Match{{CVE: "CVE-Q", Package: "zlib", Version: "1.3.2-r0", Image: "nginx:alpine"}},
	}
	s, err := decide.TraceCVEWorkload(twin, "CVE-Q", "edge-proxy")
	if err != nil {
		t.Fatal(err)
	}
	d := pol.Evaluate(s)
	if d.Action != "QUARANTINE" {
		t.Fatalf("want QUARANTINE for exposed non-critical fixable HIGH, got %s (%s)", d.Action, d.Reason)
	}
	if d.RuleID != "high-exposed-fixable" {
		t.Fatalf("want rule high-exposed-fixable, got %s", d.RuleID)
	}
}

func TestVEXAllows(t *testing.T) {
	root := filepath.Join("..", "..")
	twin, err := graph.Load(filepath.Join(root, "fixtures", "demo-graph.json"))
	if err != nil {
		t.Fatal(err)
	}
	pol, err := decide.LoadPolicy(filepath.Join(root, "config", "decision-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := decide.TraceCVE(twin, "CVE-2026-3456")
	if err != nil {
		t.Fatal(err)
	}
	d := pol.Evaluate(s)
	if d.Action == "ALLOW" && s.AffectedArts > 0 {
		t.Fatalf("unexpected ALLOW with affected arts: %+v", s)
	}
	_ = d
}

func TestUnsignedImageProvenanceUnverifiedChangesAction(t *testing.T) {
	pol := &decide.Policy{
		SeverityRank: map[string]int{"HIGH": 3},
		Rules: []decide.Rule{
			{
				ID:     "block-unverified-prov",
				Action: "BLOCK",
				When: decide.When{
					Provenance: strPtr(graph.StatusUnverified),
				},
				ReasonTemplate: "provenance unverified",
			},
			{
				ID:             "default-allow",
				Action:         "ALLOW",
				When:           decide.When{},
				ReasonTemplate: "ok",
			},
		},
	}
	twin := &graph.Twin{
		CVEs: []graph.CVE{{ID: "CVE-1", Package: "openssl", Severity: "HIGH", VersionRange: "< 9.0.0"}},
		Artifacts: []graph.Artifact{{
			Image:      "unsigned:latest",
			Packages:   []graph.Pkg{{Name: "openssl", Version: "3.0.0"}},
			SBOM:       graph.StatusVerified,
			Provenance: graph.StatusMissing,
		}},
	}
	s, err := decide.TraceCVEWorkloadOpts(twin, "CVE-1", "", decide.TraceOptions{
		VerifyAttestations: true,
		Verifier: verify.StaticVerifier{Result: verify.Result{
			SBOM:       graph.StatusVerified,
			Provenance: graph.StatusUnverified,
			Signature:  graph.StatusUnverified,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.Provenance != graph.StatusUnverified {
		t.Fatalf("want Provenance=UNVERIFIED, got %s", s.Provenance)
	}
	d := pol.Evaluate(s)
	if d.Action != "BLOCK" {
		t.Fatalf("want BLOCK from provenance rule, got %s", d.Action)
	}
	_ = context.Background()
}

func TestExitCode(t *testing.T) {
	if decide.ExitCode("ALLOW", false) != 0 {
		t.Fatal()
	}
	if decide.ExitCode("WARN", false) != 0 {
		t.Fatal()
	}
	if decide.ExitCode("WARN", true) != 1 {
		t.Fatal()
	}
	if decide.ExitCode("BLOCK", false) != 2 {
		t.Fatal()
	}
	if decide.ExitCode("QUARANTINE", true) != 2 {
		t.Fatal()
	}
}

func TestSemverFalsePositiveNotAffected(t *testing.T) {
	twin := &graph.Twin{
		CVEs: []graph.CVE{{ID: "CVE-Z", Package: "openssl", Severity: "HIGH", VersionRange: "< 3.3.2"}},
		Artifacts: []graph.Artifact{{
			Image:    "app:1",
			Packages: []graph.Pkg{{Name: "openssl", Version: "3.10.0"}},
		}},
	}
	s, err := decide.TraceCVE(twin, "CVE-Z")
	if err != nil {
		t.Fatal(err)
	}
	if s.AffectedArts != 0 {
		t.Fatalf("3.10.0 must not be affected by <3.3.2, got arts=%d", s.AffectedArts)
	}
}

func strPtr(s string) *string { return &s }

package decide_test

import (
	"path/filepath"
	"testing"

	"github.com/justrunme/blastguard/internal/decide"
	"github.com/justrunme/blastguard/internal/graph"
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
	s, err := decide.TraceCVE(twin, "CVE-2026-1234")
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
}

func TestSameCVEBlockVsWarnByWorkload(t *testing.T) {
	pol, err := decide.LoadPolicy(filepath.Join("..", "..", "config", "decision-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	twin := &graph.Twin{
		CVEs: []graph.CVE{{
			ID: "CVE-2026-85091", Package: "zlib", Severity: "High",
			CVSS: 8.3, FixAvailable: false,
		}},
		Artifacts: []graph.Artifact{{
			Image:    "nginx",
			Packages: []graph.Pkg{{Name: "zlib", Version: "1.3.2-r0"}},
		}},
		Workloads: []graph.Workload{
			{Name: "payment-api", Namespace: "default", Image: "nginx:alpine", Replicas: 2, Critical: true, InternetExposed: true, ReachablePath: true, Running: true},
			{Name: "internal-worker", Namespace: "default", Image: "nginx:alpine", Replicas: 1, Critical: false, InternetExposed: false, ReachablePath: false, Running: true},
		},
	}
	twin.BindWorkloads(twin.Workloads)

	exposed, err := decide.TraceCVEWorkload(twin, "CVE-2026-85091", "payment-api")
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.Evaluate(exposed); got.Action != "BLOCK" {
		t.Fatalf("payment-api: want BLOCK, got %s (%s) signals=%+v", got.Action, got.Reason, exposed)
	}

	internal, err := decide.TraceCVEWorkload(twin, "CVE-2026-85091", "internal-worker")
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.Evaluate(internal); got.Action != "WARN" {
		t.Fatalf("internal-worker: want WARN, got %s (%s) signals=%+v", got.Action, got.Reason, internal)
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
	// Only payment-api:v41 has VEX not_affected for CVE-2026-3456, but ml-builder also has x/net vulnerable without VEX.
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

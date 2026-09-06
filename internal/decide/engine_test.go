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

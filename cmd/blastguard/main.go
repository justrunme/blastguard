package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/justrunme/blastguard/internal/cluster"
	"github.com/justrunme/blastguard/internal/decide"
	"github.com/justrunme/blastguard/internal/graph"
	"github.com/justrunme/blastguard/internal/ingest"
	"github.com/justrunme/blastguard/internal/render"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	root := findRoot()
	twinPath := filepath.Join(root, "fixtures", "demo-graph.json")
	policyPath := filepath.Join(root, "config", "decision-policy.json")

	switch os.Args[1] {
	case "ingest":
		runIngest(os.Args[2:])
	case "demo":
		cve := "CVE-2026-1234"
		if len(os.Args) > 2 {
			cve = os.Args[2]
		}
		runTrace(twinPath, policyPath, cve)
	case "rehearse":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: blastguard rehearse <CVE-ID|image> [ref]")
			os.Exit(2)
		}
		if strings.HasPrefix(os.Args[2], "CVE-") {
			runTrace(twinPath, policyPath, os.Args[2])
			return
		}
		if os.Args[2] == "image" {
			if len(os.Args) < 4 {
				fmt.Fprintln(os.Stderr, "usage: blastguard rehearse image <ref>")
				os.Exit(2)
			}
			runImageRehearse(twinPath, policyPath, os.Args[3])
			return
		}
		runImageRehearse(twinPath, policyPath, os.Args[2])
	case "prove":
		runProve(twinPath, policyPath)
	case "version":
		fmt.Println("blastguard 0.1.0")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`BlastGuard — Supply Chain Blast-Radius Control Plane

Don't count vulnerabilities. Predict their blast radius.

Usage:
  blastguard ingest [options]
  blastguard demo [CVE-ID]
  blastguard rehearse CVE-2026-1234
  blastguard rehearse image ghcr.io/justrunme/payment-api:v2
  blastguard prove

Commands:
  ingest       Build graph from SBOM, vulnerability reports, and VEX
               --sbom-cyclonedx <path>
               --sbom-spdx <path>
               --vulns-grype <path>
               --vulns-osv <path>
               --vex <path>
               --from-cluster (scan live Kubernetes cluster)
               --kubeconfig <path>
               --output <path>
               --policy <path>
               --trace <CVE-ID> (evaluate after ingestion)
               --workload <name> (scope --trace to one workload)

Discover → Trace → Decide → Enforce → Verify
`)
}

func findRoot() string {
	if v := os.Getenv("BLASTGUARD_ROOT"); v != "" {
		return v
	}
	wd, _ := os.Getwd()
	candidates := []string{wd, filepath.Join(wd, ".."), filepath.Join(wd, "../..")}
	exe, _ := os.Executable()
	if exe != "" {
		candidates = append(candidates, filepath.Dir(exe), filepath.Join(filepath.Dir(exe), ".."))
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "fixtures", "demo-graph.json")); err == nil {
			return c
		}
	}
	return wd
}

func runTrace(twinPath, policyPath, cve string) {
	t, err := graph.Load(twinPath)
	must(err)
	p, err := decide.LoadPolicy(policyPath)
	must(err)
	s, err := decide.TraceCVE(t, cve)
	must(err)
	d := p.Evaluate(s)
	fmt.Print(render.Card(d))
	writeEvidence(filepath.Join(filepath.Dir(twinPath), "..", ".evidence"), d)
}

func runProve(twinPath, policyPath string) {
	t, err := graph.Load(twinPath)
	must(err)
	p, err := decide.LoadPolicy(policyPath)
	must(err)

	beforeSig, err := decide.TraceCVE(t, "CVE-2026-1234")
	must(err)
	before := p.Evaluate(beforeSig)

	// Simulate fleet remediation: bump openssl across artifacts + move workloads to fixed images.
	patched := *t
	arts := make([]graph.Artifact, len(t.Artifacts))
	copy(arts, t.Artifacts)
	for i := range arts {
		pkgs := make([]graph.Pkg, len(arts[i].Packages))
		copy(pkgs, arts[i].Packages)
		for j := range pkgs {
			if pkgs[j].Name == "openssl" {
				pkgs[j].Version = "3.3.2"
			}
		}
		arts[i].Packages = pkgs
	}
	patched.Artifacts = arts
	wls := make([]graph.Workload, len(t.Workloads))
	copy(wls, t.Workloads)
	for i := range wls {
		if wls[i].Name == "payment-api" {
			wls[i].Image = "ghcr.io/justrunme/payment-api:v42"
		}
	}
	patched.Workloads = wls
	afterSig, err := decide.TraceCVE(&patched, "CVE-2026-1234")
	must(err)
	after := p.Evaluate(afterSig)
	fmt.Print(render.Remediation(before, after))
}

func runImageRehearse(twinPath, policyPath, image string) {
	t, err := graph.Load(twinPath)
	must(err)
	p, err := decide.LoadPolicy(policyPath)
	must(err)

	art := t.Artifact(image)
	lines := []string{"──────────────────────────────"}
	if art == nil {
		lines = append(lines, "Image not in twin fixtures — treating as unknown proposed artifact")
		lines = append(lines, "POLICY", "⚠ WARN", "Reason: unknown image; rehearse requires SBOM attachment")
		fmt.Print(render.RehearseImage(image, lines))
		return
	}

	newCVEs := 0
	var decisions []decide.Decision
	for _, cve := range t.CVEs {
		if !graph.PackageAffected(art, &cve) {
			continue
		}
		newCVEs++
		// Project runtime as if this image replaced payment-api in prod
		proj := *t
		wls := make([]graph.Workload, len(t.Workloads))
		copy(wls, t.Workloads)
		for i := range wls {
			if wls[i].Name == "payment-api" {
				wls[i].Image = image
			}
		}
		proj.Workloads = wls
		s, err := decide.TraceCVE(&proj, cve.ID)
		must(err)
		// annotate VEX
		if t.VEXStatus(cve.ID, image) == "not_affected" {
			s.VEXNotAffected = true
			lines = append(lines, fmt.Sprintf("%s\n  VEX: not_affected", cve.ID))
		} else if s.ReachablePath && s.InternetExposed {
			lines = append(lines, fmt.Sprintf("%s\n  reachable → ingress → API", cve.ID))
		} else {
			lines = append(lines, fmt.Sprintf("%s\n  present but not reachable", cve.ID))
		}
		decisions = append(decisions, p.Evaluate(s))
	}

	action := "ALLOW"
	reason := "no new reachable HIGH vulnerability"
	for _, d := range decisions {
		if d.Action == "BLOCK" {
			action = "BLOCK"
			reason = d.Reason
			break
		}
		if d.Action == "QUARANTINE" && action != "BLOCK" {
			action = "QUARANTINE"
			reason = d.Reason
		}
		if d.Action == "WARN" && action == "ALLOW" {
			action = "WARN"
			reason = d.Reason
		}
	}

	lines = append(lines,
		fmt.Sprintf("New CVEs                    %d", newCVEs),
		"POLICY",
		fmt.Sprintf("%s %s", map[string]string{"BLOCK": "●", "QUARANTINE": "●", "WARN": "⚠", "ALLOW": "✓"}[action], action),
		"Reason:",
		"  "+reason,
	)
	fmt.Print(render.RehearseImage(image, lines))
}

func writeEvidence(dir string, d decide.Decision) {
	_ = os.MkdirAll(dir, 0o755)
	b, _ := json.MarshalIndent(d, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "decision-latest.json"), b, 0o644)
}

func runIngest(args []string) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	sbomCDX := fs.String("sbom-cyclonedx", "", "CycloneDX SBOM JSON file")
	sbomSPDX := fs.String("sbom-spdx", "", "SPDX SBOM JSON file")
	vulnsGrype := fs.String("vulns-grype", "", "Grype vulnerability JSON report")
	vulnsOSV := fs.String("vulns-osv", "", "OSV-Scanner vulnerability JSON report")
	vexFile := fs.String("vex", "", "OpenVEX document")
	fromCluster := fs.Bool("from-cluster", false, "Scan live Kubernetes cluster")
	kubeconfig := fs.String("kubeconfig", "", "Path to kubeconfig")
	output := fs.String("output", "", "Output twin JSON file")
	policyPath := fs.String("policy", "", "Policy file for evaluation")
	traceCVE := fs.String("trace", "", "CVE to trace after ingestion")
	workload := fs.String("workload", "", "Scope --trace to a single workload name")

	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	builder := ingest.NewBuilder()

	if *sbomCDX != "" {
		must(builder.IngestCycloneDX(*sbomCDX))
		fmt.Fprintf(os.Stderr, "✓ Ingested CycloneDX SBOM from %s\n", *sbomCDX)
	}

	if *sbomSPDX != "" {
		must(builder.IngestSPDX(*sbomSPDX))
		fmt.Fprintf(os.Stderr, "✓ Ingested SPDX SBOM from %s\n", *sbomSPDX)
	}

	if *vulnsGrype != "" {
		must(builder.IngestGrype(*vulnsGrype))
		fmt.Fprintf(os.Stderr, "✓ Ingested Grype vulnerabilities from %s\n", *vulnsGrype)
	}

	if *vulnsOSV != "" {
		must(builder.IngestOSV(*vulnsOSV))
		fmt.Fprintf(os.Stderr, "✓ Ingested OSV-Scanner vulnerabilities from %s\n", *vulnsOSV)
	}

	if *vexFile != "" {
		must(builder.IngestVEX(*vexFile))
		fmt.Fprintf(os.Stderr, "✓ Ingested VEX statements from %s\n", *vexFile)
	}

	twin := builder.Build()

	if *fromCluster {
		scanner, err := cluster.NewScanner(*kubeconfig)
		must(err)
		workloads, err := scanner.ScanCluster(context.Background())
		must(err)
		twin.BindWorkloads(workloads)
		fmt.Fprintf(os.Stderr, "✓ Scanned cluster: %d workloads\n", len(workloads))
	}

	if *output != "" {
		b, err := json.MarshalIndent(twin, "", "  ")
		must(err)
		must(os.WriteFile(*output, b, 0o644))
		fmt.Fprintf(os.Stderr, "✓ Wrote twin to %s\n", *output)
	} else {
		b, err := json.MarshalIndent(twin, "", "  ")
		must(err)
		fmt.Println(string(b))
	}

	if *traceCVE != "" && *policyPath != "" {
		p, err := decide.LoadPolicy(*policyPath)
		must(err)
		s, err := decide.TraceCVEWorkload(twin, *traceCVE, *workload)
		must(err)
		d := p.Evaluate(s)
		fmt.Fprintln(os.Stderr, "\n── Decision ──")
		if *workload != "" {
			fmt.Fprintf(os.Stderr, "workload=%s\n", *workload)
		}
		fmt.Fprint(os.Stderr, render.Card(d))
		fmt.Fprintf(os.Stderr, "DECISION %s workload=%s cve=%s\n", d.Action, *workload, *traceCVE)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

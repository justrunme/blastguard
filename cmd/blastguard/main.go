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
	"github.com/justrunme/blastguard/internal/config"
	"github.com/justrunme/blastguard/internal/decide"
	"github.com/justrunme/blastguard/internal/graph"
	"github.com/justrunme/blastguard/internal/ingest"
	"github.com/justrunme/blastguard/internal/remediate"
	"github.com/justrunme/blastguard/internal/render"
	"github.com/justrunme/blastguard/internal/runtime"
	"github.com/justrunme/blastguard/internal/verify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	root := findRoot()
	twinPath := filepath.Join(root, "fixtures", "demo-graph.json")
	policyPath := filepath.Join(root, "config", "decision-policy.json")
	demo, _ := config.LoadDemoFromRoot(root)

	switch os.Args[1] {
	case "ingest":
		runIngest(os.Args[2:], root, demo)
	case "demo":
		fs := flag.NewFlagSet("demo", flag.ExitOnError)
		output := fs.String("output", "text", "Output format: text|json")
		failOn := fs.String("fail-on", "", "Fail on warn|block (block is always exit 2)")
		verifyAtt := fs.Bool("verify-attestations", false, "Run cosign verify-attestation for images")
		_ = fs.Parse(flagsFirst(os.Args[2:]))
		cve := "CVE-2026-1234"
		for _, a := range fs.Args() {
			if strings.HasPrefix(a, "CVE-") {
				cve = a
				break
			}
		}
		code := runTrace(twinPath, policyPath, cve, demo, *output, *failOn, *verifyAtt)
		os.Exit(code)
	case "rehearse":
		code := runRehearse(flagsFirst(os.Args[2:]), twinPath, policyPath, demo)
		os.Exit(code)
	case "remediate":
		os.Exit(runRemediate(flagsFirst(os.Args[2:]), twinPath))
	case "prove":
		fs := flag.NewFlagSet("prove", flag.ExitOnError)
		output := fs.String("output", "text", "Output format: text|json")
		_ = fs.Parse(flagsFirst(os.Args[2:]))
		runProve(twinPath, policyPath, demo, *output)
	case "version":
		fmt.Println("blastguard 0.2.0")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

// flagsFirst moves -flag and --flag[=val] args ahead of positionals so the
// standard library flag parser accepts "cmd CVE-… --output json".
func flagsFirst(args []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			// boolean flags have no following value; ones with = already inline.
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				// Treat next token as value unless this looks like a bool switch
				// we know about. Safer: always take next when it doesn't look like CVE-/path.
				next := args[i+1]
				name := strings.TrimLeft(a, "-")
				if name == "verify-attestations" || name == "from-cluster" || name == "h" || name == "help" {
					continue
				}
				flags = append(flags, next)
				i++
			}
			continue
		}
		rest = append(rest, a)
	}
	return append(flags, rest...)
}

func usage() {
	fmt.Print(`BlastGuard — Supply Chain Blast-Radius Control Plane

Don't count vulnerabilities. Predict their blast radius.

Usage:
  blastguard ingest [options]
  blastguard demo [CVE-ID] [--output text|json] [--fail-on warn|block] [--verify-attestations]
  blastguard rehearse CVE-2026-1234 [--output json] [--fail-on warn]
  blastguard rehearse image <ref> [--workload <name>] [--output json]
  blastguard prove [--output json]
  blastguard remediate --image <new> [--twin <path>] [--output md|json]

Exit codes (decision commands / ingest --trace):
  0  ALLOW (WARN also exits 0 unless --fail-on warn)
  1  WARN when --fail-on warn; UNKNOWN (incomplete inventory)
  2  BLOCK or QUARANTINE

Commands:
  ingest       Build graph from SBOM, vulnerability reports, and VEX
               --sbom-cyclonedx <path>
               --sbom-spdx <path>
               --vulns-grype <path>
               --vulns-osv <path>
               --vex <path> (OpenVEX file)
               --vex-attestation <image> (OCI OpenVEX via cosign; requires trust material)
               --key <path> | --certificate-identity + --certificate-oidc-issuer
               --runtime-evidence <path> (optional blastguard.runtime_evidence/v1)
               --from-cluster (scan live Kubernetes cluster)
               --kubeconfig <path>
               --output <path|json> (twin file path, or "json" with --trace for decision JSON)
               --policy <path>
               --trace <CVE-ID> (evaluate after ingestion)
               --workload <name> (scope --trace to one workload)
               --fail-on warn|block
               --verify-attestations

  remediate    Impact report for rolling live workloads to --image
               --image <ref> (proposed image already in twin)
               --twin <path>
               --output md|json

Discover → Trace → Decide → Enforce (CI exit codes) → Verify
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

func runTrace(twinPath, policyPath, cve string, demo config.Demo, output, failOn string, verifyAtt bool) int {
	t, err := graph.Load(twinPath)
	must(err)
	p, err := decide.LoadPolicy(policyPath)
	must(err)
	opts := decide.TraceOptions{Demo: &demo, VerifyAttestations: verifyAtt}
	if verifyAtt {
		opts.Verifier = verify.Default()
	}
	s, err := decide.TraceCVEWorkloadOpts(t, cve, "", opts)
	must(err)
	d := p.Evaluate(s)
	emitDecision(d, output)
	writeEvidence(filepath.Join(filepath.Dir(twinPath), "..", ".evidence"), d)
	return decide.ExitCode(d.Action, strings.EqualFold(failOn, "warn"))
}

func runProve(twinPath, policyPath string, demo config.Demo, output string) {
	t, err := graph.Load(twinPath)
	must(err)
	p, err := decide.LoadPolicy(policyPath)
	must(err)

	cveID := demo.Remediation.CVE
	if cveID == "" {
		cveID = "CVE-2026-1234"
	}
	pkg := demo.Remediation.Package
	if pkg == "" {
		pkg = "openssl"
	}
	fixed := demo.Remediation.FixedVersion
	if fixed == "" {
		fixed = "3.3.2"
	}

	beforeSig, err := decide.TraceCVEWorkloadOpts(t, cveID, "", decide.TraceOptions{Demo: &demo})
	must(err)
	before := p.Evaluate(beforeSig)

	patched := *t
	arts := make([]graph.Artifact, len(t.Artifacts))
	copy(arts, t.Artifacts)
	for i := range arts {
		pkgs := make([]graph.Pkg, len(arts[i].Packages))
		copy(pkgs, arts[i].Packages)
		for j := range pkgs {
			if pkgs[j].Name == pkg {
				pkgs[j].Version = fixed
			}
		}
		arts[i].Packages = pkgs
	}
	patched.Artifacts = arts
	wls := make([]graph.Workload, len(t.Workloads))
	copy(wls, t.Workloads)
	for i := range wls {
		if img, ok := demo.Remediation.WorkloadImageUpdates[wls[i].Name]; ok {
			wls[i].Image = img
		}
	}
	patched.Workloads = wls
	// Clear scanner matches so range evaluation uses bumped versions.
	patched.Matches = nil
	afterSig, err := decide.TraceCVEWorkloadOpts(&patched, cveID, "", decide.TraceOptions{Demo: &demo})
	must(err)
	after := p.Evaluate(afterSig)
	if strings.EqualFold(output, "json") {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"before": before, "after": after})
		return
	}
	fmt.Print(render.Remediation(before, after))
}

func runRehearse(args []string, twinPath, policyPath string, demo config.Demo) int {
	fs := flag.NewFlagSet("rehearse", flag.ExitOnError)
	output := fs.String("output", "text", "Output format: text|json")
	failOn := fs.String("fail-on", "", "Fail on warn|block")
	workload := fs.String("workload", "", "Workload to project the image onto (default from config/demo.json)")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: blastguard rehearse <CVE-ID|image> [ref]")
		return 2
	}
	if strings.HasPrefix(rest[0], "CVE-") {
		return runTrace(twinPath, policyPath, rest[0], demo, *output, *failOn, false)
	}
	image := rest[0]
	if image == "image" {
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: blastguard rehearse image <ref>")
			return 2
		}
		image = rest[1]
	}
	wl := *workload
	if wl == "" {
		wl = demo.DefaultWorkload
	}
	return runImageRehearse(twinPath, policyPath, image, wl, demo, *output, *failOn)
}

func runImageRehearse(twinPath, policyPath, image, workload string, demo config.Demo, output, failOn string) int {
	t, err := graph.Load(twinPath)
	must(err)
	p, err := decide.LoadPolicy(policyPath)
	must(err)

	art := t.Artifact(image)
	lines := []string{"──────────────────────────────"}
	if art == nil {
		lines = append(lines, "Image not in twin fixtures — treating as unknown proposed artifact")
		lines = append(lines, "POLICY", "⚠ WARN", "Reason: unknown image; rehearse requires SBOM attachment")
		if strings.EqualFold(output, "json") {
			d := decide.Decision{Action: "WARN", RuleID: "unknown-image", Reason: "unknown image; rehearse requires SBOM attachment"}
			emitDecision(d, "json")
			return decide.ExitCode(d.Action, strings.EqualFold(failOn, "warn"))
		}
		fmt.Print(render.RehearseImage(image, lines))
		return decide.ExitCode("WARN", strings.EqualFold(failOn, "warn"))
	}

	newCVEs := 0
	var decisions []decide.Decision
	for _, cve := range t.CVEs {
		if !graph.TwinPackageAffected(t, art, &cve) {
			continue
		}
		newCVEs++
		proj := *t
		wls := make([]graph.Workload, len(t.Workloads))
		copy(wls, t.Workloads)
		for i := range wls {
			if wls[i].Name == workload {
				wls[i].Image = image
			}
		}
		proj.Workloads = wls
		s, err := decide.TraceCVEWorkloadOpts(&proj, cve.ID, "", decide.TraceOptions{Demo: &demo})
		must(err)
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

	if strings.EqualFold(output, "json") {
		emitDecision(decide.Decision{Action: action, Reason: reason, Signals: decide.Signals{FixImage: image, AffectedArts: newCVEs}}, "json")
		return decide.ExitCode(action, strings.EqualFold(failOn, "warn"))
	}

	lines = append(lines,
		fmt.Sprintf("New CVEs                    %d", newCVEs),
		"POLICY",
		fmt.Sprintf("%s %s", map[string]string{"BLOCK": "●", "QUARANTINE": "●", "WARN": "⚠", "ALLOW": "✓"}[action], action),
		"Reason:",
		"  "+reason,
	)
	fmt.Print(render.RehearseImage(image, lines))
	return decide.ExitCode(action, strings.EqualFold(failOn, "warn"))
}

func emitDecision(d decide.Decision, output string) {
	if strings.EqualFold(output, "json") {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(d)
		return
	}
	fmt.Print(render.Card(d))
}

func writeEvidence(dir string, d decide.Decision) {
	_ = os.MkdirAll(dir, 0o755)
	b, _ := json.MarshalIndent(d, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "decision-latest.json"), b, 0o644)
}

func runIngest(args []string, root string, demo config.Demo) {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	sbomCDX := fs.String("sbom-cyclonedx", "", "CycloneDX SBOM JSON file")
	sbomSPDX := fs.String("sbom-spdx", "", "SPDX SBOM JSON file")
	vulnsGrype := fs.String("vulns-grype", "", "Grype vulnerability JSON report")
	vulnsOSV := fs.String("vulns-osv", "", "OSV-Scanner vulnerability JSON report")
	vexFile := fs.String("vex", "", "OpenVEX document")
	vexAttestation := fs.String("vex-attestation", "", "Image ref to fetch+verify OpenVEX attestation from (OCI)")
	cosignKey := fs.String("key", "", "Cosign public key for --vex-attestation (or set COSIGN_KEY)")
	certIdentity := fs.String("certificate-identity", "", "Expected certificate identity for --vex-attestation")
	certIdentityRegexp := fs.String("certificate-identity-regexp", "", "Expected certificate identity regexp for --vex-attestation")
	certOIDCIssuer := fs.String("certificate-oidc-issuer", "", "Expected OIDC issuer for --vex-attestation")
	runtimeEvidence := fs.String("runtime-evidence", "", "Optional runtime evidence JSON (blastguard.runtime_evidence/v1)")
	fromCluster := fs.Bool("from-cluster", false, "Scan live Kubernetes cluster")
	kubeconfig := fs.String("kubeconfig", "", "Path to kubeconfig")
	output := fs.String("output", "", "Output twin JSON file, or 'json' to emit decision JSON with --trace")
	policyPath := fs.String("policy", "", "Policy file for evaluation")
	traceCVE := fs.String("trace", "", "CVE to trace after ingestion")
	workload := fs.String("workload", "", "Scope --trace to a single workload name")
	failOn := fs.String("fail-on", "", "Exit 1 on WARN when set to warn; BLOCK/QUARANTINE always exit 2")
	verifyAtt := fs.Bool("verify-attestations", false, "Run cosign verify-attestation per artifact")
	decisionOut := fs.String("decision-output", "text", "Decision format when tracing: text|json")

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

	twin := builder.Build()

	if *fromCluster {
		scanner, err := cluster.NewScanner(*kubeconfig)
		must(err)
		workloads, err := scanner.ScanCluster(context.Background())
		must(err)
		twin.BindWorkloads(workloads)
		fmt.Fprintf(os.Stderr, "✓ Scanned cluster: %d workloads\n", len(workloads))
	}

	// OpenVEX after artifacts/workloads exist so digest binding can match.
	if *vexAttestation != "" {
		key := *cosignKey
		if key == "" {
			key = os.Getenv("COSIGN_KEY")
		}
		cv := &verify.CosignVerifier{
			KeyPath:                   key,
			CertificateIdentity:       *certIdentity,
			CertificateIdentityRegexp: *certIdentityRegexp,
			CertificateOIDCIssuer:     *certOIDCIssuer,
		}
		res := cv.VerifyOpenVEX(context.Background(), *vexAttestation)
		// Fail closed: never apply an unverified payload.
		if res.Status != graph.StatusVerified || len(res.Payload) == 0 {
			fmt.Fprintf(os.Stderr, "openvex attestation verify failed for %s: %s (%s)\n", *vexAttestation, res.Status, res.Detail)
			os.Exit(1)
		}
		before := len(twin.VEX)
		warns, err := ingest.ApplyOpenVEXBytes(twin, res.Payload)
		must(err)
		for _, w := range warns {
			fmt.Fprintf(os.Stderr, "⚠ %s\n", w)
		}
		applied := len(twin.VEX) - before
		fmt.Fprintf(os.Stderr, "✓ Applied OpenVEX attestation from %s: %d statement(s) accepted (%d in predicate)\n",
			*vexAttestation, applied, res.Statements)
	}
	if *vexFile != "" {
		warns, err := ingest.ApplyOpenVEX(twin, *vexFile)
		must(err)
		for _, w := range warns {
			fmt.Fprintf(os.Stderr, "⚠ %s\n", w)
		}
		fmt.Fprintf(os.Stderr, "✓ Applied OpenVEX from %s\n", *vexFile)
	}

	writeTwin := *output
	decisionJSON := false
	if strings.EqualFold(writeTwin, "json") {
		decisionJSON = true
		writeTwin = ""
		*decisionOut = "json"
	}

	if writeTwin != "" {
		b, err := json.MarshalIndent(twin, "", "  ")
		must(err)
		must(os.WriteFile(writeTwin, b, 0o644))
		fmt.Fprintf(os.Stderr, "✓ Wrote twin to %s\n", writeTwin)
	} else if *traceCVE == "" || !decisionJSON {
		b, err := json.MarshalIndent(twin, "", "  ")
		must(err)
		fmt.Println(string(b))
	}

	if *traceCVE != "" && *policyPath != "" {
		p, err := decide.LoadPolicy(*policyPath)
		must(err)
		opts := decide.TraceOptions{Demo: &demo, VerifyAttestations: *verifyAtt}
		if *verifyAtt {
			opts.Verifier = verify.Default()
		}
		if *runtimeEvidence != "" {
			doc, err := runtime.Load(*runtimeEvidence)
			must(err)
			opts.RuntimeEvidence = doc
		}
		s, err := decide.TraceCVEWorkloadOpts(twin, *traceCVE, *workload, opts)
		must(err)
		d := p.Evaluate(s)
		fmt.Fprintln(os.Stderr, "\n── Decision ──")
		if *workload != "" {
			fmt.Fprintf(os.Stderr, "workload=%s\n", *workload)
		}
		if strings.EqualFold(*decisionOut, "json") {
			emitDecision(d, "json")
		} else {
			fmt.Fprint(os.Stderr, render.Card(d))
		}
		fmt.Fprintf(os.Stderr, "DECISION %s workload=%s cve=%s\n", d.Action, *workload, *traceCVE)
		os.Exit(decide.ExitCode(d.Action, strings.EqualFold(*failOn, "warn")))
	}
	_ = root
}

func runRemediate(args []string, defaultTwin string) int {
	fs := flag.NewFlagSet("remediate", flag.ExitOnError)
	image := fs.String("image", "", "Proposed image ref (must already be in twin)")
	twinPath := fs.String("twin", defaultTwin, "Twin JSON path")
	output := fs.String("output", "md", "Output format: md|json")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if *image == "" {
		fmt.Fprintln(os.Stderr, "remediate: --image is required")
		return 2
	}
	t, err := graph.Load(*twinPath)
	must(err)
	rep, err := remediate.Compare(t, *image)
	must(err)
	if strings.EqualFold(*output, "json") {
		b, err := rep.JSON()
		must(err)
		fmt.Println(string(b))
	} else {
		fmt.Print(rep.Markdown())
	}
	return 0
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

package decide

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/justrunme/blastguard/internal/config"
	"github.com/justrunme/blastguard/internal/graph"
	"github.com/justrunme/blastguard/internal/openvex"
	"github.com/justrunme/blastguard/internal/runtime"
	"github.com/justrunme/blastguard/internal/verify"
)

type When struct {
	SeverityAtLeast *string `json:"severity_at_least"`
	Running         *bool   `json:"running"`
	InternetExposed *bool   `json:"internet_exposed"`
	ReachablePath   *bool   `json:"reachable_path"`
	CriticalService *bool   `json:"critical_service"`
	VEXNotAffected  *bool   `json:"vex_not_affected"`
	FixAvailable    *bool   `json:"fix_available"`
	Provenance      *string `json:"provenance"`
}

type Rule struct {
	ID             string `json:"id"`
	Action         string `json:"action"`
	When           When   `json:"when"`
	ReasonTemplate string `json:"reason_template"`
}

type Policy struct {
	Version      int            `json:"version"`
	Name         string         `json:"name"`
	Tagline      string         `json:"tagline"`
	Lifecycle    string         `json:"lifecycle"`
	Rules        []Rule         `json:"rules"`
	SeverityRank map[string]int `json:"severity_rank"`
	Actions      []string       `json:"actions"`
}

type Signals struct {
	CVE             string   `json:"cve"`
	Package         string   `json:"package"`
	Severity        string   `json:"severity"`
	CVSS            float64  `json:"cvss"`
	EPSS            float64  `json:"epss"`
	FixAvailable    bool     `json:"fix_available"`
	Running         bool     `json:"running"`
	InternetExposed bool     `json:"internet_exposed"`
	ReachablePath   bool     `json:"reachable_path"`
	CriticalService bool     `json:"critical_service"`
	VEXNotAffected  bool     `json:"vex_not_affected"`
	VEXStatus       string   `json:"vex_status,omitempty"`
	AffectedArts    int      `json:"affected_artifacts"`
	RunningWLs      int      `json:"running_workloads"`
	ExposedWLs      int      `json:"exposed_workloads"`
	ReachableWLs    int      `json:"reachable_workloads"`
	CriticalPath    []string `json:"critical_path"`
	SBOM            string   `json:"sbom"`
	Provenance      string   `json:"provenance"`
	FixImage        string   `json:"fix_image,omitempty"`

	// Reachability triad — TRUE|FALSE|UNKNOWN. Missing evidence is UNKNOWN.
	// ExecutionObserved never yields ALLOW by itself; observed != exploitable.
	PackagePresent    string `json:"package_present"`
	NetworkReachable  string `json:"network_reachable"`
	ExecutionObserved string `json:"execution_observed"`
}

type Decision struct {
	Action  string  `json:"action"`
	RuleID  string  `json:"rule_id"`
	Reason  string  `json:"reason"`
	Signals Signals `json:"signals"`
}

// TraceOptions controls optional attestation verification and fix lookup.
type TraceOptions struct {
	Verifier           verify.Verifier
	Demo               *config.Demo
	VerifyAttestations bool
	// RuntimeEvidence is optional Tetragon/Falco export (see runtime.Document).
	RuntimeEvidence *runtime.Document
}

func LoadPolicy(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) rank(sev string) int {
	if p.SeverityRank == nil {
		return 0
	}
	return p.SeverityRank[strings.ToUpper(strings.TrimSpace(sev))]
}

func matchBool(want *bool, have bool) bool {
	if want == nil {
		return true
	}
	return *want == have
}

func matchString(want *string, have string) bool {
	if want == nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(*want), strings.TrimSpace(have))
}

func (p *Policy) Evaluate(s Signals) Decision {
	// under_investigation keeps WARN (never ALLOW via empty blast radius alone).
	underInvest := strings.EqualFold(s.VEXStatus, openvex.StatusUnderInvestigation)

	if s.AffectedArts == 0 && s.RunningWLs == 0 && !s.VEXNotAffected && !underInvest {
		if s.CVE != "" && s.Package != "" {
			return Decision{Action: "ALLOW", RuleID: "no-blast-radius", Reason: "no affected artifacts remain in the twin", Signals: s}
		}
	}
	if s.VEXNotAffected && s.AffectedArts == 0 {
		return Decision{Action: "ALLOW", RuleID: "vex-clear", Reason: "VEX asserts not_affected for this artifact", Signals: s}
	}
	if underInvest {
		return Decision{Action: "WARN", RuleID: "vex-under-investigation", Reason: "VEX status under_investigation — keep WARN until resolved", Signals: s}
	}
	for _, r := range p.Rules {
		w := r.When
		if w.SeverityAtLeast != nil && p.rank(s.Severity) < p.rank(*w.SeverityAtLeast) {
			continue
		}
		if !matchBool(w.Running, s.Running) {
			continue
		}
		if !matchBool(w.InternetExposed, s.InternetExposed) {
			continue
		}
		if !matchBool(w.ReachablePath, s.ReachablePath) {
			continue
		}
		if !matchBool(w.CriticalService, s.CriticalService) {
			continue
		}
		if !matchBool(w.VEXNotAffected, s.VEXNotAffected) {
			continue
		}
		if !matchBool(w.FixAvailable, s.FixAvailable) {
			continue
		}
		if !matchString(w.Provenance, s.Provenance) {
			continue
		}
		return Decision{Action: r.Action, RuleID: r.ID, Reason: r.ReasonTemplate, Signals: s}
	}
	return Decision{Action: "WARN", RuleID: "fallback", Reason: "no policy rule matched", Signals: s}
}

// TraceCVE builds blast-radius signals for one CVE against the digital twin.
func TraceCVE(t *graph.Twin, cveID string) (Signals, error) {
	return TraceCVEWorkload(t, cveID, "")
}

// TraceCVEWorkload builds signals for one CVE, optionally scoped to a single workload name.
func TraceCVEWorkload(t *graph.Twin, cveID, workload string) (Signals, error) {
	return TraceCVEWorkloadOpts(t, cveID, workload, TraceOptions{})
}

// TraceCVEWorkloadOpts is TraceCVEWorkload with attestation / fix-image options.
func TraceCVEWorkloadOpts(t *graph.Twin, cveID, workload string, opts TraceOptions) (Signals, error) {
	cve := t.CVE(cveID)
	if cve == nil {
		return Signals{}, fmt.Errorf("unknown CVE %s", cveID)
	}
	s := Signals{
		CVE:               cve.ID,
		Package:           cve.Package,
		Severity:          strings.ToUpper(strings.TrimSpace(cve.Severity)),
		CVSS:              cve.CVSS,
		EPSS:              cve.EPSS,
		FixAvailable:      cve.FixAvailable,
		SBOM:              graph.StatusMissing,
		Provenance:        graph.StatusMissing,
		PackagePresent:    runtime.Unknown,
		NetworkReachable:  runtime.Unknown,
		ExecutionObserved: runtime.ExecutionObserved(opts.RuntimeEvidence, workload, cve.Package),
	}

	var criticalPath []string
	var sbomStatus, provStatus string
	statusSet := false
	pkgSeen := false
	pkgPresent := false
	netKnown := false
	vexStatuses := map[string]bool{}

	for i := range t.Artifacts {
		a := &t.Artifacts[i]
		if opts.VerifyAttestations {
			ver := opts.Verifier
			if ver == nil {
				ver = verify.Default()
			}
			r := ver.Verify(context.Background(), a.Image)
			verify.ApplyToArtifact(a, r)
		} else {
			a.SBOM = graph.NormalizeStatus(a.SBOM)
			a.Provenance = graph.NormalizeStatus(a.Provenance)
			a.Signature = graph.NormalizeStatus(a.Signature)
		}

		if artifactRelevantForStatus(t, a, cve, workload) {
			if !statusSet {
				sbomStatus = a.SBOM
				provStatus = a.Provenance
				statusSet = true
			} else {
				sbomStatus = worstStatus(sbomStatus, a.SBOM)
				provStatus = worstStatus(provStatus, a.Provenance)
			}
			if len(a.Packages) > 0 {
				pkgSeen = true
				for _, p := range a.Packages {
					if p.Name == cve.Package {
						pkgPresent = true
						break
					}
				}
			}
		}

		if !graph.TwinPackageAffected(t, a, cve) {
			continue
		}
		if vex, suppress := vexEffect(t, a, cve); suppress {
			if vex != nil {
				vexStatuses[openvex.NormalizeStatus(vex.Status)] = true
			}
			continue
		}
		if vex := t.VEXForArtifact(cve.ID, a); vex != nil {
			vexStatuses[openvex.NormalizeStatus(vex.Status)] = true
		}
		s.AffectedArts++
		for _, w := range t.Workloads {
			if workload != "" && w.Name != workload {
				continue
			}
			if !graph.ImagesMatch(w.Image, a.Image) {
				continue
			}
			netKnown = true
			if w.Running {
				s.Running = true
				s.RunningWLs++
			}
			if w.InternetExposed {
				s.InternetExposed = true
				s.ExposedWLs++
			}
			if w.ReachablePath {
				s.ReachablePath = true
				s.ReachableWLs++
			}
			if w.Critical {
				s.CriticalService = true
			}
			if w.Running && w.ReachablePath && w.InternetExposed && w.Critical {
				criticalPath = []string{
					cve.ID,
					cve.Package,
					a.Image,
					w.Namespace + "/" + w.Name,
					"public-ingress",
				}
			}
		}
	}

	s.SBOM = sbomStatus
	s.Provenance = provStatus
	if s.SBOM == "" {
		s.SBOM = graph.StatusMissing
	}
	if s.Provenance == "" {
		s.Provenance = graph.StatusMissing
	}

	if pkgSeen {
		if pkgPresent {
			s.PackagePresent = runtime.True
		} else {
			s.PackagePresent = runtime.False
		}
	}
	if netKnown {
		if s.ReachablePath {
			s.NetworkReachable = runtime.True
		} else {
			s.NetworkReachable = runtime.False
		}
	}

	// VEX-only path: if every package-affected artifact is suppressed as not_affected.
	allVEX := true
	anyArt := false
	for i := range t.Artifacts {
		a := &t.Artifacts[i]
		if !graph.TwinPackageAffected(t, a, cve) {
			continue
		}
		anyArt = true
		vex, suppress := vexEffect(t, a, cve)
		if !suppress || vex == nil || openvex.NormalizeStatus(vex.Status) != openvex.StatusNotAffected {
			allVEX = false
		}
	}
	if anyArt && allVEX {
		s.VEXNotAffected = true
		s.VEXStatus = openvex.StatusNotAffected
		s.AffectedArts = 0
	} else if vexStatuses[openvex.StatusUnderInvestigation] {
		s.VEXStatus = openvex.StatusUnderInvestigation
	} else if vexStatuses[openvex.StatusFixed] {
		s.VEXStatus = openvex.StatusFixed
	}

	s.CriticalPath = criticalPath
	s.FixImage = suggestFixImage(t, cve, opts.Demo)
	return s, nil
}

// vexEffect returns the matching VEX row and whether it suppresses the artifact
// from the blast-radius count.
//
// not_affected → suppress (justification/digest already validated at ingest).
// fixed → suppress only when the artifact package version is outside the CVE range
//
//	(fixed version present / no longer affected).
//
// under_investigation → do not suppress (decision layer keeps WARN).
func vexEffect(t *graph.Twin, a *graph.Artifact, cve *graph.CVE) (*graph.VEX, bool) {
	v := t.VEXForArtifact(cve.ID, a)
	if v == nil {
		return nil, false
	}
	switch openvex.NormalizeStatus(v.Status) {
	case openvex.StatusNotAffected:
		return v, true
	case openvex.StatusFixed:
		// Require the artifact to no longer be package-affected (fixed version present).
		if !graph.TwinPackageAffected(t, a, cve) {
			return v, true
		}
		// Scanner still marks affected → fixed claim not evidenced; keep in radius.
		return v, false
	default:
		return v, false
	}
}

func suggestFixImage(t *graph.Twin, cve *graph.CVE, demo *config.Demo) string {
	candidates := []string{}
	if demo != nil {
		candidates = append(candidates, demo.FixImageCandidates...)
	}
	for _, img := range candidates {
		if fix := t.Artifact(img); fix != nil && !graph.TwinPackageAffected(t, fix, cve) {
			return fix.Image
		}
	}
	// Generic: first artifact that contains the package at a non-affected version.
	for i := range t.Artifacts {
		a := &t.Artifacts[i]
		hasPkg := false
		for _, p := range a.Packages {
			if p.Name == cve.Package {
				hasPkg = true
				break
			}
		}
		if hasPkg && !graph.TwinPackageAffected(t, a, cve) {
			return a.Image
		}
	}
	return ""
}

func worstStatus(a, b string) string {
	rank := func(s string) int {
		switch graph.NormalizeStatus(s) {
		case graph.StatusUnverified:
			return 2
		case graph.StatusMissing:
			return 1
		case graph.StatusVerified:
			return 0
		default:
			return 1
		}
	}
	if rank(b) > rank(a) {
		return graph.NormalizeStatus(b)
	}
	return graph.NormalizeStatus(a)
}

// artifactRelevantForStatus reports whether an artifact should contribute to
// SBOM/provenance signals for this CVE/workload scope.
// Empty BindWorkloads stubs (no packages, SBOM MISSING) are excluded so they
// cannot dilute a real ingested SBOM to MISSING via worstStatus.
func artifactRelevantForStatus(t *graph.Twin, a *graph.Artifact, cve *graph.CVE, workload string) bool {
	if a == nil {
		return false
	}
	stub := len(a.Packages) == 0 && graph.NormalizeStatus(a.SBOM) == graph.StatusMissing
	if stub {
		return false
	}
	if workload != "" {
		for _, w := range t.Workloads {
			if w.Name != workload {
				continue
			}
			if graph.ImagesMatch(w.Image, a.Image) {
				return true
			}
		}
		return false
	}
	if len(a.Packages) > 0 {
		return true
	}
	return graph.TwinPackageAffected(t, a, cve)
}

// ExitCode maps a decision to process exit status.
// 0 = ALLOW (and WARN unless failOnWarn), 1 = WARN when failOnWarn, 2 = BLOCK/QUARANTINE.
func ExitCode(action string, failOnWarn bool) int {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "ALLOW":
		return 0
	case "WARN":
		if failOnWarn {
			return 1
		}
		return 0
	case "BLOCK", "QUARANTINE":
		return 2
	default:
		return 2
	}
}

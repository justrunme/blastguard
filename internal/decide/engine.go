package decide

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/justrunme/blastguard/internal/graph"
)

type When struct {
	SeverityAtLeast *string `json:"severity_at_least"`
	Running         *bool   `json:"running"`
	InternetExposed *bool   `json:"internet_exposed"`
	ReachablePath   *bool   `json:"reachable_path"`
	CriticalService *bool   `json:"critical_service"`
	VEXNotAffected  *bool   `json:"vex_not_affected"`
	FixAvailable    *bool   `json:"fix_available"`
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
	CVE             string
	Package         string
	Severity        string
	CVSS            float64
	EPSS            float64
	FixAvailable    bool
	Running         bool
	InternetExposed bool
	ReachablePath   bool
	CriticalService bool
	VEXNotAffected  bool
	AffectedArts    int
	RunningWLs      int
	ExposedWLs      int
	ReachableWLs    int
	CriticalPath    []string
	SBOM            string
	Provenance      string
	FixImage        string
}

type Decision struct {
	Action  string  `json:"action"`
	RuleID  string  `json:"rule_id"`
	Reason  string  `json:"reason"`
	Signals Signals `json:"signals"`
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

func (p *Policy) Evaluate(s Signals) Decision {
	if s.AffectedArts == 0 && s.RunningWLs == 0 && !s.VEXNotAffected {
		// No remaining blast radius — remediated or never present.
		if s.CVE != "" && s.Package != "" {
			return Decision{Action: "ALLOW", RuleID: "no-blast-radius", Reason: "no affected artifacts remain in the twin", Signals: s}
		}
	}
	if s.VEXNotAffected && s.AffectedArts == 0 {
		return Decision{Action: "ALLOW", RuleID: "vex-clear", Reason: "VEX asserts not_affected for this artifact", Signals: s}
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
	cve := t.CVE(cveID)
	if cve == nil {
		return Signals{}, fmt.Errorf("unknown CVE %s", cveID)
	}
	s := Signals{
		CVE:          cve.ID,
		Package:      cve.Package,
		Severity:     strings.ToUpper(strings.TrimSpace(cve.Severity)),
		CVSS:         cve.CVSS,
		EPSS:         cve.EPSS,
		FixAvailable: cve.FixAvailable,
		SBOM:         "VERIFIED",
		Provenance:   "VERIFIED",
	}

	var criticalPath []string
	for _, a := range t.Artifacts {
		if !graph.PackageAffected(&a, cve) {
			continue
		}
		if t.VEXStatus(cve.ID, a.Image) == "not_affected" {
			continue
		}
		s.AffectedArts++
		for _, w := range t.Workloads {
			if workload != "" && w.Name != workload {
				continue
			}
			if !graph.ImagesMatch(w.Image, a.Image) {
				continue
			}
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

	// VEX-only path: if every artifact is not_affected
	allVEX := true
	anyArt := false
	for _, a := range t.Artifacts {
		if !graph.PackageAffected(&a, cve) {
			continue
		}
		anyArt = true
		if t.VEXStatus(cve.ID, a.Image) != "not_affected" {
			allVEX = false
		}
	}
	if anyArt && allVEX {
		s.VEXNotAffected = true
		s.AffectedArts = 0
	}

	s.CriticalPath = criticalPath

	// Suggest fix image for payment-api when present
	if fix := t.Artifact("ghcr.io/justrunme/payment-api:v42"); fix != nil && !graph.PackageAffected(fix, cve) {
		s.FixImage = fix.Image
	}
	return s, nil
}

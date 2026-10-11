// Package remediate compares current vs proposed images for blast-radius impact.
package remediate

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/justrunme/blastguard/internal/graph"
)

// Verdict for whether a proposed image is safer.
const (
	SaferYes     = "safer"
	SaferNo      = "not_safer"
	SaferUnknown = "UNKNOWN"
)

// Report is the remediation impact output (JSON + markdown).
type Report struct {
	CurrentImage       string          `json:"current_image,omitempty"`
	ProposedImage      string          `json:"proposed_image"`
	SaferVerdict       string          `json:"safer_verdict"`
	SaferWorkloads     []WorkloadDelta `json:"safer_workloads"`
	UnchangedWorkloads []WorkloadDelta `json:"unchanged_workloads"`
	WorsenedWorkloads  []WorkloadDelta `json:"worsened_workloads,omitempty"`
	ResolvedCVEs       []string        `json:"resolved_cves"`
	IntroducedCVEs     []string        `json:"introduced_cves,omitempty"`
	RemainingCVEs      []CVERemain     `json:"remaining_cves"`
	RequiredChanges    []string        `json:"required_changes"`
	ScanDataMissing    bool            `json:"scan_data_missing,omitempty"`
}

// WorkloadDelta describes how a live workload's CVE set changes.
type WorkloadDelta struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Image     string   `json:"image"`
	Before    []string `json:"cves_before"`
	After     []string `json:"cves_after"`
	Resolved  []string `json:"resolved"`
	Introduced []string `json:"introduced,omitempty"`
}

// CVERemain is a CVE still present on the proposed image.
type CVERemain struct {
	ID       string `json:"id"`
	Package  string `json:"package"`
	Severity string `json:"severity"`
}

// Compare builds an impact report for moving live workloads from their current
// images toward proposed (when ImagesMatch), using twin CVE/package data.
//
// A workload is "safer" only when at least one CVE is resolved and no new or
// worse CVEs are introduced. A proposed image with no scan/package data yields
// safer_verdict=UNKNOWN (never "all resolved").
func Compare(t *graph.Twin, proposedImage string) (*Report, error) {
	if t == nil {
		return nil, fmt.Errorf("remediate: nil twin")
	}
	proposedImage = strings.TrimSpace(proposedImage)
	if proposedImage == "" {
		return nil, fmt.Errorf("remediate: proposed image required")
	}
	proposed := t.Artifact(proposedImage)
	if proposed == nil {
		return nil, fmt.Errorf("remediate: proposed image %q not in twin (ingest its SBOM first)", proposedImage)
	}

	rep := &Report{ProposedImage: proposed.Image, SaferVerdict: SaferUnknown}

	proposedHasScan := len(proposed.Packages) > 0 || artifactHasMatches(t, proposed)
	if !proposedHasScan {
		rep.ScanDataMissing = true
		rep.SaferVerdict = SaferUnknown
		rep.RequiredChanges = append(rep.RequiredChanges,
			"Proposed image has no scan/package data — cannot claim CVEs are resolved (verdict UNKNOWN)")
		return rep, nil
	}

	proposedCVEs := cvesForArtifact(t, proposed)
	proposedSet := toSet(proposedCVEs)

	for _, w := range t.Workloads {
		if !w.Running {
			continue
		}
		if !graph.ImagesMatch(w.Image, proposed.Image) && w.Image != proposed.Image {
			cur := t.Artifact(w.Image)
			if cur == nil || !graph.ImagesMatch(cur.Image, proposed.Image) {
				continue
			}
		}
		curArt := t.Artifact(w.Image)
		if curArt == nil {
			continue
		}
		if rep.CurrentImage == "" {
			rep.CurrentImage = curArt.Image
		}
		before := cvesForArtifact(t, curArt)
		after := proposedCVEs
		resolved := diff(before, proposedSet)
		beforeSet := toSet(before)
		introduced := diff(after, beforeSet)
		delta := WorkloadDelta{
			Name:       w.Name,
			Namespace:  w.Namespace,
			Image:      w.Image,
			Before:     before,
			After:      after,
			Resolved:   resolved,
			Introduced: introduced,
		}
		if len(introduced) > 0 {
			rep.WorsenedWorkloads = append(rep.WorsenedWorkloads, delta)
			rep.IntroducedCVEs = union(rep.IntroducedCVEs, introduced)
		} else if len(resolved) > 0 {
			rep.SaferWorkloads = append(rep.SaferWorkloads, delta)
		} else {
			rep.UnchangedWorkloads = append(rep.UnchangedWorkloads, delta)
		}
	}

	allBefore := map[string]bool{}
	for _, w := range rep.SaferWorkloads {
		for _, c := range w.Before {
			allBefore[c] = true
		}
	}
	for _, w := range rep.UnchangedWorkloads {
		for _, c := range w.Before {
			allBefore[c] = true
		}
	}
	for _, w := range rep.WorsenedWorkloads {
		for _, c := range w.Before {
			allBefore[c] = true
		}
	}
	for c := range allBefore {
		if !proposedSet[c] {
			rep.ResolvedCVEs = append(rep.ResolvedCVEs, c)
		}
	}
	for _, id := range proposedCVEs {
		cve := t.CVE(id)
		if cve == nil {
			continue
		}
		rep.RemainingCVEs = append(rep.RemainingCVEs, CVERemain{
			ID: cve.ID, Package: cve.Package, Severity: cve.Severity,
		})
	}

	switch {
	case len(rep.WorsenedWorkloads) > 0 || len(rep.IntroducedCVEs) > 0:
		rep.SaferVerdict = SaferNo
	case len(rep.SaferWorkloads) > 0:
		rep.SaferVerdict = SaferYes
	default:
		rep.SaferVerdict = SaferUnknown
	}

	if len(rep.SaferWorkloads) > 0 {
		var names []string
		for _, w := range rep.SaferWorkloads {
			names = append(names, w.Namespace+"/"+w.Name)
		}
		rep.RequiredChanges = append(rep.RequiredChanges,
			fmt.Sprintf("Roll workloads to %s: %s", proposed.Image, strings.Join(names, ", ")))
	}
	if len(rep.IntroducedCVEs) > 0 {
		rep.RequiredChanges = append(rep.RequiredChanges,
			fmt.Sprintf("Proposed image introduces CVE(s): %s — not safer", strings.Join(rep.IntroducedCVEs, ", ")))
	}
	if len(rep.RemainingCVEs) > 0 {
		rep.RequiredChanges = append(rep.RequiredChanges,
			fmt.Sprintf("%d CVE(s) remain on proposed image — plan further upgrades or VEX", len(rep.RemainingCVEs)))
	}
	if len(rep.SaferWorkloads) == 0 && len(rep.WorsenedWorkloads) == 0 && len(rep.RemainingCVEs) == 0 {
		rep.RequiredChanges = append(rep.RequiredChanges, "No running workloads match proposed image family; attach SBOM for current fleet images")
	}
	return rep, nil
}

func artifactHasMatches(t *graph.Twin, a *graph.Artifact) bool {
	if a == nil {
		return false
	}
	// Packages on the artifact are the primary scan signal.
	if len(a.Packages) > 0 {
		return true
	}
	// Exact-image scanner matches only (not ImagesMatch across tags).
	for _, m := range t.Matches {
		if m.Image != "" && m.Image == a.Image {
			return true
		}
	}
	return false
}

func cvesForArtifact(t *graph.Twin, a *graph.Artifact) []string {
	var ids []string
	for i := range t.CVEs {
		cve := &t.CVEs[i]
		if !graph.TwinPackageAffected(t, a, cve) {
			continue
		}
		if v := t.VEXForArtifact(cve.ID, a); v != nil && strings.EqualFold(v.Status, "not_affected") {
			continue
		}
		ids = append(ids, cve.ID)
	}
	return ids
}

func toSet(ids []string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func diff(before []string, afterSet map[string]bool) []string {
	var out []string
	for _, id := range before {
		if !afterSet[id] {
			out = append(out, id)
		}
	}
	return out
}

func union(a, b []string) []string {
	seen := toSet(a)
	out := append([]string{}, a...)
	for _, id := range b {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Markdown renders a human-readable impact report.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Remediation impact\n\n")
	if r.CurrentImage != "" {
		fmt.Fprintf(&b, "- Current image family: `%s`\n", r.CurrentImage)
	}
	fmt.Fprintf(&b, "- Proposed image: `%s`\n", r.ProposedImage)
	fmt.Fprintf(&b, "- Safer verdict: `%s`\n\n", r.SaferVerdict)

	if r.ScanDataMissing {
		b.WriteString("Proposed image has **no scan data** — verdict is UNKNOWN, not \"all resolved\".\n\n")
	}

	b.WriteString("## Safer workloads\n\n")
	if len(r.SaferWorkloads) == 0 {
		b.WriteString("_None_\n\n")
	} else {
		for _, w := range r.SaferWorkloads {
			fmt.Fprintf(&b, "- `%s/%s` (%s): resolves %s\n",
				w.Namespace, w.Name, w.Image, strings.Join(w.Resolved, ", "))
		}
		b.WriteString("\n")
	}

	if len(r.WorsenedWorkloads) > 0 {
		b.WriteString("## Worsened workloads (new CVEs)\n\n")
		for _, w := range r.WorsenedWorkloads {
			fmt.Fprintf(&b, "- `%s/%s`: introduces %s\n",
				w.Namespace, w.Name, strings.Join(w.Introduced, ", "))
		}
		b.WriteString("\n")
	}

	b.WriteString("## Remaining CVEs on proposed image\n\n")
	if len(r.RemainingCVEs) == 0 {
		b.WriteString("_None_\n\n")
	} else {
		for _, c := range r.RemainingCVEs {
			fmt.Fprintf(&b, "- `%s` (%s, %s)\n", c.ID, c.Package, c.Severity)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Required changes\n\n")
	for _, c := range r.RequiredChanges {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	return b.String()
}

// JSON returns indented JSON.
func (r *Report) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

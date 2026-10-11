// Package remediate compares current vs proposed images for blast-radius impact.
package remediate

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/justrunme/blastguard/internal/graph"
)

// Report is the remediation impact output (JSON + markdown).
type Report struct {
	CurrentImage       string          `json:"current_image,omitempty"`
	ProposedImage      string          `json:"proposed_image"`
	SaferWorkloads     []WorkloadDelta `json:"safer_workloads"`
	UnchangedWorkloads []WorkloadDelta `json:"unchanged_workloads"`
	ResolvedCVEs       []string        `json:"resolved_cves"`
	RemainingCVEs      []CVERemain     `json:"remaining_cves"`
	RequiredChanges    []string        `json:"required_changes"`
}

// WorkloadDelta describes how a live workload's CVE set changes.
type WorkloadDelta struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Image     string   `json:"image"`
	Before    []string `json:"cves_before"`
	After     []string `json:"cves_after"`
	Resolved  []string `json:"resolved"`
}

// CVERemain is a CVE still present on the proposed image.
type CVERemain struct {
	ID       string `json:"id"`
	Package  string `json:"package"`
	Severity string `json:"severity"`
}

// Compare builds an impact report for moving live workloads from their current
// images toward proposed (when ImagesMatch), using twin CVE/package data.
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

	rep := &Report{ProposedImage: proposed.Image}

	proposedCVEs := cvesForArtifact(t, proposed)
	proposedSet := toSet(proposedCVEs)

	for _, w := range t.Workloads {
		if !w.Running {
			continue
		}
		if !graph.ImagesMatch(w.Image, proposed.Image) && w.Image != proposed.Image {
			// Only report workloads that could adopt this image family, or exact match family.
			// If proposed is a different app image, still compare when current artifact shares repo.
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
		delta := WorkloadDelta{
			Name:      w.Name,
			Namespace: w.Namespace,
			Image:     w.Image,
			Before:    before,
			After:     after,
			Resolved:  resolved,
		}
		if len(resolved) > 0 {
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

	if len(rep.SaferWorkloads) > 0 {
		var names []string
		for _, w := range rep.SaferWorkloads {
			names = append(names, w.Namespace+"/"+w.Name)
		}
		rep.RequiredChanges = append(rep.RequiredChanges,
			fmt.Sprintf("Roll workloads to %s: %s", proposed.Image, strings.Join(names, ", ")))
	}
	if len(rep.RemainingCVEs) > 0 {
		rep.RequiredChanges = append(rep.RequiredChanges,
			fmt.Sprintf("%d CVE(s) remain on proposed image — plan further upgrades or VEX", len(rep.RemainingCVEs)))
	}
	if len(rep.SaferWorkloads) == 0 && len(rep.RemainingCVEs) == 0 {
		rep.RequiredChanges = append(rep.RequiredChanges, "No running workloads match proposed image family; attach SBOM for current fleet images")
	}
	return rep, nil
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

// Markdown renders a human-readable impact report.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Remediation impact\n\n")
	if r.CurrentImage != "" {
		fmt.Fprintf(&b, "- Current image family: `%s`\n", r.CurrentImage)
	}
	fmt.Fprintf(&b, "- Proposed image: `%s`\n\n", r.ProposedImage)

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

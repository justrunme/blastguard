package render

import (
	"fmt"
	"strings"

	"github.com/justrunme/blastguard/internal/decide"
)

func pad(s string, n int) string {
	if len(s) > n {
		if n <= 3 {
			return s[:n]
		}
		return s[:n-3] + "..."
	}
	return s + strings.Repeat(" ", n-len(s))
}

func Card(d decide.Decision) string {
	s := d.Signals
	var b strings.Builder
	row := func(left, right string) {
		fmt.Fprintf(&b, "│  %s %s │\n", pad(left, 22), pad(right, 20))
	}
	b.WriteString("┌──────────────────────────────────────────────┐\n")
	b.WriteString("│  BLASTGUARD                                  │\n")
	fmt.Fprintf(&b, "│  %s │\n", pad(s.CVE, 43))
	b.WriteString("├──────────────────────────────────────────────┤\n")
	row("SBOM", s.SBOM)
	row("PROVENANCE", s.Provenance)
	row("Affected artifacts", fmt.Sprintf("%d", s.AffectedArts))
	row("Running workloads", fmt.Sprintf("%d", s.RunningWLs))
	row("Internet exposed", fmt.Sprintf("%d", s.ExposedWLs))
	row("Reachable", fmt.Sprintf("%d", s.ReachableWLs))
	if len(s.CriticalPath) > 0 {
		b.WriteString("├──────────────────────────────────────────────┤\n")
		b.WriteString("│  Critical path                               │\n")
		for _, hop := range s.CriticalPath {
			fmt.Fprintf(&b, "│    -> %s │\n", pad(hop, 37))
		}
	}
	b.WriteString("├──────────────────────────────────────────────┤\n")
	row("POLICY", d.Action)
	row("Reason", d.Reason)
	if s.FixImage != "" && d.Action != "ALLOW" {
		row("FIX", s.FixImage)
	}
	b.WriteString("└──────────────────────────────────────────────┘\n")
	return b.String()
}

func Remediation(before, after decide.Decision) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CVE %s\n", before.Signals.CVE)
	fmt.Fprintf(&b, "Before\n")
	fmt.Fprintf(&b, "  Blast radius       %d artifacts\n", before.Signals.AffectedArts)
	fmt.Fprintf(&b, "  Runtime affected   %d workloads\n", before.Signals.RunningWLs)
	fmt.Fprintf(&b, "  Externally exposed %d\n", before.Signals.ExposedWLs)
	fmt.Fprintf(&b, "  Decision           %s\n", before.Action)
	fmt.Fprintf(&b, "After\n")
	fmt.Fprintf(&b, "  Blast radius       %d artifacts\n", after.Signals.AffectedArts)
	fmt.Fprintf(&b, "  Runtime affected   %d workloads\n", after.Signals.RunningWLs)
	fmt.Fprintf(&b, "  Externally exposed %d\n", after.Signals.ExposedWLs)
	fmt.Fprintf(&b, "  Decision           %s\n", after.Action)
	if after.Signals.AffectedArts == 0 && after.Signals.RunningWLs == 0 {
		fmt.Fprintf(&b, "REMEDIATION PROVED\n")
	} else {
		fmt.Fprintf(&b, "REMEDIATION INCOMPLETE\n")
	}
	return b.String()
}

func RehearseImage(title string, lines []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PROPOSED IMAGE\n%s\n", title)
	for _, l := range lines {
		fmt.Fprintln(&b, l)
	}
	return b.String()
}

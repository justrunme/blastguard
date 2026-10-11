package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/justrunme/blastguard/internal/graph"
)

type CycloneDXComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl"`
}

type CycloneDXMetadata struct {
	Component *CycloneDXComponent `json:"component"`
}

type CycloneDX struct {
	BOMFormat   string               `json:"bomFormat"`
	SpecVersion string               `json:"specVersion"`
	Metadata    *CycloneDXMetadata   `json:"metadata"`
	Components  []CycloneDXComponent `json:"components"`
}

type SPDXPackage struct {
	SPDXID       string `json:"SPDXID"`
	Name         string `json:"name"`
	VersionInfo  string `json:"versionInfo"`
	ExternalRefs []struct {
		ReferenceCategory string `json:"referenceCategory"`
		ReferenceType     string `json:"referenceType"`
		ReferenceLocator  string `json:"referenceLocator"`
	} `json:"externalRefs"`
}

type SPDX struct {
	SPDXVersion string        `json:"spdxVersion"`
	Name        string        `json:"name"`
	Packages    []SPDXPackage `json:"packages"`
}

type GrypeMatch struct {
	Vulnerability struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Cvss        []struct {
			Metrics struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"metrics"`
		} `json:"cvss"`
		Fix struct {
			Versions []string `json:"versions"`
			State    string   `json:"state"`
		} `json:"fix"`
		// Legacy / alternate field some exporters use.
		FixVersions []string `json:"fixVersions"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
	} `json:"relatedVulnerabilities"`
	MatchDetails []struct {
		Type    string `json:"type"`
		Matcher string `json:"matcher"`
		Found   struct {
			VersionConstraint string `json:"versionConstraint"`
		} `json:"found"`
	} `json:"matchDetails"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Type    string `json:"type"`
		Purl    string `json:"purl"`
	} `json:"artifact"`
}

type Grype struct {
	Matches []GrypeMatch `json:"matches"`
	Source  *struct {
		Target *struct {
			UserInput string `json:"userInput"`
			ImageID   string `json:"imageID"`
		} `json:"target"`
	} `json:"source"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type OSVVulnerability struct {
	ID       string `json:"id"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Summary  string `json:"summary"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type OSVResult struct {
	Package         OSVPackage         `json:"package"`
	Vulnerabilities []OSVVulnerability `json:"vulnerabilities"`
}

type OSVScanner struct {
	Results []OSVResult `json:"results"`
}

type VEXStatement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Products []struct {
		ID string `json:"@id"`
	} `json:"products"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type VEX struct {
	Statements []VEXStatement `json:"statements"`
}

type Builder struct {
	packages      map[string]graph.Pkg
	cves          map[string]*graph.CVE
	matches       []graph.Match
	vexStatements []graph.VEX
	imageRef      string
	imageDigest   string
}

func NewBuilder() *Builder {
	return &Builder{
		packages: make(map[string]graph.Pkg),
		cves:     make(map[string]*graph.CVE),
	}
}

func (b *Builder) IngestCycloneDX(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cdx CycloneDX
	if err := json.Unmarshal(data, &cdx); err != nil {
		return err
	}
	if cdx.Metadata != nil && cdx.Metadata.Component != nil {
		b.imageRef = imageRefFromComponent(cdx.Metadata.Component.Name, cdx.Metadata.Component.Version)
	}
	for _, comp := range cdx.Components {
		if comp.Name == "" || comp.Type == "file" || comp.Type == "operating-system" {
			continue
		}
		eco := ecosystemFromPURL(comp.Purl)
		b.packages[comp.Name] = graph.Pkg{
			Name:      comp.Name,
			Version:   comp.Version,
			Ecosystem: eco,
		}
	}
	return nil
}

func (b *Builder) IngestSPDX(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var spdx SPDX
	if err := json.Unmarshal(data, &spdx); err != nil {
		return err
	}
	for _, pkg := range spdx.Packages {
		if pkg.Name != "" && pkg.VersionInfo != "" {
			eco := ""
			for _, ref := range pkg.ExternalRefs {
				if strings.Contains(strings.ToLower(ref.ReferenceType), "purl") {
					eco = ecosystemFromPURL(ref.ReferenceLocator)
					break
				}
			}
			b.packages[pkg.Name] = graph.Pkg{
				Name:      pkg.Name,
				Version:   pkg.VersionInfo,
				Ecosystem: eco,
			}
		}
	}
	return nil
}

func (b *Builder) IngestGrype(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var grype Grype
	if err := json.Unmarshal(data, &grype); err != nil {
		return err
	}
	if grype.Source != nil && grype.Source.Target != nil {
		if grype.Source.Target.UserInput != "" && b.imageRef == "" {
			b.imageRef = grype.Source.Target.UserInput
		}
		if grype.Source.Target.ImageID != "" {
			b.imageDigest = grype.Source.Target.ImageID
		}
	}
	for _, match := range grype.Matches {
		vuln := match.Vulnerability
		if vuln.ID == "" {
			continue
		}
		fixVersions := vuln.Fix.Versions
		if len(fixVersions) == 0 {
			fixVersions = vuln.FixVersions
		}
		eco := ecosystemFromGrype(match.Artifact.Type, match.Artifact.Purl)
		rangeExpr := constraintFromGrype(match, fixVersions)

		if existing, exists := b.cves[vuln.ID]; !exists {
			cvss := 0.0
			if len(vuln.Cvss) > 0 {
				cvss = vuln.Cvss[0].Metrics.BaseScore
			}
			b.cves[vuln.ID] = &graph.CVE{
				ID:           vuln.ID,
				Package:      match.Artifact.Name,
				VersionRange: rangeExpr,
				Severity:     normalizeSeverity(vuln.Severity),
				CVSS:         cvss,
				EPSS:         0.0,
				FixAvailable: len(fixVersions) > 0 || strings.EqualFold(vuln.Fix.State, "fixed"),
				Description:  vuln.Description,
				Ecosystem:    eco,
			}
		} else if existing.VersionRange == "" && rangeExpr != "" {
			existing.VersionRange = rangeExpr
		}

		// Scanner already matched this package version — record authoritative edge.
		b.matches = append(b.matches, graph.Match{
			CVE:       vuln.ID,
			Package:   match.Artifact.Name,
			Version:   match.Artifact.Version,
			Image:     b.imageRef,
			Ecosystem: eco,
		})
		if match.Artifact.Name != "" && match.Artifact.Version != "" {
			if _, ok := b.packages[match.Artifact.Name]; !ok {
				b.packages[match.Artifact.Name] = graph.Pkg{
					Name:      match.Artifact.Name,
					Version:   match.Artifact.Version,
					Ecosystem: eco,
				}
			}
		}
	}
	return nil
}

func (b *Builder) IngestOSV(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var osv OSVScanner
	if err := json.Unmarshal(data, &osv); err != nil {
		return err
	}
	for _, result := range osv.Results {
		eco := graph.InferEcosystem(result.Package.Name, result.Package.Ecosystem)
		for _, vuln := range result.Vulnerabilities {
			if vuln.ID == "" {
				continue
			}
			rangeExpr := osvRangeExpression(vuln)
			if _, exists := b.cves[vuln.ID]; !exists {
				cvss := 0.0
				severity := "UNKNOWN"
				for _, sev := range vuln.Severity {
					if sev.Type == "CVSS_V3" {
						_, _ = fmt.Sscanf(sev.Score, "CVSS:3.%*d/%*s/%f", &cvss)
						// Also accept score suffix like ".../8.3"
						if cvss == 0 {
							parts := strings.Split(sev.Score, "/")
							if len(parts) > 0 {
								_, _ = fmt.Sscanf(parts[len(parts)-1], "%f", &cvss)
							}
						}
						if cvss >= 9.0 {
							severity = "CRITICAL"
						} else if cvss >= 7.0 {
							severity = "HIGH"
						} else if cvss >= 4.0 {
							severity = "MEDIUM"
						} else if cvss > 0 {
							severity = "LOW"
						}
					}
				}
				b.cves[vuln.ID] = &graph.CVE{
					ID:           vuln.ID,
					Package:      result.Package.Name,
					VersionRange: rangeExpr,
					Severity:     severity,
					CVSS:         cvss,
					EPSS:         0.0,
					FixAvailable: strings.Contains(rangeExpr, "<"),
					Description:  vuln.Summary,
					Ecosystem:    eco,
				}
			}
			b.matches = append(b.matches, graph.Match{
				CVE:       vuln.ID,
				Package:   result.Package.Name,
				Version:   result.Package.Version,
				Image:     b.imageRef,
				Ecosystem: eco,
			})
		}
	}
	return nil
}

func (b *Builder) IngestVEX(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var vex VEX
	if err := json.Unmarshal(data, &vex); err != nil {
		return err
	}
	for _, stmt := range vex.Statements {
		for _, prod := range stmt.Products {
			b.vexStatements = append(b.vexStatements, graph.VEX{
				CVE:           stmt.Vulnerability.Name,
				Image:         prod.ID,
				Status:        stmt.Status,
				Justification: stmt.Justification,
			})
		}
	}
	return nil
}

func (b *Builder) Build() *graph.Twin {
	var packages []graph.Pkg
	for _, pkg := range b.packages {
		packages = append(packages, pkg)
	}

	var cves []graph.CVE
	for _, cve := range b.cves {
		cves = append(cves, *cve)
	}

	imageRef := b.imageRef
	if imageRef == "" {
		imageRef = "ingested-image"
	}

	// SBOM is present when we ingested package metadata; provenance/signature
	// stay MISSING until verify.Attestation runs (never hardcode VERIFIED).
	sbomStatus := graph.StatusMissing
	if len(packages) > 0 {
		sbomStatus = graph.StatusVerified
	}

	return &graph.Twin{
		CVEs: cves,
		Artifacts: []graph.Artifact{
			{
				Image:      imageRef,
				Digest:     b.imageDigest,
				Packages:   packages,
				SBOM:       sbomStatus,
				Provenance: graph.StatusMissing,
				Signature:  graph.StatusMissing,
			},
		},
		Workloads: []graph.Workload{},
		VEX:       b.vexStatements,
		Matches:   b.matches,
	}
}

func imageRefFromComponent(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" {
		return ""
	}
	if version != "" && !strings.Contains(name, ":") {
		return name + ":" + version
	}
	return name
}

func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN":
		return s
	case "NEGLIGIBLE", "INFO":
		return "LOW"
	default:
		if s == "" {
			return "UNKNOWN"
		}
		return s
	}
}

func ecosystemFromPURL(purl string) string {
	purl = strings.TrimSpace(purl)
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if i := strings.Index(rest, "/"); i > 0 {
		return graph.InferEcosystem("", rest[:i])
	}
	return ""
}

func ecosystemFromGrype(artifactType, purl string) string {
	if eco := ecosystemFromPURL(purl); eco != "" {
		return eco
	}
	return graph.InferEcosystem("", artifactType)
}

func constraintFromGrype(match GrypeMatch, fixVersions []string) string {
	for _, d := range match.MatchDetails {
		c := strings.TrimSpace(d.Found.VersionConstraint)
		if c == "" {
			continue
		}
		// Grype appends " (apk)" / " (unknown)" — strip trailing paren note.
		if i := strings.Index(c, " ("); i > 0 {
			c = strings.TrimSpace(c[:i])
		}
		return c
	}
	if len(fixVersions) > 0 {
		return "< " + fixVersions[0]
	}
	return ""
}

func osvRangeExpression(vuln OSVVulnerability) string {
	var parts []string
	for _, aff := range vuln.Affected {
		for _, r := range aff.Ranges {
			introduced := ""
			fixed := ""
			last := ""
			for _, e := range r.Events {
				if e.Introduced != "" && e.Introduced != "0" {
					introduced = e.Introduced
				}
				if e.Introduced == "0" && introduced == "" {
					introduced = "0"
				}
				if e.Fixed != "" {
					fixed = e.Fixed
				}
				if e.LastAffected != "" {
					last = e.LastAffected
				}
			}
			if fixed != "" {
				if introduced != "" && introduced != "0" {
					parts = append(parts, ">= "+introduced+", < "+fixed)
				} else {
					parts = append(parts, "< "+fixed)
				}
			} else if last != "" {
				parts = append(parts, "<= "+last)
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	// Use first range as the CVE-level expression (matches still pin exact versions).
	return parts[0]
}

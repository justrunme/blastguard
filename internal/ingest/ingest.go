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
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Cvss     []struct {
			Metrics struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"metrics"`
		} `json:"cvss"`
		FixVersions []string `json:"fixVersions"`
		Description string   `json:"description"`
	} `json:"vulnerability"`
	RelatedVulnerabilities []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
	} `json:"relatedVulnerabilities"`
	Artifact struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"artifact"`
}

type Grype struct {
	Matches []GrypeMatch `json:"matches"`
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
	Summary string `json:"summary"`
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
	vexStatements []graph.VEX
	imageRef      string
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
		b.packages[comp.Name] = graph.Pkg{
			Name:    comp.Name,
			Version: comp.Version,
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
			b.packages[pkg.Name] = graph.Pkg{
				Name:    pkg.Name,
				Version: pkg.VersionInfo,
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
	for _, match := range grype.Matches {
		vuln := match.Vulnerability
		if vuln.ID == "" {
			continue
		}
		if _, exists := b.cves[vuln.ID]; !exists {
			cvss := 0.0
			if len(vuln.Cvss) > 0 {
				cvss = vuln.Cvss[0].Metrics.BaseScore
			}
			b.cves[vuln.ID] = &graph.CVE{
				ID:           vuln.ID,
				Package:      match.Artifact.Name,
				VersionRange: "< " + strings.Join(vuln.FixVersions, ", "),
				Severity:     normalizeSeverity(vuln.Severity),
				CVSS:         cvss,
				EPSS:         0.0,
				FixAvailable: len(vuln.FixVersions) > 0,
				Description:  vuln.Description,
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
		for _, vuln := range result.Vulnerabilities {
			if vuln.ID == "" {
				continue
			}
			if _, exists := b.cves[vuln.ID]; !exists {
				cvss := 0.0
				severity := "UNKNOWN"
				for _, sev := range vuln.Severity {
					if sev.Type == "CVSS_V3" {
						fmt.Sscanf(sev.Score, "CVSS:3.%*d/%*s/%f", &cvss)
						if cvss >= 9.0 {
							severity = "CRITICAL"
						} else if cvss >= 7.0 {
							severity = "HIGH"
						} else if cvss >= 4.0 {
							severity = "MEDIUM"
						} else {
							severity = "LOW"
						}
					}
				}
				b.cves[vuln.ID] = &graph.CVE{
					ID:           vuln.ID,
					Package:      result.Package.Name,
					VersionRange: "",
					Severity:     severity,
					CVSS:         cvss,
					EPSS:         0.0,
					FixAvailable: false,
					Description:  vuln.Summary,
				}
			}
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

	return &graph.Twin{
		CVEs: cves,
		Artifacts: []graph.Artifact{
			{
				Image:      imageRef,
				Packages:   packages,
				SBOM:       "verified",
				Provenance: "verified",
				Signature:  "verified",
			},
		},
		Workloads: []graph.Workload{},
		VEX:       b.vexStatements,
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

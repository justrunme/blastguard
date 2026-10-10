package graph

import (
	"encoding/json"
	"os"
	"strings"
)

type CVE struct {
	ID           string  `json:"id"`
	Package      string  `json:"package"`
	VersionRange string  `json:"version_range"`
	Severity     string  `json:"severity"`
	CVSS         float64 `json:"cvss"`
	EPSS         float64 `json:"epss"`
	FixAvailable bool    `json:"fix_available"`
	Description  string  `json:"description"`
}

type Pkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Artifact struct {
	Image      string `json:"image"`
	Packages   []Pkg  `json:"packages"`
	SBOM       string `json:"sbom"`
	Provenance string `json:"provenance"`
	Signature  string `json:"signature"`
}

type Workload struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	Image           string `json:"image"`
	Replicas        int    `json:"replicas"`
	Critical        bool   `json:"critical"`
	InternetExposed bool   `json:"internet_exposed"`
	ReachablePath   bool   `json:"reachable_path"`
	Running         bool   `json:"running"`
}

type VEX struct {
	CVE           string `json:"cve"`
	Image         string `json:"image"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type Twin struct {
	CVEs      []CVE      `json:"cves"`
	Artifacts []Artifact `json:"artifacts"`
	Workloads []Workload `json:"workloads"`
	VEX       []VEX      `json:"vex"`
}

func Load(path string) (*Twin, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Twin
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (t *Twin) Artifact(image string) *Artifact {
	for i := range t.Artifacts {
		if t.Artifacts[i].Image == image || ImagesMatch(t.Artifacts[i].Image, image) {
			return &t.Artifacts[i]
		}
	}
	return nil
}

// ImageName returns the repository name of an image ref (nginx from nginx:alpine).
func ImageName(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	if i := strings.Index(ref, ":"); i >= 0 {
		ref = ref[:i]
	}
	return ref
}

// ImagesMatch reports whether two image refs refer to the same repository
// (nginx matches nginx:alpine; registry.k8s.io/coredns/coredns does not).
func ImagesMatch(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	an, bn := ImageName(a), ImageName(b)
	return an != "" && an == bn
}

// BindWorkloads attaches live workloads and clones the SBOM artifact onto
// each matching cluster image so CVE → package → image → workload lines up.
func (t *Twin) BindWorkloads(workloads []Workload) {
	t.Workloads = workloads
	if len(t.Artifacts) == 0 {
		return
	}
	seen := make(map[string]bool, len(t.Artifacts))
	for _, a := range t.Artifacts {
		seen[a.Image] = true
	}
	base := t.Artifacts[0]
	for _, w := range workloads {
		if w.Image == "" || seen[w.Image] {
			continue
		}
		if !ImagesMatch(base.Image, w.Image) {
			continue
		}
		clone := base
		clone.Image = w.Image
		t.Artifacts = append(t.Artifacts, clone)
		seen[w.Image] = true
	}
}

func (t *Twin) CVE(id string) *CVE {
	for i := range t.CVEs {
		if t.CVEs[i].ID == id {
			return &t.CVEs[i]
		}
	}
	return nil
}

func (t *Twin) VEXStatus(cve, image string) string {
	for _, v := range t.VEX {
		if v.CVE == cve && v.Image == image {
			return v.Status
		}
	}
	return ""
}

// PackageAffected is intentionally simple for the demo twin:
// if the artifact lists the package name, treat it as in-range unless version equals a known fixed marker.
func PackageAffected(a *Artifact, cve *CVE) bool {
	if a == nil || cve == nil {
		return false
	}
	for _, p := range a.Packages {
		if p.Name != cve.Package {
			continue
		}
		// Demo fixed versions: openssl 3.3.2+, libxml2 2.12.8+, x/net 0.34.0+
		switch cve.Package {
		case "openssl":
			return p.Version < "3.3.2"
		case "libxml2":
			return p.Version < "2.12.8"
		case "golang.org/x/net":
			return p.Version < "0.34.0"
		default:
			return true
		}
	}
	return false
}

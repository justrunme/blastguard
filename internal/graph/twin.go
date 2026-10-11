package graph

import (
	"encoding/json"
	"os"
	"strings"
)

// Supply-chain verification states for SBOM / provenance / signature signals.
const (
	StatusVerified   = "VERIFIED"
	StatusUnverified = "UNVERIFIED"
	StatusMissing    = "MISSING"
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
	Ecosystem    string  `json:"ecosystem,omitempty"`
}

type Pkg struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Match is a scanner-confirmed affected edge (Grype/Trivy/OSV already matched
// this package version). When present for a CVE, matches are authoritative.
type Match struct {
	CVE       string `json:"cve"`
	Package   string `json:"package"`
	Version   string `json:"version"`
	Image     string `json:"image,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type Artifact struct {
	Image      string `json:"image"`
	Digest     string `json:"digest,omitempty"`
	Packages   []Pkg  `json:"packages"`
	SBOM       string `json:"sbom"`
	Provenance string `json:"provenance"`
	Signature  string `json:"signature"`
}

type Workload struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	Image           string `json:"image"`
	ImageID         string `json:"image_id,omitempty"`
	Replicas        int    `json:"replicas"`
	Critical        bool   `json:"critical"`
	InternetExposed bool   `json:"internet_exposed"`
	ReachablePath   bool   `json:"reachable_path"`
	Running         bool   `json:"running"`
}

type VEX struct {
	CVE           string `json:"cve"`
	Image         string `json:"image"`
	Digest        string `json:"digest,omitempty"`
	Product       string `json:"product,omitempty"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

type Twin struct {
	CVEs      []CVE      `json:"cves"`
	Artifacts []Artifact `json:"artifacts"`
	Workloads []Workload `json:"workloads"`
	VEX       []VEX      `json:"vex"`
	Matches   []Match    `json:"matches,omitempty"`
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
		if t.Artifacts[i].Image == image {
			return &t.Artifacts[i]
		}
	}
	// Fall back to repository-name match only when no exact tag/digest hit.
	for i := range t.Artifacts {
		if ImagesMatch(t.Artifacts[i].Image, image) {
			return &t.Artifacts[i]
		}
	}
	return nil
}

// NormalizeImageDigest extracts an exact sha256:<64 hex> digest from a raw
// image ID or image reference. Handles docker-pullable://…@sha256:… and
// name@sha256:… forms. Short or prefix digests return "".
func NormalizeImageDigest(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	// Strip docker-pullable:// (and similar) scheme prefixes.
	if i := strings.Index(raw, "://"); i >= 0 {
		raw = raw[i+3:]
	}
	// Prefer the digest after the last '@' when present.
	if at := strings.LastIndex(raw, "@"); at >= 0 {
		raw = raw[at+1:]
	}
	idx := strings.Index(raw, "sha256:")
	if idx < 0 {
		return ""
	}
	dig := raw[idx:]
	for i, r := range dig {
		if r == '?' || r == '#' || r == ' ' || r == '"' {
			dig = dig[:i]
			break
		}
	}
	const want = 7 + 64
	if len(dig) < want {
		return ""
	}
	hexPart := dig[7:want]
	for _, r := range hexPart {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	if len(dig) > want {
		next := dig[want]
		if (next >= '0' && next <= '9') || (next >= 'a' && next <= 'f') {
			return ""
		}
	}
	return dig[:want]
}

// ArtifactByDigest returns an artifact pinned by exact content digest equality.
// The input is normalized (docker-pullable://…@sha256:… → sha256:<64hex>).
// Comparison is equality only against Artifact.Digest or the exact digest
// parsed from Artifact.Image — never substring/suffix Contains matches.
func (t *Twin) ArtifactByDigest(raw string) *Artifact {
	digest := NormalizeImageDigest(raw)
	if digest == "" {
		return nil
	}
	for i := range t.Artifacts {
		a := &t.Artifacts[i]
		ad := NormalizeImageDigest(a.Digest)
		if ad == "" {
			ad = NormalizeImageDigest(a.Image)
		}
		if ad != "" && ad == digest {
			return a
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

// BindWorkloads attaches live workloads. SBOM packages are never cloned across
// different tags/digests (nginx:1.25 must not imply nginx:1.27). A stub artifact
// is added only when the exact image ref is absent.
func (t *Twin) BindWorkloads(workloads []Workload) {
	t.Workloads = workloads
	seen := make(map[string]bool, len(t.Artifacts))
	for _, a := range t.Artifacts {
		seen[a.Image] = true
	}
	for _, w := range workloads {
		if w.Image == "" || seen[w.Image] {
			continue
		}
		if w.ImageID != "" {
			if a := t.ArtifactByDigest(w.ImageID); a != nil {
				continue
			}
		}
		if hasExactImage(t, w.Image) {
			continue
		}
		t.Artifacts = append(t.Artifacts, Artifact{
			Image:      w.Image,
			Digest:     NormalizeImageDigest(w.ImageID),
			Packages:   nil,
			SBOM:       StatusMissing,
			Provenance: StatusMissing,
			Signature:  StatusMissing,
		})
		seen[w.Image] = true
	}
}

func hasExactImage(t *Twin, image string) bool {
	for _, a := range t.Artifacts {
		if a.Image == image {
			return true
		}
	}
	return false
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
	if v := t.VEXFor(cve, image, ""); v != nil {
		return v.Status
	}
	return ""
}

// VEXForArtifact returns the VEX statement bound to this artifact (digest or exact image).
func (t *Twin) VEXForArtifact(cve string, a *Artifact) *VEX {
	if a == nil {
		return nil
	}
	return t.VEXFor(cve, a.Image, a.Digest)
}

// VEXFor finds a statement for cve bound to image and/or digest.
// Digest match is exact equality on a full sha256:<64 hex> only (no substring /
// suffix). When the VEX product carries a name, the artifact image name must
// also match so pkg:oci/whatever@sha256:… cannot suppress nginx@sha256:….
// Loose repository-name matches are rejected so not_affected cannot leap across tags.
func (t *Twin) VEXFor(cve, image, digest string) *VEX {
	cve = strings.TrimSpace(cve)
	image = strings.TrimSpace(image)
	digest = strings.ToLower(strings.TrimSpace(digest))
	for i := range t.VEX {
		v := &t.VEX[i]
		if v.CVE != cve {
			continue
		}
		if v.Digest != "" {
			vd := strings.ToLower(strings.TrimSpace(v.Digest))
			if len(vd) != 7+64 || !strings.HasPrefix(vd, "sha256:") {
				continue
			}
			if digest == "" || vd != digest {
				continue
			}
			if !vexProductNameMatches(v, image) {
				continue
			}
			return v
		}
		if image != "" && (v.Image == image || v.Product == image) {
			return v
		}
	}
	return nil
}

func vexProductNameMatches(v *VEX, image string) bool {
	if v == nil || image == "" {
		return true
	}
	// Extract name from product purl or image ref stored on the VEX row.
	name := ""
	raw := v.Product
	if raw == "" {
		raw = v.Image
	}
	if strings.HasPrefix(raw, "pkg:") {
		rest := raw
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[i+1:]
		}
		name = rest
		if i := strings.Index(name, "@"); i >= 0 {
			name = name[:i]
		}
		if i := strings.Index(name, "?"); i >= 0 {
			name = name[:i]
		}
	} else {
		name = ImageName(raw)
	}
	if name == "" {
		return true
	}
	an := ImageName(image)
	if strings.EqualFold(an, name) {
		return true
	}
	base := func(s string) string {
		if i := strings.LastIndex(s, "/"); i >= 0 {
			return s[i+1:]
		}
		return s
	}
	return strings.EqualFold(base(an), base(name))
}

// PackageAffected reports whether artifact a is affected by cve.
// Prefer scanner Match edges when present for the CVE; otherwise evaluate
// VersionRange with an ecosystem-aware comparator. Never use lexicographic
// string compares and never treat "any version" as affected.
func PackageAffected(a *Artifact, cve *CVE) bool {
	return PackageAffectedWithMatches(a, cve, nil)
}

// PackageAffectedWithMatches is PackageAffected with optional twin-level matches.
func PackageAffectedWithMatches(a *Artifact, cve *CVE, matches []Match) bool {
	if a == nil || cve == nil {
		return false
	}

	cveHasMatches := false
	for _, m := range matches {
		if m.CVE == cve.ID {
			cveHasMatches = true
			break
		}
	}

	// Scanner matches for this CVE are authoritative: do not fall back to ranges.
	if cveHasMatches {
		for _, m := range matches {
			if m.CVE != cve.ID {
				continue
			}
			if m.Image != "" && a.Image != "" && !ImagesMatch(m.Image, a.Image) && a.Image != m.Image {
				continue
			}
			if len(a.Packages) == 0 {
				return true
			}
			for _, p := range a.Packages {
				if p.Name != m.Package {
					continue
				}
				if m.Version == "" || p.Version == m.Version {
					return true
				}
			}
		}
		return false
	}

	if strings.TrimSpace(cve.VersionRange) == "" {
		return false
	}
	for _, p := range a.Packages {
		if p.Name != cve.Package {
			continue
		}
		eco := p.Ecosystem
		if eco == "" {
			eco = cve.Ecosystem
		}
		eco = InferEcosystem(p.Name, eco)
		ok, err := VersionInRange(p.Version, cve.VersionRange, eco)
		if err != nil {
			continue
		}
		if ok {
			return true
		}
	}
	return false
}

// TwinPackageAffected uses twin.Matches when evaluating.
func TwinPackageAffected(t *Twin, a *Artifact, cve *CVE) bool {
	if t == nil {
		return PackageAffected(a, cve)
	}
	return PackageAffectedWithMatches(a, cve, t.Matches)
}

// NormalizeStatus maps fixture/scanner strings to VERIFIED|UNVERIFIED|MISSING.
func NormalizeStatus(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case StatusVerified, "OK", "PASS", "PASSED":
		return StatusVerified
	case StatusUnverified, "INVALID", "FAILED", "FAIL":
		return StatusUnverified
	case StatusMissing, "ABSENT", "NONE", "UNKNOWN", "":
		return StatusMissing
	default:
		return StatusMissing
	}
}

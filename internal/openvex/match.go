package openvex

import (
	"fmt"
	"strings"

	"github.com/justrunme/blastguard/internal/graph"
)

// KnownStatuses are the OpenVEX vocabulary status values we accept.
var KnownStatuses = map[string]bool{
	StatusNotAffected:        true,
	StatusAffected:           true,
	StatusFixed:              true,
	StatusUnderInvestigation: true,
}

// Accepted is a VEX statement accepted into the twin after validation.
type Accepted struct {
	CVE           string
	Product       string
	Digest        string
	ImageRef      string
	Name          string
	Status        string
	Justification string
}

// EvaluateStatements validates OpenVEX statements against twin artifacts.
// not_affected without a valid justification is ignored with a warning.
// not_affected / fixed must bind to an exact artifact digest or exact image
// ref:version; otherwise the statement is ignored with a warning.
func EvaluateStatements(doc *Document, artifacts []graph.Artifact) (accepted []Accepted, warnings []Warning) {
	if doc == nil {
		return nil, nil
	}
	if err := ValidateDocument(doc); err != nil {
		warnings = append(warnings, Warning{Reason: err.Error()})
		return nil, warnings
	}
	for _, stmt := range doc.Statements {
		cve := strings.TrimSpace(stmt.Vulnerability.Name)
		if cve == "" {
			cve = strings.TrimSpace(stmt.Vulnerability.ID)
		}
		status := NormalizeStatus(stmt.Status)
		if cve == "" || status == "" {
			warnings = append(warnings, Warning{Reason: "statement missing vulnerability name or status"})
			continue
		}
		if !KnownStatuses[status] {
			warnings = append(warnings, Warning{
				CVE: cve, Reason: fmt.Sprintf("unknown status %q rejected", stmt.Status),
			})
			continue
		}
		if len(stmt.Products) == 0 {
			warnings = append(warnings, Warning{CVE: cve, Reason: "statement has no products"})
			continue
		}

		for _, prod := range stmt.Products {
			pid := ParseProductIdentity(prod.ID)
			if status == StatusNotAffected && !ValidJustification(stmt.Justification) {
				warnings = append(warnings, Warning{
					CVE: cve, Product: prod.ID,
					Reason: fmt.Sprintf("not_affected ignored: invalid or missing justification %q", stmt.Justification),
				})
				continue
			}
			// Short/prefix digests are never accepted.
			if strings.Contains(strings.ToLower(prod.ID), "sha256:") && pid.Digest == "" {
				warnings = append(warnings, Warning{
					CVE: cve, Product: prod.ID,
					Reason: "product digest is not exactly sha256:<64 hex>; ignored",
				})
				continue
			}

			bound, why := bindProduct(pid, artifacts)
			if !bound {
				warnings = append(warnings, Warning{
					CVE: cve, Product: prod.ID,
					Reason: why,
				})
				continue
			}

			accepted = append(accepted, Accepted{
				CVE:           cve,
				Product:       prod.ID,
				Digest:        pid.Digest,
				ImageRef:      firstNonEmpty(pid.ImageRef, prod.ID),
				Name:          pid.Name,
				Status:        status,
				Justification: strings.TrimSpace(stmt.Justification),
			})
		}
	}
	return accepted, warnings
}

// ValidateDocument requires @context, author, and timestamp.
func ValidateDocument(doc *Document) error {
	if doc == nil {
		return fmt.Errorf("nil document")
	}
	if strings.TrimSpace(doc.Context) == "" {
		return fmt.Errorf("document missing @context")
	}
	if !strings.Contains(strings.ToLower(doc.Context), "openvex") {
		return fmt.Errorf("document @context %q is not an OpenVEX context", doc.Context)
	}
	if strings.TrimSpace(doc.Author) == "" {
		return fmt.Errorf("document missing author")
	}
	if strings.TrimSpace(doc.Timestamp) == "" {
		return fmt.Errorf("document missing timestamp")
	}
	return nil
}

// bindProduct requires digest match when digest is present; otherwise exact
// image ref (including tag). Repository-name-only matches are rejected.
// Statements are never accepted when the twin has no artifacts.
func bindProduct(pid ProductIdentity, artifacts []graph.Artifact) (bool, string) {
	if pid.Raw == "" {
		return false, "empty product id"
	}
	if pid.Digest == "" && pid.ImageRef == "" && pid.Version == "" {
		return false, "product not bound to digest or version; ignored"
	}
	if len(artifacts) == 0 {
		return false, "no artifacts to bind against; statement rejected"
	}

	for _, a := range artifacts {
		if pid.Digest != "" {
			if !ValidDigest(pid.Digest) {
				return false, fmt.Sprintf("product digest %s is not exactly sha256:<64 hex>; ignored", pid.Digest)
			}
			if artifactMatchesDigestAndName(a, pid.Digest, pid.Name) {
				return true, ""
			}
			continue
		}
		// Exact image ref / tag binding (not loose ImagesMatch across tags).
		if pid.ImageRef != "" && exactImageRef(a.Image, pid.ImageRef) {
			if pid.Name != "" && !nameMatchesArtifact(pid.Name, a) {
				continue
			}
			return true, ""
		}
		if pid.Version != "" && imageTag(a.Image) == pid.Version &&
			(pid.Name == "" || nameMatchesArtifact(pid.Name, a)) {
			return true, ""
		}
	}

	if pid.Digest != "" {
		return false, fmt.Sprintf("product digest %s does not match any artifact digest/name; ignored", pid.Digest)
	}
	return false, fmt.Sprintf("product %q does not match any artifact digest/version; ignored", pid.Raw)
}

// MatchArtifact reports whether an accepted VEX row applies to artifact a.
func MatchArtifact(v Accepted, a *graph.Artifact) bool {
	if a == nil {
		return false
	}
	if v.Digest != "" {
		return artifactMatchesDigestAndName(*a, v.Digest, v.Name)
	}
	if v.ImageRef != "" && exactImageRef(a.Image, v.ImageRef) {
		if v.Name != "" && !nameMatchesArtifact(v.Name, *a) {
			return false
		}
		return true
	}
	// Fallback: exact string equality with stored product id.
	return a.Image == v.ImageRef || a.Image == v.Product
}

// artifactMatchesDigestAndName requires exact digest equality and, when a
// product name is present, that the artifact image/name matches it.
func artifactMatchesDigestAndName(a graph.Artifact, digest, name string) bool {
	digest = strings.ToLower(strings.TrimSpace(digest))
	if !ValidDigest(digest) {
		return false
	}
	artDig := strings.ToLower(strings.TrimSpace(a.Digest))
	if artDig == "" {
		// Digest may be embedded in the image ref as name@sha256:…
		_, artDig = splitDigest(a.Image)
		artDig = strings.ToLower(strings.TrimSpace(artDig))
	}
	if artDig == "" || artDig != digest {
		return false
	}
	if name != "" && !nameMatchesArtifact(name, a) {
		return false
	}
	return true
}

func nameMatchesArtifact(name string, a graph.Artifact) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	an := graph.ImageName(a.Image)
	if strings.EqualFold(an, name) {
		return true
	}
	// Allow path-qualified names (library/nginx vs nginx).
	if strings.EqualFold(pathBase(an), pathBase(name)) {
		return true
	}
	return false
}

func pathBase(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func exactImageRef(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	// Compare without digest suffix — digests themselves must be exact equality.
	aBase, aDig := splitDigest(a)
	bBase, bDig := splitDigest(b)
	if aDig != "" && bDig != "" {
		if !ValidDigest(aDig) || !ValidDigest(bDig) || aDig != bDig {
			return false
		}
		return aBase == bBase || pathBase(aBase) == pathBase(bBase)
	}
	return aBase == bBase && aDig == bDig
}

func splitDigest(ref string) (base, dig string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ref[:i], extractDigest(ref[i+1:])
	}
	return ref, ""
}

func imageTag(ref string) string {
	ref, _ = splitDigest(ref)
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	if i := strings.Index(ref, ":"); i >= 0 {
		return ref[i+1:]
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ToGraphVEX converts accepted statements into twin VEX rows.
func ToGraphVEX(accepted []Accepted) []graph.VEX {
	out := make([]graph.VEX, 0, len(accepted))
	for _, a := range accepted {
		out = append(out, graph.VEX{
			CVE:           a.CVE,
			Image:         a.ImageRef,
			Digest:        a.Digest,
			Product:       a.Product,
			Status:        a.Status,
			Justification: a.Justification,
		})
	}
	return out
}

package openvex

import (
	"fmt"
	"strings"

	"github.com/justrunme/blastguard/internal/graph"
)

// Accepted is a VEX statement accepted into the twin after validation.
type Accepted struct {
	CVE           string
	Product       string
	Digest        string
	ImageRef      string
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
				Status:        status,
				Justification: strings.TrimSpace(stmt.Justification),
			})
		}
	}
	return accepted, warnings
}

// bindProduct requires digest match when digest is present; otherwise exact
// image ref (including tag). Repository-name-only matches are rejected.
func bindProduct(pid ProductIdentity, artifacts []graph.Artifact) (bool, string) {
	if pid.Raw == "" {
		return false, "empty product id"
	}
	if pid.Digest == "" && pid.ImageRef == "" && pid.Version == "" {
		return false, "product not bound to digest or version; ignored"
	}

	// Digest/version-bound statements may be accepted before artifacts exist;
	// decision-time VEXFor still requires exact digest/image match.
	if len(artifacts) == 0 {
		if pid.Digest != "" || pid.ImageRef != "" || pid.Version != "" {
			return true, ""
		}
		return false, "no artifacts and product lacks digest/version binding; ignored"
	}

	for _, a := range artifacts {
		if pid.Digest != "" {
			if artifactHasDigest(a, pid.Digest) {
				return true, ""
			}
			continue
		}
		// Exact image ref / tag binding (not loose ImagesMatch across tags).
		if pid.ImageRef != "" && exactImageRef(a.Image, pid.ImageRef) {
			return true, ""
		}
		if pid.Version != "" && imageTag(a.Image) == pid.Version &&
			(pid.Name == "" || graph.ImageName(a.Image) == pid.Name || strings.EqualFold(graph.ImageName(a.Image), pid.Name)) {
			return true, ""
		}
	}

	if pid.Digest != "" {
		return false, fmt.Sprintf("product digest %s does not match any artifact digest/version; ignored", pid.Digest)
	}
	return false, fmt.Sprintf("product %q does not match any artifact digest/version; ignored", pid.Raw)
}

// MatchArtifact reports whether an accepted VEX row applies to artifact a.
func MatchArtifact(v Accepted, a *graph.Artifact) bool {
	if a == nil {
		return false
	}
	if v.Digest != "" {
		return artifactHasDigest(*a, v.Digest)
	}
	if v.ImageRef != "" && exactImageRef(a.Image, v.ImageRef) {
		return true
	}
	// Fallback: exact string equality with stored product id.
	return a.Image == v.ImageRef || a.Image == v.Product
}

func artifactHasDigest(a graph.Artifact, digest string) bool {
	digest = strings.ToLower(strings.TrimSpace(digest))
	if digest == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(a.Digest), digest) {
		return true
	}
	img := strings.ToLower(a.Image)
	if strings.Contains(img, "@"+digest) || strings.HasSuffix(img, digest) {
		return true
	}
	return false
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
	// Compare without digest suffix.
	aBase, aDig := splitDigest(a)
	bBase, bDig := splitDigest(b)
	if aDig != "" && bDig != "" && aDig == bDig {
		return true
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

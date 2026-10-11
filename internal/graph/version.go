package graph

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	apkversion "github.com/knqyf263/go-apk-version"
	debversion "github.com/knqyf263/go-deb-version"
	rpmversion "github.com/knqyf263/go-rpm-version"
	modsemver "golang.org/x/mod/semver"
)

// Ecosystem identifiers used for version comparison.
const (
	EcoSemver  = "semver"
	EcoGo      = "go"
	EcoDebian  = "debian"
	EcoRPM     = "rpm"
	EcoAPK     = "apk"
	EcoAlpine  = "alpine"
	EcoUnknown = ""
)

var (
	constraintToken = regexp.MustCompile(`(?i)^\s*(>=|<=|>|<|=|==)?\s*(.+?)\s*$`)
	commaSplit      = regexp.MustCompile(`\s*,\s*`)
)

// VersionInRange reports whether version satisfies an affected-range expression.
// Supported forms (comma-AND): "< 3.3.2", ">= 1.0.0, < 2.0.0", "<= 1.3.2".
// Ecosystem selects the comparator (semver, Go, Debian, RPM, APK).
func VersionInRange(version, rangeExpr, ecosystem string) (bool, error) {
	version = strings.TrimSpace(version)
	rangeExpr = strings.TrimSpace(rangeExpr)
	if version == "" || rangeExpr == "" {
		return false, nil
	}
	parts := commaSplit.Split(rangeExpr, -1)
	eco := normalizeEcosystem(ecosystem)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		op, bound, err := parseConstraint(part)
		if err != nil {
			return false, err
		}
		cmp, err := compareVersions(version, bound, eco)
		if err != nil {
			return false, err
		}
		if !opSatisfied(op, cmp) {
			return false, nil
		}
	}
	return true, nil
}

func parseConstraint(part string) (op, bound string, err error) {
	m := constraintToken.FindStringSubmatch(part)
	if m == nil {
		return "", "", fmt.Errorf("invalid version constraint %q", part)
	}
	op = strings.TrimSpace(m[1])
	bound = strings.TrimSpace(m[2])
	if op == "" {
		op = "="
	}
	if op == "==" {
		op = "="
	}
	if bound == "" {
		return "", "", fmt.Errorf("empty version bound in %q", part)
	}
	return op, bound, nil
}

func opSatisfied(op string, cmp int) bool {
	switch op {
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "=", "==":
		return cmp == 0
	default:
		return false
	}
}

func normalizeEcosystem(eco string) string {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "go", "golang", "gomod", "go modules":
		return EcoGo
	case "debian", "ubuntu", "deb":
		return EcoDebian
	case "rpm", "rhel", "centos", "fedora", "amazon":
		return EcoRPM
	case "apk", "alpine":
		return EcoAPK
	case "semver", "npm", "pypi", "cargo", "maven", "nuget", "rubygems", "composer":
		return EcoSemver
	default:
		return EcoSemver
	}
}

// compareVersions returns -1 if a<b, 0 if equal, 1 if a>b.
func compareVersions(a, b, ecosystem string) (int, error) {
	switch ecosystem {
	case EcoGo:
		return compareGo(a, b)
	case EcoDebian:
		return compareDeb(a, b)
	case EcoRPM:
		return compareRPM(a, b)
	case EcoAPK:
		return compareAPK(a, b)
	default:
		return compareSemver(a, b)
	}
}

func compareSemver(a, b string) (int, error) {
	va, errA := semver.NewVersion(stripV(a))
	vb, errB := semver.NewVersion(stripV(b))
	if errA == nil && errB == nil {
		return va.Compare(vb), nil
	}
	// Fall back to dotted numeric compare for near-semver (e.g. 1.3.2-r0 → 1.3.2).
	return compareDotted(stripAPKRelease(a), stripAPKRelease(b)), nil
}

func compareGo(a, b string) (int, error) {
	a, b = ensureV(a), ensureV(b)
	if modsemver.IsValid(a) && modsemver.IsValid(b) {
		return modsemver.Compare(a, b), nil
	}
	return compareSemver(a, b)
}

func compareDeb(a, b string) (int, error) {
	va, err := debversion.NewVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := debversion.NewVersion(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

func compareRPM(a, b string) (int, error) {
	va := rpmversion.NewVersion(a)
	vb := rpmversion.NewVersion(b)
	return va.Compare(vb), nil
}

func compareAPK(a, b string) (int, error) {
	va, err := apkversion.NewVersion(a)
	if err != nil {
		return 0, err
	}
	vb, err := apkversion.NewVersion(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}

func stripV(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

func ensureV(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

func stripAPKRelease(v string) string {
	v = stripV(v)
	if i := strings.Index(v, "-r"); i > 0 {
		return v[:i]
	}
	return v
}

func compareDotted(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var ai, bi int
		if i < len(as) {
			ai = atoiPrefix(as[i])
		}
		if i < len(bs) {
			bi = atoiPrefix(bs[i])
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func atoiPrefix(s string) int {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0
	}
	n, _ := strconv.Atoi(s[:i])
	return n
}

// InferEcosystem guesses a comparator from package name / purl hints.
func InferEcosystem(name, hint string) string {
	h := strings.ToLower(strings.TrimSpace(hint))
	if h != "" {
		return normalizeEcosystem(h)
	}
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "golang.org/") || strings.HasPrefix(n, "github.com/") || strings.HasPrefix(n, "gopkg.in/") {
		return EcoGo
	}
	return EcoSemver
}

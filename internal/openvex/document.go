// Package openvex parses and validates OpenVEX documents for BlastGuard ingest.
package openvex

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OpenVEX not_affected justifications (https://github.com/openvex/spec).
var ValidJustifications = map[string]bool{
	"component_not_present":                             true,
	"vulnerable_code_not_present":                       true,
	"vulnerable_code_not_in_execute_path":               true,
	"vulnerable_code_cannot_be_controlled_by_adversary": true,
	"inline_mitigations_already_exist":                  true,
}

// Status values from the OpenVEX vocabulary.
const (
	StatusNotAffected        = "not_affected"
	StatusAffected           = "affected"
	StatusFixed              = "fixed"
	StatusUnderInvestigation = "under_investigation"
)

// Document is a minimal OpenVEX document.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    any         `json:"version"`
	Statements []Statement `json:"statements"`
}

// Statement is one OpenVEX statement.
type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Products        []Product     `json:"products"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification"`
	ActionStatement string        `json:"action_statement,omitempty"`
}

// Vulnerability identifies the CVE (or other vuln id).
type Vulnerability struct {
	Name string `json:"name"`
	ID   string `json:"@id,omitempty"`
}

// Product is an OpenVEX product identifier (typically an OCI purl).
type Product struct {
	ID string `json:"@id"`
}

// ProductIdentity is a normalized product binding.
type ProductIdentity struct {
	Raw      string
	Digest   string // sha256:… when present
	ImageRef string // repo:tag or repo when parseable
	Name     string // image/repository name
	Version  string // tag or purl version
}

// Warning records a statement that was ignored (or partially applied).
type Warning struct {
	CVE     string
	Product string
	Reason  string
}

// ParseDocument unmarshals OpenVEX JSON.
func ParseDocument(data []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("openvex: parse: %w", err)
	}
	return &doc, nil
}

// NormalizeStatus lowercases and trims a VEX status.
func NormalizeStatus(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ValidJustification reports whether j is an OpenVEX justification enum value.
func ValidJustification(j string) bool {
	return ValidJustifications[strings.ToLower(strings.TrimSpace(j))]
}

// ParseProductIdentity extracts digest / image / version from a product @id.
func ParseProductIdentity(raw string) ProductIdentity {
	raw = strings.TrimSpace(raw)
	id := ProductIdentity{Raw: raw}
	if raw == "" {
		return id
	}

	// pkg:oci/name@version?… or pkg:oci/name@sha256:…
	if strings.HasPrefix(raw, "pkg:") {
		rest := raw
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[i+1:]
		}
		namePart := rest
		var ver string
		if i := strings.Index(rest, "@"); i >= 0 {
			namePart = rest[:i]
			ver = rest[i+1:]
		}
		if q := strings.Index(namePart, "?"); q >= 0 {
			namePart = namePart[:q]
		}
		id.Name = namePart
		id.Version = ver
		if dig := extractDigest(ver); dig != "" {
			id.Digest = dig
		} else if dig := extractDigest(raw); dig != "" {
			id.Digest = dig
		} else if ver != "" && !strings.HasPrefix(ver, "sha256:") {
			id.ImageRef = namePart + ":" + stripQuery(ver)
			id.Version = stripQuery(ver)
		} else {
			id.ImageRef = namePart
		}
		// repository_url query may qualify the image ref
		if repo := queryParam(raw, "repository_url"); repo != "" {
			tag := id.Version
			if id.Digest != "" {
				id.ImageRef = strings.TrimSuffix(repo, "/") + "/" + namePart + "@" + id.Digest
			} else if tag != "" && !strings.HasPrefix(tag, "sha256:") {
				id.ImageRef = strings.TrimSuffix(repo, "/") + "/" + namePart + ":" + tag
			} else {
				id.ImageRef = strings.TrimSuffix(repo, "/") + "/" + namePart
			}
		}
		return id
	}

	// Plain image reference: name:tag@sha256:… or name@sha256:…
	id.ImageRef = raw
	if dig := extractDigest(raw); dig != "" {
		id.Digest = dig
		if at := strings.Index(raw, "@"); at >= 0 {
			id.ImageRef = raw[:at]
		}
	}
	ref := id.ImageRef
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	if i := strings.Index(ref, ":"); i >= 0 {
		id.Name = ref[:i]
		id.Version = ref[i+1:]
	} else {
		id.Name = ref
	}
	return id
}

func stripQuery(s string) string {
	if i := strings.Index(s, "?"); i >= 0 {
		return s[:i]
	}
	return s
}

func extractDigest(s string) string {
	s = strings.ToLower(s)
	idx := strings.Index(s, "sha256:")
	if idx < 0 {
		return ""
	}
	dig := s[idx:]
	// trim trailing query/path junk
	for i, r := range dig {
		if r == '?' || r == '#' || r == ' ' || r == '"' {
			dig = dig[:i]
			break
		}
	}
	// Require exactly "sha256:" + 64 hex digits. Short/prefix digests are rejected.
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
	// Reject if more hex follows without a separator (ambiguous longer token).
	if len(dig) > want {
		next := dig[want]
		if (next >= '0' && next <= '9') || (next >= 'a' && next <= 'f') {
			return ""
		}
	}
	return dig[:want]
}

// ValidDigest reports whether d is exactly sha256:<64 lowercase/any-case hex>.
func ValidDigest(d string) bool {
	d = strings.ToLower(strings.TrimSpace(d))
	return extractDigest(d) == d && len(d) == 7+64
}

func queryParam(raw, key string) string {
	q := strings.Index(raw, "?")
	if q < 0 {
		return ""
	}
	rest := raw[q+1:]
	if at := strings.Index(rest, "@"); at >= 0 {
		rest = rest[:at]
	}
	for _, part := range strings.Split(rest, "&") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && kv[0] == key {
			return kv[1]
		}
	}
	return ""
}

// Package runtime defines optional execution-evidence inputs for BlastGuard.
//
// Observed execution is NOT exploitability: a TRUE ExecutionObserved signal
// means runtime telemetry saw a package/binary load or exec related to the
// finding. It does not prove a reachable exploit path. Missing evidence is
// always UNKNOWN and must never produce ALLOW by itself.
package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const FormatV1 = "blastguard.runtime_evidence/v1"

// EvidenceLevel is the triad vocabulary shared with decide signals.
const (
	True    = "TRUE"
	False   = "FALSE"
	Unknown = "UNKNOWN"
)

// Document is the on-disk format for Tetragon/Falco (or manual) exports.
//
// Example:
//
//	{
//	  "format": "blastguard.runtime_evidence/v1",
//	  "source": "tetragon",
//	  "observations": [
//	    {
//	      "workload": "payment-api",
//	      "namespace": "prod",
//	      "image": "ghcr.io/justrunme/payment-api:v41",
//	      "image_digest": "sha256:…",
//	      "package": "openssl",
//	      "executable": "/usr/lib/libssl.so.3",
//	      "observed_at": "2026-10-11T00:00:00Z"
//	    }
//	  ]
//	}
type Document struct {
	Format       string         `json:"format"`
	Source       string         `json:"source"`
	Observations []Observation  `json:"observations"`
}

// Observation is one runtime sighting. No synthetic/fake rows should be shipped
// in fixtures used as "proof of exploitability".
type Observation struct {
	Workload    string `json:"workload"`
	Namespace   string `json:"namespace,omitempty"`
	Image       string `json:"image,omitempty"`
	ImageDigest string `json:"image_digest,omitempty"`
	Package     string `json:"package,omitempty"`
	Executable  string `json:"executable,omitempty"`
	ObservedAt  string `json:"observed_at,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Load reads and validates a runtime evidence document.
func Load(path string) (*Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse validates JSON evidence.
func Parse(data []byte) (*Document, error) {
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("runtime evidence: %w", err)
	}
	if d.Format != "" && d.Format != FormatV1 {
		return nil, fmt.Errorf("runtime evidence: unsupported format %q (want %s)", d.Format, FormatV1)
	}
	if d.Format == "" {
		d.Format = FormatV1
	}
	return &d, nil
}

// ExecutionObserved returns TRUE/FALSE/UNKNOWN for a workload+package scope.
// Without a document, the result is always UNKNOWN.
func ExecutionObserved(doc *Document, workload, pkg string) string {
	if doc == nil || len(doc.Observations) == 0 {
		return Unknown
	}
	workload = strings.TrimSpace(workload)
	pkg = strings.TrimSpace(pkg)
	sawScope := false
	for _, o := range doc.Observations {
		if workload != "" && o.Workload != "" && o.Workload != workload {
			continue
		}
		sawScope = true
		if pkg == "" || o.Package == "" || o.Package == pkg {
			return True
		}
	}
	if sawScope {
		return False
	}
	// Evidence file present but no row for this workload → UNKNOWN (not FALSE).
	return Unknown
}

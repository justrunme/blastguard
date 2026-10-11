package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Demo holds fixture-oriented defaults kept out of core decision logic.
type Demo struct {
	DefaultWorkload     string            `json:"default_workload"`
	FixImageCandidates  []string          `json:"fix_image_candidates"`
	Remediation         DemoRemediation   `json:"remediation"`
	CriticalLabel       string            `json:"critical_label"`
	CriticalAnnotations []string          `json:"critical_annotations"`
}

type DemoRemediation struct {
	CVE                  string            `json:"cve"`
	Package              string            `json:"package"`
	FixedVersion         string            `json:"fixed_version"`
	WorkloadImageUpdates map[string]string `json:"workload_image_updates"`
}

// DefaultDemo returns built-in fallbacks mirroring fixtures/demo-graph.json.
func DefaultDemo() Demo {
	return Demo{
		DefaultWorkload:    "payment-api",
		FixImageCandidates: []string{"ghcr.io/justrunme/payment-api:v42"},
		CriticalLabel:      "blastguard.io/critical",
		Remediation: DemoRemediation{
			CVE:          "CVE-2026-1234",
			Package:      "openssl",
			FixedVersion: "3.3.2",
			WorkloadImageUpdates: map[string]string{
				"payment-api": "ghcr.io/justrunme/payment-api:v42",
			},
		},
	}
}

// LoadDemo reads config/demo.json from root (or path). Missing file → defaults.
func LoadDemo(path string) (Demo, error) {
	d := DefaultDemo()
	if path == "" {
		return d, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return d, nil
		}
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, err
	}
	if d.CriticalLabel == "" {
		d.CriticalLabel = "blastguard.io/critical"
	}
	return d, nil
}

// LoadDemoFromRoot loads <root>/config/demo.json.
func LoadDemoFromRoot(root string) (Demo, error) {
	return LoadDemo(filepath.Join(root, "config", "demo.json"))
}

package runtime_test

import (
	"testing"

	"github.com/justrunme/blastguard/internal/runtime"
)

func TestExecutionObservedUnknownWithoutDoc(t *testing.T) {
	if got := runtime.ExecutionObserved(nil, "api", "openssl"); got != runtime.Unknown {
		t.Fatalf("got %s", got)
	}
}

func TestExecutionObservedTrue(t *testing.T) {
	doc := &runtime.Document{
		Format: runtime.FormatV1,
		Observations: []runtime.Observation{{
			Workload: "api", Package: "openssl",
		}},
	}
	if got := runtime.ExecutionObserved(doc, "api", "openssl"); got != runtime.True {
		t.Fatalf("got %s", got)
	}
	if got := runtime.ExecutionObserved(doc, "other", "openssl"); got != runtime.Unknown {
		t.Fatalf("other workload want UNKNOWN got %s", got)
	}
}

func TestExecutionObservedNoMatchingRowIsUnknown(t *testing.T) {
	doc := &runtime.Document{
		Format: runtime.FormatV1,
		Observations: []runtime.Observation{{
			Workload: "api", Package: "curl",
		}},
	}
	if got := runtime.ExecutionObserved(doc, "api", "openssl"); got != runtime.Unknown {
		t.Fatalf("no matching package row want UNKNOWN got %s", got)
	}
}

func TestExecutionObservedEmptyPackageDoesNotMatchAll(t *testing.T) {
	doc := &runtime.Document{
		Format: runtime.FormatV1,
		Observations: []runtime.Observation{{
			Workload: "api", Package: "",
		}},
	}
	if got := runtime.ExecutionObserved(doc, "api", "openssl"); got != runtime.Unknown {
		t.Fatalf("empty observation package must not match openssl, got %s", got)
	}
}

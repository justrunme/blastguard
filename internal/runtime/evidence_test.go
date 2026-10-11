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

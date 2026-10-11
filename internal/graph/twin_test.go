package graph

import "testing"

func TestNormalizeStatus(t *testing.T) {
	cases := map[string]string{
		"verified":   StatusVerified,
		"VERIFIED":   StatusVerified,
		"missing":    StatusMissing,
		"unverified": StatusUnverified,
		"":           StatusMissing,
	}
	for in, want := range cases {
		if got := NormalizeStatus(in); got != want {
			t.Fatalf("%q: got %s want %s", in, got, want)
		}
	}
}

func TestBindWorkloadsNoCloneAcrossTags(t *testing.T) {
	twin := &Twin{
		Artifacts: []Artifact{{
			Image:    "nginx:1.25",
			Packages: []Pkg{{Name: "zlib", Version: "1.2.0"}},
			SBOM:     StatusVerified,
		}},
	}
	twin.BindWorkloads([]Workload{
		{Name: "a", Namespace: "default", Image: "nginx:1.25"},
		{Name: "b", Namespace: "default", Image: "nginx:1.27"},
	})
	var got125, got127 *Artifact
	for i := range twin.Artifacts {
		a := &twin.Artifacts[i]
		switch a.Image {
		case "nginx:1.25":
			got125 = a
		case "nginx:1.27":
			got127 = a
		}
	}
	if got125 == nil || len(got125.Packages) != 1 {
		t.Fatalf("1.25 should keep SBOM packages: %+v", got125)
	}
	if got127 == nil {
		t.Fatal("expected stub artifact for unmatched tag")
	}
	if len(got127.Packages) != 0 {
		t.Fatalf("must not clone packages onto nginx:1.27, got %+v", got127.Packages)
	}
	if got127.SBOM != StatusMissing {
		t.Fatalf("stub SBOM want MISSING got %s", got127.SBOM)
	}
}

func TestImagesMatchAndName(t *testing.T) {
	if ImageName("ghcr.io/foo/bar:v1") != "bar" {
		t.Fatal(ImageName("ghcr.io/foo/bar:v1"))
	}
	if !ImagesMatch("nginx", "nginx:alpine") {
		t.Fatal("expected match")
	}
	if ImagesMatch("coredns", "nginx") {
		t.Fatal("expected no match")
	}
}

func TestFixedImageNotAffected(t *testing.T) {
	twin, err := Load("../../fixtures/demo-graph.json")
	if err != nil {
		t.Fatal(err)
	}
	art := twin.Artifact("ghcr.io/justrunme/payment-api:v42")
	if art == nil {
		t.Fatal("missing v42")
	}
	for i := range twin.CVEs {
		c := &twin.CVEs[i]
		if TwinPackageAffected(twin, art, c) {
			t.Fatalf("%s should not affect fixed image packages=%v range=%q", c.ID, art.Packages, c.VersionRange)
		}
	}
}

func TestNormalizeImageDigest(t *testing.T) {
	full := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := map[string]string{
		full: full,
		"docker-pullable://nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": full,
		"nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":                   full,
		"sha256:a":                            "",
		"sha256:aaaaaaaa":                     "",
		"docker-pullable://nginx@sha256:aaaa": "",
		"":                                    "",
	}
	for in, want := range cases {
		if got := NormalizeImageDigest(in); got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestArtifactByDigestExactEquality(t *testing.T) {
	full := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	other := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	twin := &Twin{
		Artifacts: []Artifact{
			{Image: "nginx:alpine", Digest: full},
			{Image: "redis:alpine@" + other, Digest: ""},
		},
	}
	// Exact match via Digest field.
	if a := twin.ArtifactByDigest(full); a == nil || a.Image != "nginx:alpine" {
		t.Fatalf("exact digest: %+v", a)
	}
	// docker-pullable ImageID form.
	if a := twin.ArtifactByDigest("docker-pullable://nginx@" + full); a == nil || a.Image != "nginx:alpine" {
		t.Fatalf("docker-pullable: %+v", a)
	}
	// Digest embedded in Image ref.
	if a := twin.ArtifactByDigest(other); a == nil || a.Image != "redis:alpine@"+other {
		t.Fatalf("image-embedded digest: %+v", a)
	}
}

func TestArtifactByDigestRejectsPrefixAndSubstring(t *testing.T) {
	full := "sha256:a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890"
	twin := &Twin{
		Artifacts: []Artifact{
			{Image: "nginx:alpine", Digest: full},
			// Different image whose digest string shares a prefix/substring with a query.
			{Image: "evil:latest", Digest: "sha256:a1b2cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
		},
	}
	prefix := "sha256:a1b2"
	if a := twin.ArtifactByDigest(prefix); a != nil {
		t.Fatalf("prefix digest must not match, got %+v", a)
	}
	// Short fragment that historically matched via strings.Contains.
	if a := twin.ArtifactByDigest("a1b2c3d4"); a != nil {
		t.Fatalf("substring must not match, got %+v", a)
	}
	// Different image with overlapping hex prefix must not win for the nginx digest.
	if a := twin.ArtifactByDigest(full); a == nil || a.Image != "nginx:alpine" {
		t.Fatalf("full digest should hit nginx, got %+v", a)
	}
	wrongFull := "sha256:a1b2cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if a := twin.ArtifactByDigest(wrongFull); a == nil || a.Image != "evil:latest" {
		t.Fatalf("wrongFull should hit evil only, got %+v", a)
	}
}

package graph

import "testing"

func TestVersionInRangeSemverFalsePositive(t *testing.T) {
	// Lexicographic "3.10.0" < "3.3.2" is true; semver must say not affected.
	ok, err := VersionInRange("3.10.0", "< 3.3.2", EcoSemver)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("3.10.0 must not be affected by < 3.3.2")
	}

	ok, err = VersionInRange("3.3.1", "< 3.3.2", EcoSemver)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("3.3.1 must be affected by < 3.3.2")
	}

	ok, err = VersionInRange("3.3.2", "< 3.3.2", EcoSemver)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("3.3.2 must not be affected by < 3.3.2")
	}
}

func TestVersionInRangeGoPseudo(t *testing.T) {
	cases := []struct {
		ver, rng string
		want     bool
	}{
		{"v0.33.0", "< 0.34.0", true},
		{"0.34.0", "< 0.34.0", false},
		{"v0.0.0-20240101120000-abcdef123456", "< v0.34.0", true},
		{"v0.35.0-0.20240101120000-abcdef123456", "< v0.34.0", false},
	}
	for _, tc := range cases {
		ok, err := VersionInRange(tc.ver, tc.rng, EcoGo)
		if err != nil {
			t.Fatalf("%s in %s: %v", tc.ver, tc.rng, err)
		}
		if ok != tc.want {
			t.Fatalf("%s in %s: got %v want %v", tc.ver, tc.rng, ok, tc.want)
		}
	}
}

func TestVersionInRangeDebianRPMAPK(t *testing.T) {
	ok, err := VersionInRange("1.2.3-1", "< 1.2.3-2", EcoDebian)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected deb 1.2.3-1 < 1.2.3-2")
	}

	ok, err = VersionInRange("1.2.3-2.el8", "< 1.2.3-3.el8", EcoRPM)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected rpm compare")
	}

	ok, err = VersionInRange("1.3.2-r0", "<= 1.3.2-r0", EcoAPK)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected apk 1.3.2-r0 <= 1.3.2-r0")
	}

	ok, err = VersionInRange("1.3.2-r1", "< 1.3.2-r0", EcoAPK)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("1.3.2-r1 must not be < 1.3.2-r0")
	}
}

func TestPackageAffectedRangeAndMatch(t *testing.T) {
	cve := &CVE{ID: "CVE-X", Package: "openssl", VersionRange: "< 3.3.2", Ecosystem: EcoSemver}
	art := &Artifact{
		Image:    "app:1",
		Packages: []Pkg{{Name: "openssl", Version: "3.10.0"}},
	}
	if PackageAffected(art, cve) {
		t.Fatal("3.10.0 must not match < 3.3.2")
	}
	art.Packages[0].Version = "3.3.1"
	if !PackageAffected(art, cve) {
		t.Fatal("3.3.1 must match < 3.3.2")
	}

	// Scanner match authoritative.
	cve2 := &CVE{ID: "CVE-Y", Package: "zlib"}
	matches := []Match{{CVE: "CVE-Y", Package: "zlib", Version: "1.3.2-r0", Image: "app:1"}}
	art2 := &Artifact{Image: "app:1", Packages: []Pkg{{Name: "zlib", Version: "1.3.2-r0"}}}
	if !PackageAffectedWithMatches(art2, cve2, matches) {
		t.Fatal("expected scanner match hit")
	}
	art2.Packages[0].Version = "1.3.3-r0"
	if PackageAffectedWithMatches(art2, cve2, matches) {
		t.Fatal("wrong version must not match scanner edge")
	}
}

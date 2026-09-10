package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestImagePackageSetDigestIsOrderIndependent(t *testing.T) {
	first := imageLockPackage{Name: "linux", Version: "1", Architecture: "x86_64", ReleaseID: "r", Repository: "core", Filename: "linux.pkg.tar.zst", URL: "https://packages.example/r/linux.pkg.tar.zst", SignatureURL: "https://packages.example/r/linux.pkg.tar.zst.sig", SHA256: strings.Repeat("a", 64), SignatureSHA256: strings.Repeat("b", 64), Install: true}
	second := imageLockPackage{Name: "base", Version: "1", Architecture: "any", ReleaseID: "r", Repository: "core", Filename: "base.pkg.tar.zst", URL: "https://packages.example/r/base.pkg.tar.zst", SignatureURL: "https://packages.example/r/base.pkg.tar.zst.sig", SHA256: strings.Repeat("c", 64), SignatureSHA256: strings.Repeat("d", 64), Install: true}
	packages := []imageLockPackage{first, second}
	sort.Slice(packages, func(i, j int) bool {
		return strings.Join([]string{packages[i].Name, packages[i].Architecture, packages[i].Version, packages[i].SHA256}, "\x00") < strings.Join([]string{packages[j].Name, packages[j].Architecture, packages[j].Version, packages[j].SHA256}, "\x00")
	})
	left, err := canonicalPackageSet(packages)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []imageLockPackage{second, first}
	sort.Slice(reversed, func(i, j int) bool {
		return strings.Join([]string{reversed[i].Name, reversed[i].Architecture, reversed[i].Version, reversed[i].SHA256}, "\x00") < strings.Join([]string{reversed[j].Name, reversed[j].Architecture, reversed[j].Version, reversed[j].SHA256}, "\x00")
	})
	right, err := canonicalPackageSet(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatal("sorted package set changed with input order")
	}

	firstBytes, err := canonicalPackageSet(packages)
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := canonicalPackageSet(packages)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstBytes) != string(secondBytes) {
		t.Fatal("canonical package set changed between runs")
	}
}

func TestWriteImageLockRetainsVerifiedTransactionAndGuardsOutput(t *testing.T) {
	fixture := newFixture(t)
	defer fixture.server.Close()
	directory := t.TempDir()
	if err := writeImageLock(context.Background(), fixture.client, fixture.manifestURL, directory, false); err != nil {
		t.Fatal(err)
	}
	lockBytes, err := os.ReadFile(filepath.Join(directory, "release-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock imageLock
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		t.Fatal(err)
	}
	if lock.Authority != "omarchy-manifest-client-v1" || lock.TransactionSHA256 == "" || lock.SystemManifest.SHA256 == "" || lock.OPRManifest.SHA256 == "" || len(lock.Repositories) != 2 || lock.PackageCount != 2 || lock.SourcePackageCount != 4 || len(lock.Packages) != 2 {
		t.Fatalf("incomplete verified image lock: %+v", lock)
	}
	for _, pkg := range lock.Packages {
		if pkg.Architecture != "x86_64" && pkg.Architecture != "any" {
			t.Fatalf("non-target package retained: %+v", pkg)
		}
		if strings.Contains(pkg.URL, "/aarch64/") {
			t.Fatalf("non-target repository package retained: %+v", pkg)
		}
	}
	if err := writeImageLock(context.Background(), fixture.client, fixture.manifestURL, directory, false); err == nil {
		t.Fatal("image lock replaced existing verified outputs")
	}
}

func TestImagePackageRejectsUntrustedURLs(t *testing.T) {
	item := map[string]any{
		"releaseId": "r", "name": "demo", "version": "1", "architecture": "x86_64",
		"artifactUrl": "http://aur.archlinux.org/demo.pkg.tar.zst", "artifactSignatureUrl": "http://aur.archlinux.org/demo.pkg.tar.zst.sig",
		"artifactSha256": strings.Repeat("a", 64), "artifactSignatureSha256": strings.Repeat("b", 64),
	}
	if _, err := imagePackage(item); err == nil {
		t.Fatal("accepted an HTTP AUR package URL")
	}
}

func TestSelectedImagePackageFiltersArchitectureAndRepository(t *testing.T) {
	repositories := []Repository{
		{Name: "core", Architecture: "x86_64", PackageBaseURL: "https://packages.example/releases/r/core/x86_64"},
		{Name: "core", Architecture: "aarch64", PackageBaseURL: "https://packages.example/releases/r/core/aarch64"},
	}
	item := func(architecture, base, name string) map[string]any {
		return map[string]any{
			"releaseId": "r", "name": name, "version": "1", "architecture": architecture,
			"artifactUrl": base + "/" + name + ".pkg.tar.zst", "artifactSignatureUrl": base + "/" + name + ".pkg.tar.zst.sig",
			"artifactSha256": strings.Repeat("a", 64), "artifactSignatureSha256": strings.Repeat("b", 64),
		}
	}
	selected, ok, err := selectedImagePackage(item("aarch64", repositories[1].PackageBaseURL, "arm"), "x86_64", []Repository{repositories[0]})
	if err != nil {
		t.Fatal(err)
	}
	if ok || selected.Name != "" {
		t.Fatalf("selected non-native package: %+v", selected)
	}
	selected, ok, err = selectedImagePackage(item("any", repositories[0].PackageBaseURL, "docs"), "x86_64", []Repository{repositories[0]})
	if err != nil || !ok || selected.Repository != "core" {
		t.Fatalf("selected any package incorrectly: %+v, %v, %v", selected, ok, err)
	}
	if _, ok, err = selectedImagePackage(item("x86_64", repositories[1].PackageBaseURL, "wrong-repo"), "x86_64", []Repository{repositories[0]}); err == nil || ok {
		t.Fatal("accepted package outside selected repository")
	}
}

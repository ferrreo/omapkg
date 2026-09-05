package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const nvidiaFixtureSHA256 = "b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d"

// Set OPR_WORKER_NVIDIA_E2E_IMAGE to a local digest-pinned Arch builder and
// OPR_WORKER_NVIDIA_E2E_SOURCE to the verified NVIDIA .run fixture.
func TestRunnerNVIDIAExtractionNativeOCI(t *testing.T) {
	imageRef := os.Getenv("OPR_WORKER_NVIDIA_E2E_IMAGE")
	sourcePath := os.Getenv("OPR_WORKER_NVIDIA_E2E_SOURCE")
	if imageRef == "" || sourcePath == "" {
		t.Skip("OPR_WORKER_NVIDIA_E2E_IMAGE and OPR_WORKER_NVIDIA_E2E_SOURCE are not set")
	}
	index := strings.LastIndex(imageRef, "@")
	if index < 0 {
		t.Fatalf("NVIDIA E2E image must include a digest")
	}
	imageDigest := imageRef[index+1:]
	if err := validateImageReference(imageRef, imageDigest); err != nil {
		t.Fatal(err)
	}
	sourcePath, err := filepath.Abs(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(sourcePath); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("NVIDIA fixture is unavailable: %v", err)
	}
	digest, size, err := hashFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if digest != nvidiaFixtureSHA256 {
		t.Fatalf("NVIDIA fixture SHA256 = %s, want %s", digest, nvidiaFixtureSHA256)
	}

	job := Job{
		ID:              "runner-nvidia-e2e",
		LeaseToken:      "lease",
		LeaseExpiresAt:  time.Now().Add(10 * time.Minute).Format(time.RFC3339),
		RevisionID:      "revision-nvidia-e2e",
		PackageName:     "opr-nvidia-installer",
		Version:         "610.57.04",
		Pkgrel:          1,
		Architecture:    "x86_64",
		Recipe:          nvidiaFixtureRecipe,
		RecipeSHA256:    hashBytes([]byte(nvidiaFixtureRecipe)),
		SourceDateEpoch: 1700000000,
		ImageDigest:     imageDigest,
		ImageRef:        imageRef,
		Sources:         []Source{{Name: "NVIDIA-Linux-x86_64-610.57.04.run", URL: "https://example.invalid/NVIDIA-Linux-x86_64-610.57.04.run", SHA256: nvidiaFixtureSHA256}},
		Dependencies:    []string{"bash"},
		SmokeCommands: []string{
			"test -x /usr/bin/nvidia-installer",
			"test -s /usr/bin/nvidia-installer",
		},
		Surface: "recipe",
	}
	runner := Runner{Runtime: "podman", Image: imageRef, ImageDigest: imageDigest, Origin: "https://omapkg.example", StateDir: t.TempDir(), BuildTimeout: 10 * time.Minute}
	result, err := runner.Execute(context.Background(), job, []fetchedSource{{Source: job.Sources[0], Path: sourcePath}})
	if err != nil {
		t.Fatalf("%v\n%s", err, result.Log)
	}
	if result.ArtifactPath == "" || !result.SmokePassed || result.InstalledSize <= 0 {
		t.Fatalf("runner result = %+v", result)
	}
	if size <= 0 {
		t.Fatal("NVIDIA fixture is empty")
	}
}

const nvidiaFixtureRecipe = `pkgname=opr-nvidia-installer
pkgver=610.57.04
pkgrel=1
pkgdesc='NVIDIA installer extraction fixture'
arch=('x86_64')
license=('LicenseRef-NVIDIA')
source=('NVIDIA-Linux-x86_64-610.57.04.run')
sha256sums=('b2e935c66b83bb00c0c857bc8e0ee0fd52de9286b40c9cc1eec29a7ce7eb116d')

build() {
  sh "$srcdir/NVIDIA-Linux-x86_64-610.57.04.run" --extract-only --target "$srcdir/vendor-root"
}

package() {
  install -Dm755 "$srcdir/vendor-root/nvidia-installer" "$pkgdir/usr/bin/nvidia-installer"
}
`

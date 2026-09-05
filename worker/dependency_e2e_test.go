package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This opt-in test builds and signs one package, serves it from a local
// repository-shaped HTTPS endpoint, installs it through dependencyPlan, then
// builds and smokes a second package that declares the first as a dependency.
// Set OPR_WORKER_DEP_E2E_IMAGE to a local digest-pinned Arch builder image.
func TestRunnerDependencyPlanNativeOCI(t *testing.T) {
	imageRef := os.Getenv("OPR_WORKER_DEP_E2E_IMAGE")
	if imageRef == "" {
		t.Skip("OPR_WORKER_DEP_E2E_IMAGE is not set")
	}
	index := strings.LastIndex(imageRef, "@")
	if index < 0 {
		t.Fatalf("OPR_WORKER_DEP_E2E_IMAGE must include a digest-pinned image")
	}
	imageDigest := imageRef[index+1:]
	if index < 0 || !strings.HasPrefix(imageDigest, "sha256:") || validateImageReference(imageRef, imageDigest) != nil {
		t.Fatalf("OPR_WORKER_DEP_E2E_IMAGE must include a valid digest-pinned image")
	}
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	runner := Runner{Runtime: "podman", Image: imageRef, ImageDigest: imageDigest, StateDir: t.TempDir(), BuildTimeout: 10 * time.Minute}
	root := t.TempDir()
	firstWork := filepath.Join(root, "first-work")
	firstOutput := filepath.Join(root, "first-output")
	if err := os.MkdirAll(firstWork, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(firstOutput, 0o700); err != nil {
		t.Fatal(err)
	}
	firstRecipe := `pkgname=opr-dependency-fixture
pkgver=1.0
pkgrel=1
pkgdesc='OPR dependency fixture'
arch=('x86_64')
license=('MIT')
source=()
sha256sums=()

build() { :; }

package() {
  install -Dm644 /dev/stdin "$pkgdir/usr/share/opr-dependency-fixture/provider" <<'EOF'
provider
EOF
}
`
	if err := writeRecipe(firstWork, firstRecipe); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.build(ctx, firstWork, firstOutput, "dependency-e2e-first", 1700000000, imageRef); err != nil {
		t.Fatal(err)
	}
	firstArtifact, err := findArtifact(firstOutput, "opr-dependency-fixture")
	if err != nil {
		t.Fatal(err)
	}
	firstSHA, firstSize, err := hashFile(firstArtifact)
	if err != nil {
		t.Fatal(err)
	}

	gnupg := filepath.Join(root, "gnupg")
	if err := os.Mkdir(gnupg, 0o700); err != nil {
		t.Fatal(err)
	}
	runGPG := func(args ...string) []byte {
		command := exec.CommandContext(ctx, "gpg", append([]string{"--batch", "--homedir", gnupg}, args...)...)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("gpg %v: %v\n%s", args, err, output)
		}
		return output
	}
	runGPG("--pinentry-mode", "loopback", "--passphrase", "", "--quick-gen-key", "OPR dependency test", "rsa2048", "sign", "1d")
	publicKey := runGPG("--armor", "--export")
	fingerprint := ""
	for _, line := range strings.Split(string(runGPG("--with-colons", "--fingerprint")), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			fingerprint = fields[9]
			break
		}
	}
	if len(fingerprint) != 40 {
		t.Fatalf("gpg did not report a v4 fingerprint: %q", fingerprint)
	}
	signaturePath := firstArtifact + ".sig"
	runGPG("--yes", "--detach-sign", "--output", signaturePath, firstArtifact)
	signatureSHA, signatureSize, err := hashFile(signaturePath)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"/repo/key.asc": publicKey,
		"/repo/x86_64/opr-dependency-fixture-1.0-1-x86_64.pkg.tar.zst":     mustReadFile(t, firstArtifact),
		"/repo/x86_64/opr-dependency-fixture-1.0-1-x86_64.pkg.tar.zst.sig": mustReadFile(t, signaturePath),
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, ok := files[request.URL.Path]
		if !ok {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	plan := &DependencyPlan{
		Channel:              "stable",
		PublicKeyURL:         server.URL + "/repo/key.asc",
		PublicKeyFingerprint: fingerprint,
		Packages: []DependencyPackage{{
			ReleaseID:       "release-dependency-fixture",
			Name:            "opr-dependency-fixture",
			Version:         "1.0-1",
			Architecture:    "x86_64",
			Filename:        "opr-dependency-fixture-1.0-1-x86_64.pkg.tar.zst",
			URL:             server.URL + "/repo/x86_64/opr-dependency-fixture-1.0-1-x86_64.pkg.tar.zst",
			SHA256:          firstSHA,
			Size:            firstSize,
			SignatureURL:    server.URL + "/repo/x86_64/opr-dependency-fixture-1.0-1-x86_64.pkg.tar.zst.sig",
			SignatureSHA256: signatureSHA,
		}},
	}
	dependencyDir := filepath.Join(root, "dependency-plan")
	if err := materializeDependencyPlanWithClient(ctx, plan, Job{Architecture: "x86_64"}, origin, dependencyDir, server.Client()); err != nil {
		t.Fatal(err)
	}
	prepared, err := runner.prepareDependenciesWithPlan(ctx, "dependency-e2e-second", imageRef, []string{"opr-dependency-fixture=1.0-1", "tree"}, plan, dependencyDir)
	if err != nil {
		t.Fatalf("%v\n%s", err, prepared.log)
	}
	defer prepared.cleanup()
	if err := os.RemoveAll(dependencyDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dependencyDir); !os.IsNotExist(err) {
		t.Fatalf("dependency staging directory remains after prep: %v", err)
	}
	secondWork := filepath.Join(root, "second-work")
	secondOutput := filepath.Join(root, "second-output")
	if err := os.MkdirAll(secondWork, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secondOutput, 0o700); err != nil {
		t.Fatal(err)
	}
	secondRecipe := `pkgname=opr-dependent-fixture
pkgver=1.0
pkgrel=1
pkgdesc='OPR dependent fixture'
arch=('x86_64')
license=('MIT')
depends=('opr-dependency-fixture=1.0-1')
source=()
sha256sums=()

build() { :; }

package() {
  install -Dm755 /dev/stdin "$pkgdir/usr/bin/opr-dependent-fixture" <<'EOF'
#!/bin/sh
test -f /usr/share/opr-dependency-fixture/provider
EOF
}
`
	if err := writeRecipe(secondWork, secondRecipe); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.build(ctx, secondWork, secondOutput, "dependency-e2e-second-build", 1700000000, prepared.ref); err != nil {
		t.Fatal(err)
	}
	secondArtifact, err := findArtifact(secondOutput, "opr-dependent-fixture")
	if err != nil {
		t.Fatal(err)
	}
	smokeLog, err := runner.smoke(ctx, secondArtifact, "dependency-e2e-second-smoke", prepared.ref, []string{"/usr/bin/opr-dependent-fixture"})
	if err != nil {
		t.Fatalf("smoke failed: %v\n%s", err, smokeLog)
	}
	metadata, err := readPackageMetadata(secondOutput, secondArtifact, Job{PackageName: "opr-dependent-fixture", Version: "1.0", Pkgrel: 1, Architecture: "x86_64"})
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Depends) != 1 || metadata.Depends[0] != "opr-dependency-fixture=1.0-1" {
		encoded, _ := json.Marshal(metadata)
		t.Fatalf("dependent package metadata = %s", encoded)
	}
	if signatureSize <= 0 {
		t.Fatal("empty dependency signature")
	}
}

func mustReadFile(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

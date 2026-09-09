package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Set OPR_WORKER_E2E_IMAGE to a local digest-pinned Arch builder image to run
// this test. It is opt-in because it downloads a pinned source archive and
// needs a local OCI runtime and several minutes of disk/CPU.
func TestRunnerExecuteNativeOCI(t *testing.T) {
	imageRef := os.Getenv("OPR_WORKER_E2E_IMAGE")
	if imageRef == "" {
		t.Skip("OPR_WORKER_E2E_IMAGE is not set")
	}
	marker := "@sha256:"
	index := strings.LastIndex(imageRef, marker)
	if index < 0 {
		t.Fatalf("OPR_WORKER_E2E_IMAGE must include @sha256 digest")
	}
	imageDigest := imageRef[index+1:]
	if err := validateImageReference(imageRef, imageDigest); err != nil {
		t.Fatal(err)
	}
	architecture := os.Getenv("OPR_WORKER_E2E_ARCH")
	if architecture == "" {
		architecture = "x86_64"
	}
	if architecture != "x86_64" && architecture != "aarch64" {
		t.Fatalf("OPR_WORKER_E2E_ARCH must be x86_64 or aarch64")
	}

	source := Source{
		Name:   "hello-2.12.tar.gz",
		URL:    "https://ftp.gnu.org/gnu/hello/hello-2.12.tar.gz",
		SHA256: "cf04af86dc085268c5f4470fbae49b18afbc221b78096aab842d934a76bad0ab",
	}
	fetched, err := fetchSources(context.Background(), []Source{source}, t.TempDir(), defaultMaxSourceBytes, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	recipe := fmt.Sprintf(`pkgname=opr-hello-real
pkgver=2.12
pkgrel=1
arch=('%s')
license=('GPL-3.0-or-later')
source=('hello-2.12.tar.gz')
sha256sums=('cf04af86dc085268c5f4470fbae49b18afbc221b78096aab842d934a76bad0ab')

build() {
  cd "hello-$pkgver"
	test "$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%%f\n')" = lo
  ! grep -q '^00000000' /proc/net/route
  if /usr/bin/timeout 2 /usr/bin/bash -c 'exec 3<>/dev/tcp/198.51.100.1/80'; then
    echo 'offline build unexpectedly reached network' >&2
    return 1
  fi
  if touch /etc/opr-escape-test; then return 1; fi
  test ! -e /var/run/docker.sock || return 1
  test ! -e /run/podman/podman.sock || return 1
  ./configure --prefix=/usr
  make
}

package() {
  cd "hello-$pkgver"
  make DESTDIR="$pkgdir" install
}
`, architecture)
	job := Job{
		ID:              "runner-e2e",
		LeaseToken:      "lease",
		LeaseExpiresAt:  time.Now().Add(10 * time.Minute).Format(time.RFC3339),
		RevisionID:      "revision-e2e",
		PackageName:     "opr-hello-real",
		Version:         "2.12",
		Pkgrel:          1,
		Architecture:    architecture,
		Recipe:          recipe,
		RecipeSHA256:    hashBytes([]byte(recipe)),
		SourceDateEpoch: 1700000000,
		ImageDigest:     imageDigest,
		ImageRef:        imageRef,
		Sources:         []Source{source},
		Dependencies:    []string{"bash", "tree"},
		SmokeCommands: []string{
			`test "$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n')" = lo`,
			`! grep -q '^00000000' /proc/net/route`,
			`if touch /etc/opr-escape-test; then exit 1; fi`,
			`test -f /usr/share/man/man1/hello.1.gz || test -f /usr/share/man/man1/hello.1`,
			`/usr/bin/hello --version | /usr/bin/grep -F '2.12'`,
		},
		Surface: "binary",
	}
	runtime := os.Getenv("OPR_WORKER_E2E_RUNTIME")
	if runtime == "" {
		runtime = "podman"
	}
	runner := Runner{Runtime: runtime, RuntimeImage: os.Getenv("OPR_WORKER_E2E_RUNTIME_IMAGE"), StateDir: t.TempDir(), BuildTimeout: 10 * time.Minute}
	if runner.RuntimeImage == "" {
		t.Fatal("OPR_WORKER_E2E_RUNTIME_IMAGE is required")
	}
	// Syntax checks must reject each execution surface without sourcing shell.
	for _, surface := range []string{"recipe", "smoke", "public"} {
		invalid := job
		switch surface {
		case "recipe":
			invalid.Recipe = "if then"
		case "smoke":
			invalid.SmokeCommands = []string{"if then"}
		case "public":
			invalid.PublicRecipe = "if then"
		}
		if _, err := runner.checkShell(context.Background(), invalid, "invalid-"+surface, imageRef); err == nil {
			t.Fatalf("accepted invalid %s shell", surface)
		}
	}
	noexec := job
	noexec.Recipe = "exit 97\n" + job.Recipe
	if output, err := runner.checkShell(context.Background(), noexec, "noexec", imageRef); err != nil {
		t.Fatalf("syntax check executed recipe: %v %s", err, output)
	}
	missing, err := runner.Execute(context.Background(), job, fetched)
	if err == nil || missing.RuntimeAnalysis == nil || !strings.Contains(err.Error(), "dependency-detected-not-included glibc") {
		t.Fatalf("undeclared runtime dependency was not detected: %v\n%s", err, missing.Log)
	}
	job.Recipe = strings.Replace(recipe, "license=('GPL-3.0-or-later')", "license=('GPL-3.0-or-later')\ndepends=('glibc')", 1)
	job.RecipeSHA256 = hashBytes([]byte(job.Recipe))
	result, err := runner.Execute(context.Background(), job, fetched)
	if err != nil {
		t.Fatalf("%v\n%s", err, result.Log)
	}
	defer result.Cleanup()
	if result.BuildEnvironment == nil || result.RuntimeEnvironment == nil || result.RuntimeAnalysis == nil {
		t.Fatal("build and runtime evidence missing")
	}
	for _, entry := range result.RuntimeEnvironment.Packages {
		if strings.HasPrefix(entry, "make ") || strings.HasPrefix(entry, "tree ") {
			t.Fatalf("build-only dependency leaked into runtime: %s", entry)
		}
	}
	if destination := os.Getenv("OPR_WORKER_E2E_OUTPUT"); destination != "" {
		retainE2EArtifact(t, result.ArtifactPath, destination)
	}
	if result.ArtifactPath == "" || result.SmokePassed == false {
		t.Fatalf("runner result = %+v", result)
	}
	if architecture == "x86_64" && result.InstalledSize != 118848 {
		t.Fatalf("installed size = %d, want 118848", result.InstalledSize)
	}
	if architecture == "aarch64" && result.InstalledSize <= 0 {
		t.Fatalf("installed size = %d, want positive value", result.InstalledSize)
	}
	if _, err := os.Stat(result.ArtifactPath); err != nil {
		t.Fatalf("artifact missing: %v", err)
	}
}

func retainE2EArtifact(t *testing.T, artifact, destination string) {
	t.Helper()
	abs, err := filepath.Abs(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(abs), 0o700); err != nil {
		t.Fatal(err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(abs), ".acceptance-*")
	if err != nil {
		t.Fatalf("retain artifact: %v", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	input, err := os.Open(artifact)
	if err != nil {
		temporary.Close()
		t.Fatalf("retain artifact: %v", err)
	}
	if _, err := io.Copy(temporary, input); err != nil {
		input.Close()
		temporary.Close()
		t.Fatalf("retain artifact: %v", err)
	}
	input.Close()
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		t.Fatalf("retain artifact: %v", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		t.Fatalf("retain artifact: %v", err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatalf("retain artifact: %v", err)
	}
	if err := os.Rename(temporaryName, abs); err != nil {
		t.Fatalf("retain artifact: %v", err)
	}
	for _, member := range []string{".PKGINFO", ".BUILDINFO"} {
		data, err := exec.Command("bsdtar", "-xOf", artifact, member).Output()
		if err != nil {
			t.Fatalf("decode %s: %v", member, err)
		}
		metadata := abs + member
		if err := os.WriteFile(metadata, data, 0o600); err != nil {
			t.Fatalf("retain %s: %v", member, err)
		}
	}
}

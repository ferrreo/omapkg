package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestBuilderArgsDisableNetworkAndDropCapabilities(t *testing.T) {
	runner := Runner{Runtime: "podman", Image: "registry.invalid/opr-builder@sha256:" + strings.Repeat("a", 64)}
	args := runner.baseContainerArgs("opr-build-test", "none", "/opr/work", []mount{{Source: "/tmp/work", Target: "/opr/work"}, {Source: "/tmp/out", Target: "/opr/output", ReadOnly: true}}, map[string]string{"SOURCE_DATE_EPOCH": "1700000000"}, "")
	joined := strings.Join(args, " ")
	for _, expected := range []string{"--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges:true", "--pull=never", "--entrypoint ", "dst=/opr/output,readonly", "SOURCE_DATE_EPOCH=1700000000"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("runner args missing %q: %s", expected, joined)
		}
	}
}

func TestMakepkgDebugOverridePreservesExistingNegation(t *testing.T) {
	command := exec.Command("bash", "-ceu", `OPTIONS=('debug' '!debug' 'strip'); OPTIONS=("${OPTIONS[@]/#debug/!debug}"); printf '%s\n' "${OPTIONS[*]}"`)
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(output)); got != "!debug !debug strip" {
		t.Fatalf("OPTIONS = %q", got)
	}
}

func TestSmokeInstallScriptRemovesImageNoExtractRules(t *testing.T) {
	script := smokeInstallScript()
	for _, expected := range []string{"cp /etc/pacman.conf \"$config\"", "NoExtract", "pacman --config \"$config\" -U --noconfirm /package.pkg.tar.zst", "rm -f \"$config\""} {
		if !strings.Contains(script, expected) {
			t.Fatalf("smoke install script missing %q: %s", expected, script)
		}
	}
	if strings.Contains(script, "--nodeps") {
		t.Fatal("smoke install script disables dependency validation")
	}
}

func TestFindArtifactRequiresSinglePackage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "opr-hello-1-1-x86_64.pkg.tar.zst"), []byte("pkg"), 0o600); err != nil {
		t.Fatal(err)
	}
	filename, err := findArtifact(dir, "opr-hello")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filename) != "opr-hello-1-1-x86_64.pkg.tar.zst" {
		t.Fatalf("unexpected artifact %s", filename)
	}
	if err := os.WriteFile(filepath.Join(dir, "opr-hello-debug-1-1-x86_64.pkg.tar.zst"), []byte("pkg"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := findArtifact(dir, "opr-hello"); err == nil {
		t.Fatal("multiple artifacts were accepted")
	}
	for _, entry := range []string{"opr-hello-1-1-x86_64.pkg.tar.zst", "opr-hello-debug-1-1-x86_64.pkg.tar.zst"} {
		if err := os.Remove(filepath.Join(dir, entry)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "other-1-1-x86_64.pkg.tar.zst"), []byte("pkg"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := findArtifact(dir, "opr-hello"); err == nil {
		t.Fatal("unrelated artifact was accepted")
	}
}

func TestPackageMetadataBindsOutputToJob(t *testing.T) {
	output := t.TempDir()
	if err := os.WriteFile(filepath.Join(output, ".PKGINFO"), []byte("# generated\npkgname = opr-hello\npkgver = 2.12-3\narch = x86_64\nsize = 118848\ndepend = glibc\ndepend = lib:libc.so.6\ndepend = libOpenCL.so=1-64\nprovides = opr-hello=2.12-3\nprovides = libOpenCL.so=1-64\nconflict = opr-hello-git>=2.12\nreplaces = old-hello\ninstalled = bash-5.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata, err := readPackageMetadata(output, filepath.Join(output, "opr-hello-2.12-3-x86_64.pkg.tar.zst"), Job{PackageName: "opr-hello", Version: "2.12", Pkgrel: 3, Architecture: "x86_64"})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.InstalledSize != 118848 {
		t.Fatalf("installed size = %d", metadata.InstalledSize)
	}
	if got, want := strings.Join(metadata.Depends, ","), "glibc,lib:libc.so.6,libOpenCL.so=1-64"; got != want {
		t.Fatalf("depends = %q, want %q", got, want)
	}
	if got, want := strings.Join(metadata.Provides, ","), "opr-hello=2.12-3,libOpenCL.so=1-64"; got != want {
		t.Fatalf("provides = %q, want %q", got, want)
	}
	if got, want := strings.Join(metadata.Conflicts, ","), "opr-hello-git>=2.12"; got != want {
		t.Fatalf("conflicts = %q, want %q", got, want)
	}
	if got, want := strings.Join(metadata.Replaces, ","), "old-hello"; got != want {
		t.Fatalf("replaces = %q, want %q", got, want)
	}
	dependencyPlan, _ := dependencyPlanFixture()
	provenanceJob := Job{ID: "job-1", RevisionID: "revision-1", PackageName: "opr-hello", Version: "2.12", Pkgrel: 3, Architecture: "x86_64", RecipeSHA256: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), SourceDateEpoch: 1, DependencyPlan: dependencyPlan}
	provenance, err := provenanceFor(provenanceJob, "worker-1", strings.Repeat("c", 64), metadata.InstalledSize, metadata, "2026-09-05T00:00:00Z", "2026-09-05T00:01:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		PackageMetadata packageMetadata `json:"packageMetadata"`
		DependencyPlan  *DependencyPlan `json:"dependencyPlan"`
	}
	if err := json.Unmarshal([]byte(provenance), &decoded); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(decoded.PackageMetadata.Depends, ","), "glibc,lib:libc.so.6,libOpenCL.so=1-64"; got != want {
		t.Fatalf("provenance depends = %q, want %q", got, want)
	}
	if decoded.DependencyPlan == nil || decoded.DependencyPlan.Packages[0].ReleaseID != dependencyPlan.Packages[0].ReleaseID {
		t.Fatal("provenance dependency plan was not preserved")
	}
	if _, err := provenanceFor(Job{}, "worker-1", "", metadata.InstalledSize+1, metadata, "2026-09-05T00:00:00Z", "2026-09-05T00:01:00Z"); err == nil {
		t.Fatal("mismatched provenance installed size was accepted")
	}
	if _, err := readPackageMetadata(output, "artifact", Job{PackageName: "opr-hello", Version: "2.12", Pkgrel: 2, Architecture: "x86_64"}); err == nil {
		t.Fatal("mismatched package version was accepted")
	}
}

func TestPackageMetadataRejectsInvalidRelationsAndBounds(t *testing.T) {
	base := "pkgname = demo\npkgver = 1-1\narch = x86_64\nsize = 1\n"
	empty, err := parsePackageMetadata([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if empty.Depends == nil || empty.Provides == nil || empty.Conflicts == nil || empty.Replaces == nil {
		t.Fatal("empty relation lists must be encoded as arrays")
	}
	ordinary, err := parsePackageMetadata([]byte(base + "depend = libfoo.so>=1-64\nconflict = libfoo.so\n"))
	if err != nil || len(ordinary.Depends) != 1 || ordinary.Depends[0] != "libfoo.so>=1-64" || len(ordinary.Conflicts) != 1 || ordinary.Conflicts[0] != "libfoo.so" {
		t.Fatalf("lowercase .so package relation was rejected: %+v, err=%v", ordinary, err)
	}
	for _, relation := range []string{"depend = ../escape\n", "provides = demo>1\n", "provides = lib:libfoo.so.1=1-64\n", "depend = libOpenCL.so.1\n", "depend = libOpenCL.so>1-64\n", "conflict = demo with-space\n", "conflict = lib:libfoo.so.1\n", "conflict = libOpenCL.so=1-64\n"} {
		if _, err := parsePackageMetadata([]byte(base + relation)); err == nil {
			t.Fatalf("invalid relation accepted: %q", relation)
		}
	}
	if _, err := parsePackageMetadata([]byte("pkgname = demo\npkgver = 1-1\narch = x86_64\nsize = 9007199254740992\n")); err == nil {
		t.Fatal("JSON-unsafe installed size accepted")
	}
	var tooMany strings.Builder
	tooMany.WriteString(base)
	for index := 0; index <= maxPackageRelations; index++ {
		tooMany.WriteString("depend = dep")
		tooMany.WriteString(strconv.Itoa(index))
		tooMany.WriteByte('\n')
	}
	if _, err := parsePackageMetadata([]byte(tooMany.String())); err == nil {
		t.Fatal("oversized relation list accepted")
	}
}

func TestPrivateImagePullKeepsCredentialsOutOfArguments(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "runtime.log")
	runtime := filepath.Join(dir, "docker")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$TMPDIR/runtime.log"
case "$1" in
login)
  printf '{}' > "$3"
  chmod 600 "$3"
  cat >/dev/null
  ;;
--config)
  printf '{}' > "$2/config.json"
  chmod 600 "$2/config.json"
  cat >/dev/null
  ;;
pull) ;;
*) exit 1 ;;
esac
`
	if err := os.WriteFile(runtime, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	runner := Runner{Runtime: runtime}
	err := runner.pullPrivateImage(context.Background(), "registry.cloudflare.com/omarpkg/builder@sha256:"+strings.Repeat("a", 64), RegistryCredentials{
		Registry: "registry.cloudflare.com",
		Username: "worker",
		Password: "ephemeral-secret",
	})
	if err != nil {
		logged, _ := os.ReadFile(logFile)
		t.Fatalf("%v (runtime log: %s)", err, logged)
	}
	logged, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), "ephemeral-secret") || !strings.Contains(string(logged), "--password-stdin") || !strings.Contains(string(logged), "--config") || !strings.Contains(string(logged), "pull") {
		t.Fatalf("runtime arguments leaked credentials or missed auth flags: %s", logged)
	}
}

func TestMissingPrivateImageRequestsCredentialsBeforePull(t *testing.T) {
	dir := t.TempDir()
	runtime := filepath.Join(dir, "podman")
	digest := "sha256:" + strings.Repeat("b", 64)
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$TMPDIR/runtime.log"
case "$1" in
image)
  if test -f "$TMPDIR/inspected"; then
    printf 'registry.cloudflare.com/omarpkg/builder@` + digest + `\n'
    exit 0
  fi
  : > "$TMPDIR/inspected"
  exit 1
  ;;
login)
  if test "$2" = --authfile; then
    printf '{}' > "$3"
    chmod 600 "$3"
    cat >/dev/null
  fi
  ;;
pull) ;;
*) exit 1 ;;
esac
`
	if err := os.WriteFile(runtime, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	runner := Runner{Runtime: runtime}
	credentialsRequested := 0
	getCredentials := func(context.Context, string, string) (RegistryCredentials, error) {
		credentialsRequested++
		return RegistryCredentials{Registry: "registry.cloudflare.com", Username: "worker", Password: "ephemeral-secret"}, nil
	}
	imageRef := "registry.cloudflare.com/omarpkg/builder@" + digest
	if err := runner.ensureImageReference(context.Background(), imageRef, digest, getCredentials, "job-1", "lease"); err != nil {
		t.Fatal(err)
	}
	if credentialsRequested != 1 {
		t.Fatalf("credential requests = %d, want 1", credentialsRequested)
	}
	if err := runner.ensureImageReference(context.Background(), imageRef, digest, func(context.Context, string, string) (RegistryCredentials, error) {
		return RegistryCredentials{}, errors.New("credential endpoint should not be called for cached image")
	}, "job-1", "lease"); err != nil {
		t.Fatal(err)
	}
	logged, err := os.ReadFile(filepath.Join(dir, "runtime.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logged), "ephemeral-secret") || !strings.Contains(string(logged), "--authfile") || !strings.Contains(string(logged), "--password-stdin") {
		t.Fatalf("private pull args leaked credentials or missed stdin auth: %s", logged)
	}
}

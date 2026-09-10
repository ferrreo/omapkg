package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testOutputContract(architecture string) *outputContract {
	contract := &outputContract{SchemaVersion: 2, Outputs: []expectedOutput{
		{Name: "opr-split-core", FullVersion: "2:1.2-3.1", Architecture: architecture},
		{Name: "opr-split-addon", FullVersion: "2:1.2-3.1", Architecture: architecture},
		{Name: "opr-split-docs", FullVersion: "2:1.2-3.1", Architecture: "any"},
	}}
	contract.RuntimeGroups = [][]string{{"opr-split-core", "opr-split-addon", "opr-split-docs"}}
	contract.Cohort.ID = "split-cohort"
	contract.Cohort.Revision = 1
	contract.Cohort.ManifestSHA256 = strings.Repeat("c", 64)
	return contract
}

func TestOutputContractRejectsAmbiguousIdentity(t *testing.T) {
	job := Job{OutputContract: testOutputContract("x86_64"), Architecture: "x86_64", Surface: "binary", Attempt: 1}
	if err := validateOutputContract(job); err != nil {
		t.Fatal(err)
	}
	if outputFilename(job.OutputContract.Outputs[0]) != "opr-split-core-2:1.2-3.1-x86_64.pkg.tar.zst" {
		t.Fatal("full package version was not preserved in filename")
	}
	for _, mutation := range []func(*Job){
		func(j *Job) { j.OutputContract.Outputs = append(j.OutputContract.Outputs, j.OutputContract.Outputs[0]) },
		func(j *Job) { j.OutputContract.Outputs[0].Architecture = "aarch64" },
		func(j *Job) { j.OutputContract.Outputs[0].FullVersion = "1:2:3-1" },
		func(j *Job) { j.Attempt = 0 },
	} {
		candidate := job
		candidate.OutputContract = testOutputContract("x86_64")
		mutation(&candidate)
		if validateOutputContract(candidate) == nil {
			t.Fatal("accepted invalid output contract")
		}
	}
}

// Native acceptance includes split metadata, epochs, subreleases, a portable
// output, local sibling dependency installation, and exact-set rejection.
// A source named makepkg.conf must survive helper configuration unchanged.
func TestRunnerSplitOutputsNativeOCI(t *testing.T) {
	image := os.Getenv("OPR_WORKER_E2E_IMAGE")
	if image == "" {
		t.Skip("OPR_WORKER_E2E_IMAGE is not set")
	}
	runtimeImage := os.Getenv("OPR_WORKER_E2E_RUNTIME_IMAGE")
	if runtimeImage == "" {
		t.Fatal("OPR_WORKER_E2E_RUNTIME_IMAGE is required")
	}
	architecture := os.Getenv("OPR_WORKER_E2E_ARCH")
	if architecture == "" {
		architecture = "x86_64"
	}
	directory := t.TempDir()
	contents := []byte("#include <stdio.h>\nint main(void) { puts(\"split-output-ok\"); return 0; }\n")
	source := Source{Name: "makepkg.conf", URL: "https://example.org/sample.c", SHA256: hashBytes(contents)}
	path := filepath.Join(directory, source.Name)
	if err := os.WriteFile(path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
	recipe := fmt.Sprintf(`pkgbase=opr-split-fixture
pkgname=('opr-split-core' 'opr-split-core-full' 'opr-split-addon' 'opr-split-docs')
pkgver=1.2
pkgrel=3.1
epoch=2
arch=('%s')
license=('MIT')
source=('makepkg.conf')
sha256sums=('%s')
build() { cc -x c -O2 -o split makepkg.conf; }
package_opr-split-core() {
  depends=('glibc')
  install -Dm755 split "$pkgdir/usr/bin/opr-split-core"
}
package_opr-split-core-full() {
  depends=('glibc')
  conflicts=('opr-split-core')
  provides=('opr-split-core=2:1.2-3.1')
  install -Dm755 split "$pkgdir/usr/bin/opr-split-core"
}
package_opr-split-addon() {
  depends=('opr-split-core=2:1.2-3.1')
  install -Dm644 makepkg.conf "$pkgdir/usr/share/opr-split/addon.c"
}
package_opr-split-docs() {
  arch=('any')
  depends=()
  install -Dm644 makepkg.conf "$pkgdir/usr/share/doc/opr-split/sample.c"
}
`, architecture, source.SHA256)
	job := Job{ID: "split-native", LeaseToken: "test", LeaseExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), RevisionID: "split-revision",
		PackageName: "opr-split-fixture", Version: "1.2", Pkgrel: 3, Architecture: architecture, Recipe: recipe, RecipeSHA256: hashBytes([]byte(recipe)),
		SourceDateEpoch: 1700000000, ImageRef: image, ImageDigest: image[strings.LastIndex(image, "@")+1:], Sources: []Source{source}, Surface: "binary", Attempt: 1,
		OutputContract: testOutputContract(architecture), SmokeCommands: []string{"/usr/bin/opr-split-core | grep -qx split-output-ok", `if pacman -Q opr-split-addon >/dev/null 2>&1; then test -f /usr/share/opr-split/addon.c; else pacman -Q opr-split-core-full >/dev/null; fi`, "test -f /usr/share/doc/opr-split/sample.c"}}
	job.OutputContract.Outputs = append(job.OutputContract.Outputs, expectedOutput{Name: "opr-split-core-full", FullVersion: "2:1.2-3.1", Architecture: architecture})
	job.OutputContract.RuntimeGroups = [][]string{{"opr-split-core", "opr-split-addon", "opr-split-docs"}, {"opr-split-core-full", "opr-split-docs"}}
	runtime := os.Getenv("OPR_WORKER_E2E_RUNTIME")
	if runtime == "" {
		runtime = "podman"
	}
	runner := Runner{Runtime: runtime, RuntimeImage: runtimeImage, StateDir: directory, BuildTimeout: 15 * time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	result, err := runner.Execute(ctx, job, []fetchedSource{{Source: source, Path: path}})
	if err != nil {
		t.Fatalf("%v\n%s", err, result.Log)
	}
	defer result.Cleanup()
	if !result.SmokePassed || len(result.Outputs) != 4 || len(result.RuntimeTests) != 2 {
		t.Fatal("incomplete native split build")
	}
	for _, output := range result.Outputs {
		if output.PackageMetadata.FullVersion != "2:1.2-3.1" {
			t.Fatal("missing full version")
		}
	}
	for _, test := range result.RuntimeTests {
		if !test.SmokePassed || len(test.Analyses) != len(test.Outputs) {
			t.Fatal("incomplete installation test group")
		}
		for _, item := range test.Analyses {
			if item.RuntimeAnalysis == nil || item.RuntimeAnalysis.NativeCode == nil {
				t.Fatal("missing content evidence")
			}
			if item.Name == "opr-split-docs" && len(*item.RuntimeAnalysis.NativeCode) != 0 {
				t.Fatal("portable output contains native code")
			}
		}
	}
	provenance, err := provenanceForOutputs(job, "native-test-worker", result, "2026-09-09T00:00:00Z", "2026-09-09T00:01:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if destination := os.Getenv("OPR_WORKER_E2E_OUTPUT"); destination != "" {
		if err := os.MkdirAll(destination, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, "split-provenance.json"), []byte(provenance), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, output := range result.Outputs {
			retainE2EArtifact(t, output.Path, filepath.Join(destination, output.Filename))
		}
	}
	var parsed map[string]any
	if json.Unmarshal([]byte(provenance), &parsed) != nil || parsed["schemaVersion"] != float64(2) {
		t.Fatal("invalid v2 report")
	}
	job.OutputContract.Outputs = append(job.OutputContract.Outputs, expectedOutput{Name: "missing-split", FullVersion: "2:1.2-3.1", Architecture: architecture})
	if _, err := runner.collectOutputs(ctx, filepath.Dir(result.Outputs[0].Path), "missing-split", image, job.PackageName, job.OutputContract); err == nil {
		t.Fatal("missing output accepted")
	}
}

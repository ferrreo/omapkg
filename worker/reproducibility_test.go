package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompareReproducibilityOutputsUsesFinalBytes(t *testing.T) {
	root := t.TempDir()
	primaryPath := filepath.Join(root, "primary.pkg.tar.zst")
	secondaryPath := filepath.Join(root, "secondary.pkg.tar.zst")
	if err := os.WriteFile(primaryPath, []byte("header\npayload-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondaryPath, []byte("header\npayload-b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	primary, err := inspectReproducibilityFile(root, primaryPath)
	if err != nil {
		t.Fatal(err)
	}
	secondary, err := inspectReproducibilityFile(root, secondaryPath)
	if err != nil {
		t.Fatal(err)
	}
	primary.Filename, secondary.Filename = "fixture.pkg.tar.zst", "fixture.pkg.tar.zst"
	differences, err := CompareReproducibilityOutputs([]ReproducibilityOutput{primary}, []ReproducibilityOutput{secondary})
	if err != nil {
		t.Fatal(err)
	}
	if len(differences) != 1 || differences[0].Reason != "byte-mismatch" || differences[0].FirstByte <= 0 {
		t.Fatalf("differences = %+v", differences)
	}
}

func TestRunReproducibilityPairUsesFreshRootsGapAndPreservesMismatch(t *testing.T) {
	root := t.TempDir()
	cleanupCalls := 0
	build := func(ctx context.Context, request ReproducibilityBuildRequest) (ReproducibilityBuild, error) {
		output := filepath.Join(request.Root, "fixture.pkg.tar.zst")
		evidence := filepath.Join(request.Root, "environment.json")
		command := exec.CommandContext(ctx, "/bin/sh", "-ceu", `date +%s%N > "$1"; cp "$1" "$2"`, "reproducibility-fixture", evidence, output)
		command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
		if log, err := command.CombinedOutput(); err != nil {
			return ReproducibilityBuild{Log: string(log)}, err
		}
		return ReproducibilityBuild{OutputPaths: []string{output}, EvidencePaths: []string{evidence}, Log: request.Attempt, Cleanup: func() { cleanupCalls++ }}, nil
	}
	result, err := RunReproducibilityPair(context.Background(), ReproducibilitySpec{Root: root, Gap: 10 * time.Millisecond, PreserveOnSuccess: true, Build: build})
	if !errors.Is(err, ErrReproducibilityMismatch) {
		t.Fatalf("error = %v, want mismatch", err)
	}
	if result.Status != ReproducibilityMismatch || result.Gap < 10*time.Millisecond || result.FailureRoot != root {
		t.Fatalf("result = %+v", result)
	}
	if result.Primary.Root == result.Secondary.Root || result.Primary.Outputs[0].Path == result.Secondary.Outputs[0].Path {
		t.Fatal("reproducibility pair reused a build root or output path")
	}
	if cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want retained failed outputs", cleanupCalls)
	}
	for _, path := range []string{
		filepath.Join(result.Primary.Root, "reproducibility-attempt.json"),
		filepath.Join(result.Secondary.Root, "reproducibility-attempt.json"),
		filepath.Join(root, "reproducibility-diff.json"),
	} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("missing retained evidence %s: %v", path, statErr)
		}
	}
}

func TestRunReproducibilityPairRunsDeterministicBuilderTwice(t *testing.T) {
	root := t.TempDir()
	runs := 0
	build := func(ctx context.Context, request ReproducibilityBuildRequest) (ReproducibilityBuild, error) {
		runs++
		output := filepath.Join(request.Root, "fixture.pkg.tar.zst")
		command := exec.CommandContext(ctx, "/bin/sh", "-ceu", `printf '%s' 'deterministic fixture' > "$1"`, "reproducibility-fixture", output)
		command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TZ=UTC"}
		if log, err := command.CombinedOutput(); err != nil {
			return ReproducibilityBuild{Log: string(log)}, err
		}
		return ReproducibilityBuild{OutputPaths: []string{output}}, nil
	}
	result, err := RunReproducibilityPair(context.Background(), ReproducibilitySpec{Root: root, Gap: 10 * time.Millisecond, PreserveOnSuccess: true, Build: build})
	if err != nil || result.Status != ReproducibilityIndependentlyReproduced || runs != 2 || len(result.Differences) != 0 {
		t.Fatalf("result = %+v, err = %v, runs = %d", result, err, runs)
	}
}

func TestUnexpectedOutputFilesRejectsUnreviewedFiles(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"fixture.pkg.tar.zst", "fixture-build.log", ".PKGINFO", "unexpected.tar"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := unexpectedOutputFiles(directory, map[string]bool{"fixture.pkg.tar.zst": true, ".PKGINFO": true})
	if len(got) != 1 || got[0] != "unexpected.tar" {
		t.Fatalf("unexpected outputs = %v", got)
	}
}

// This opt-in test calls Runner.Execute twice; it is skipped when no local
// pinned builder/runtime pair is available. It deliberately uses local source
// bytes, so the pair never downloads or publishes anything.
func TestReproducibilityHarnessNativeOCI(t *testing.T) {
	imageRef := os.Getenv("OPR_WORKER_REPRO_IMAGE")
	runtimeImage := os.Getenv("OPR_WORKER_REPRO_RUNTIME_IMAGE")
	if imageRef == "" || runtimeImage == "" {
		t.Skip("OPR_WORKER_REPRO_IMAGE and OPR_WORKER_REPRO_RUNTIME_IMAGE are not set")
	}
	marker := "@sha256:"
	index := strings.LastIndex(imageRef, marker)
	if index < 0 {
		t.Fatal("OPR_WORKER_REPRO_IMAGE must include @sha256 digest")
	}
	imageDigest := imageRef[index+1:]
	if err := validateImageReference(imageRef, imageDigest); err != nil {
		t.Fatal(err)
	}
	runtimeIndex := strings.LastIndex(runtimeImage, marker)
	if runtimeIndex < 0 {
		t.Fatal("OPR_WORKER_REPRO_RUNTIME_IMAGE must include @sha256 digest")
	}
	sourceBytes := []byte("reproducibility fixture\n")
	sourceRoot := t.TempDir()
	sourcePath := filepath.Join(sourceRoot, "fixture.txt")
	if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	source := Source{Name: "fixture.txt", URL: "https://example.com/fixture.txt", SHA256: hashBytes(sourceBytes)}
	recipe := fmt.Sprintf(`pkgname=opr-repro-fixture
pkgver=1
pkgrel=1
arch=('x86_64')
license=('MIT')
source=('fixture.txt')
sha256sums=('%s')

build() {
  install -Dm644 fixture.txt output/fixture.txt
}

package() {
  install -Dm644 output/fixture.txt "$pkgdir/usr/share/opr-repro-fixture/fixture.txt"
}
`, source.SHA256)
	architecture := "x86_64"
	baseJob := Job{LeaseToken: "lease", LeaseExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), RevisionID: "repro-revision", PackageName: "opr-repro-fixture", Version: "1", Pkgrel: 1,
		Architecture: architecture, Recipe: recipe, RecipeSHA256: hashBytes([]byte(recipe)), SourceDateEpoch: 1700000000, ImageDigest: imageDigest, ImageRef: imageRef,
		Sources: []Source{source}, SmokeCommands: []string{"test -f /usr/share/opr-repro-fixture/fixture.txt"}, Surface: "binary"}
	buildJob := func(job Job) ReproducibilityBuilder {
		return func(ctx context.Context, request ReproducibilityBuildRequest) (ReproducibilityBuild, error) {
			job.ID = "repro-" + request.Attempt
			runner := Runner{Runtime: os.Getenv("OPR_WORKER_REPRO_RUNTIME"), RuntimeImage: runtimeImage, StateDir: request.Root, BuildTimeout: 15 * time.Minute}
			if runner.Runtime == "" {
				runner.Runtime = "podman"
			}
			result, buildErr := runner.Execute(ctx, job, []fetchedSource{{Source: source, Path: sourcePath}})
			if buildErr != nil {
				return ReproducibilityBuild{Log: result.Log, Cleanup: result.Cleanup}, buildErr
			}
			evidencePath := filepath.Join(request.Root, "build-environment.json")
			if err := os.WriteFile(evidencePath, []byte(fmt.Sprintf("%+v", result.BuildEnvironment)), 0o600); err != nil {
				if result.Cleanup != nil {
					result.Cleanup()
				}
				return ReproducibilityBuild{Log: result.Log, Cleanup: result.Cleanup}, err
			}
			return ReproducibilityBuild{OutputPaths: []string{result.ArtifactPath}, EvidencePaths: []string{evidencePath}, Log: result.Log, Cleanup: result.Cleanup}, nil
		}
	}
	result, err := RunReproducibilityPair(context.Background(), ReproducibilitySpec{Gap: 5 * time.Second, PreserveOnSuccess: true, Build: buildJob(baseJob)})
	if err != nil || result.Status != ReproducibilityIndependentlyReproduced {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	nondeterministic := baseJob
	nondeterministic.Recipe = strings.Replace(recipe, "  install -Dm644 fixture.txt output/fixture.txt", "  mkdir -p output; date +%s%N > output/fixture.txt", 1)
	nondeterministic.RecipeSHA256 = hashBytes([]byte(nondeterministic.Recipe))
	mismatch, mismatchErr := RunReproducibilityPair(context.Background(), ReproducibilitySpec{Gap: 5 * time.Second, PreserveOnSuccess: true, Build: buildJob(nondeterministic)})
	if !errors.Is(mismatchErr, ErrReproducibilityMismatch) || mismatch.Status != ReproducibilityMismatch {
		t.Fatalf("nondeterministic result = %+v, err = %v", mismatch, mismatchErr)
	}
}

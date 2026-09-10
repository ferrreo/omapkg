package main

// Native template acceptance fixtures. The matrix deliberately runs through
// Runner.Execute and RunReproducibilityPair; renderer-only tests live in the
// TypeScript suite. Missing tools or native capacity are reported as skipped
// (incomplete), never as a successful family build.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type templateMatrixFixture struct {
	id                 string
	arch               string
	sourceName         string
	source             func(*testing.T) []byte
	sourceForArch      func(*testing.T, string) []byte
	smoke              []string
	needs              []string
	locks              map[string]string
	appimageOffset     int
	split              bool
	plainInstallTarget string
}

func TestTemplateFamilyFixtureMatrixIsComplete(t *testing.T) {
	fixtures := templateMatrixFixtures()
	want := []string{"autotools-v1", "autotools-autoreconf-v1", "plain-make-v1", "cmake-v1", "meson-v1", "rust-v1", "python-v1", "node-npm-v1", "node-pnpm-v1", "node-yarn-v1", "electron-v1", "archive-v1", "deb-v1", "rpm-v1", "appimage-v1", "run-v1", "script-data-v1", "go-v2"}
	if len(fixtures) != len(want) {
		t.Fatalf("fixture count = %d, want %d", len(fixtures), len(want))
	}
	seen := make(map[string]bool, len(fixtures))
	for _, fixture := range fixtures {
		if seen[fixture.id] || fixture.sourceName == "" || fixture.source == nil && fixture.sourceForArch == nil || len(fixture.smoke) == 0 {
			t.Fatalf("invalid or duplicate fixture: %+v", fixture)
		}
		seen[fixture.id] = true
	}
	for _, id := range want {
		if !seen[id] {
			t.Fatalf("missing fixture for %s", id)
		}
	}
}

func TestTemplateFamilyReproducibilityNativeOCI(t *testing.T) {
	imageRef := os.Getenv("OPR_WORKER_TEMPLATE_MATRIX_IMAGE")
	runtimeImage := os.Getenv("OPR_WORKER_TEMPLATE_MATRIX_RUNTIME_IMAGE")
	if imageRef == "" || runtimeImage == "" {
		for _, fixture := range templateMatrixFixtures() {
			t.Run(fixture.id, func(t *testing.T) {
				t.Skip("incomplete: OPR_WORKER_TEMPLATE_MATRIX_IMAGE and OPR_WORKER_TEMPLATE_MATRIX_RUNTIME_IMAGE are not set")
			})
		}
		return
	}
	imageDigest := imageRef[strings.LastIndex(imageRef, "@")+1:]
	if err := validateImageReference(imageRef, imageDigest); err != nil {
		t.Fatal(err)
	}
	if index := strings.LastIndex(runtimeImage, "@"); index < 0 || validateImageReference(runtimeImage, runtimeImage[index+1:]) != nil {
		t.Fatal("OPR_WORKER_TEMPLATE_MATRIX_RUNTIME_IMAGE must be digest pinned")
	}
	architecture := os.Getenv("OPR_WORKER_TEMPLATE_MATRIX_ARCH")
	if architecture == "" {
		architecture = "x86_64"
	}
	if architecture != "x86_64" && architecture != "aarch64" {
		t.Fatalf("unsupported matrix architecture %q", architecture)
	}
	runtime := os.Getenv("OPR_WORKER_TEMPLATE_MATRIX_RUNTIME")
	if runtime == "" {
		runtime = "podman"
	}

	for _, fixture := range templateMatrixFixtures() {
		fixture := fixture
		t.Run(fixture.id, func(t *testing.T) {
			if fixture.arch != "any" && fixture.arch != architecture {
				t.Skipf("incomplete: fixture targets %s, worker targets %s", fixture.arch, architecture)
			}
			var sourceBytes []byte
			if fixture.sourceForArch != nil {
				sourceBytes = fixture.sourceForArch(t, architecture)
			} else {
				sourceBytes = fixture.source(t)
			}
			sourceRoot := t.TempDir()
			sourcePath := filepath.Join(sourceRoot, fixture.sourceName)
			if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			sourceHash := hashBytes(sourceBytes)
			recipe := renderedTemplateRecipe(t, fixture, sourceHash, architecture)
			job := Job{
				ID: "template-" + strings.ReplaceAll(fixture.id, ".", "-"), LeaseToken: "fixture-lease", LeaseExpiresAt: time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339),
				RevisionID: "template-matrix", PackageName: "opr-template-" + fixture.id, Version: "1.0.0", Pkgrel: 1,
				Architecture: architecture, Recipe: recipe, RecipeSHA256: hashBytes([]byte(recipe)), SourceDateEpoch: 1_700_000_000,
				ImageDigest: imageDigest, ImageRef: imageRef, Sources: []Source{{Name: fixture.sourceName, URL: "https://example.invalid/template/" + fixture.sourceName, SHA256: sourceHash}},
				SmokeCommands: fixture.smoke, Surface: "binary", Dependencies: fixtureRuntimeDependencies(fixture.id, architecture),
			}
			if fixture.split {
				job.Attempt = 1
				job.OutputContract = templateSplitOutputContract(job)
			}
			for _, need := range fixture.needs {
				if _, err := exec.LookPath(need); err != nil {
					t.Logf("incomplete: fixture declares missing host marker %s; builder image must provide it", need)
				}
			}
			validator := Runner{Runtime: runtime, Image: imageRef, ImageDigest: imageDigest, RuntimeImage: runtimeImage, StateDir: t.TempDir(), BuildTimeout: 20 * time.Minute}
			unsafeJob := job
			unsafeJob.Recipe = strings.Replace(recipe, "build() {", "build() {\n  if then", 1)
			if _, err := validator.checkShell(context.Background(), unsafeJob, "template-invalid-"+fixture.id, imageRef); err == nil {
				t.Fatal("invalid shell fixture passed recipe policy")
			}
			build := func(ctx context.Context, request ReproducibilityBuildRequest) (ReproducibilityBuild, error) {
				runner := Runner{Runtime: runtime, Image: imageRef, ImageDigest: imageDigest, RuntimeImage: runtimeImage, StateDir: request.Root, BuildTimeout: 20 * time.Minute}
				attempt := job
				attempt.ID = job.ID + "-" + request.Attempt
				attempt.Architecture = architecture
				result, err := runner.Execute(ctx, attempt, []fetchedSource{{Source: attempt.Sources[0], Path: sourcePath}})
				if err != nil {
					return ReproducibilityBuild{Log: result.Log, Cleanup: result.Cleanup}, err
				}
				evidence := filepath.Join(request.Root, "build-environment.json")
				if err := os.WriteFile(evidence, []byte(fmt.Sprintf("%+v", result.BuildEnvironment)), 0o600); err != nil {
					if result.Cleanup != nil {
						result.Cleanup()
					}
					return ReproducibilityBuild{Log: result.Log, Cleanup: result.Cleanup}, err
				}
				paths := make([]string, 0, len(result.Outputs))
				for _, output := range result.Outputs {
					paths = append(paths, output.Path)
				}
				if len(paths) == 0 {
					paths = []string{result.ArtifactPath}
				}
				return ReproducibilityBuild{OutputPaths: paths, EvidencePaths: []string{evidence}, Log: result.Log, Cleanup: result.Cleanup}, nil
			}
			pair, err := RunReproducibilityPair(context.Background(), ReproducibilitySpec{Gap: 5 * time.Second, PreserveOnSuccess: true, Build: build})
			recipeHash := hashBytes([]byte(recipe))
			if err != nil {
				writeTemplateMatrixEvidence(fixture, architecture, sourceHash, recipeHash, pair)
				if fixtureMissingCapacity(err) || fixtureMissingCapacityText(pair.Primary.Log) {
					t.Skipf("incomplete: %v\n%s", err, pair.Primary.Log)
				}
				t.Fatalf("fixture failed: %v\n%+v", err, pair)
			}
			if pair.Status != ReproducibilityIndependentlyReproduced {
				writeTemplateMatrixEvidence(fixture, architecture, sourceHash, recipeHash, pair)
				t.Fatalf("fixture status = %s, want independent reproduction", pair.Status)
			}
			writeTemplateMatrixEvidence(fixture, architecture, sourceHash, recipeHash, pair)
		})
	}
}

func fixtureRuntimeDependencies(id, architecture string) []string {
	if strings.HasPrefix(id, "node-") {
		return []string{"nodejs"}
	}
	if id == "python-v1" {
		return []string{"python", "glibc", "gcc-libs"}
	}
	if id == "electron-v1" {
		if architecture == "aarch64" {
			return []string{"electron43-arm-runtime", "bash"}
		}
		return []string{"electron43", "bash"}
	}
	if id == "script-data-v1" {
		return []string{"bash"}
	}
	return []string{"bash", "glibc", "gcc-libs"}
}

func writeTemplateMatrixEvidence(fixture templateMatrixFixture, architecture, sourceHash, recipeHash string, pair ReproducibilityPair) {
	directory := os.Getenv("OPR_WORKER_TEMPLATE_MATRIX_EVIDENCE")
	if directory == "" {
		return
	}
	if os.MkdirAll(directory, 0o700) != nil {
		return
	}
	evidence := struct {
		SchemaVersion int                 `json:"schemaVersion"`
		Family        string              `json:"family"`
		Architecture  string              `json:"architecture"`
		BuilderImage  string              `json:"builderImage"`
		RuntimeImage  string              `json:"runtimeImage"`
		SourceSHA256  string              `json:"sourceSha256"`
		RecipeSHA256  string              `json:"recipeSha256"`
		Pair          ReproducibilityPair `json:"pair"`
	}{1, fixture.id, architecture, os.Getenv("OPR_WORKER_TEMPLATE_MATRIX_IMAGE"), os.Getenv("OPR_WORKER_TEMPLATE_MATRIX_RUNTIME_IMAGE"), sourceHash, recipeHash, pair}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(directory, fixture.id+".json"), append(encoded, '\n'), 0o600)
}

func renderedTemplateRecipe(t *testing.T, fixture templateMatrixFixture, sourceHash, architecture string) string {
	t.Helper()
	repoRoot := os.Getenv("OPR_REPO_ROOT")
	if repoRoot == "" {
		working, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		repoRoot = filepath.Dir(working)
	}
	locks := make([]map[string]string, 0, len(fixture.locks))
	for name, digest := range fixture.locks {
		locks = append(locks, map[string]string{"name": name, "sha256": digest, "kind": "toolchain"})
	}
	request := map[string]any{"id": fixture.id, "sourceName": fixture.sourceName, "sourceSha256": sourceHash, "architecture": architecture}
	if len(locks) > 0 {
		request["locks"] = locks
	}
	if fixture.appimageOffset > 0 {
		request["appimageOffset"] = fixture.appimageOffset
	}
	if fixture.plainInstallTarget != "" {
		request["plainInstallTarget"] = fixture.plainInstallTarget
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bun", "run", filepath.Join(repoRoot, "scripts/template-fixture-render.ts"))
	command.Dir = repoRoot
	command.Stdin = bytes.NewReader(encoded)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("typed renderer failed for %s: %v\n%s", fixture.id, err, output)
	}
	var result struct {
		SourceSHA256 string `json:"sourceSha256"`
		RecipeSHA256 string `json:"recipeSha256"`
		Recipe       string `json:"recipe"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("typed renderer response for %s is invalid: %v\n%s", fixture.id, err, output)
	}
	if result.SourceSHA256 != sourceHash || result.Recipe == "" || result.RecipeSHA256 != hashBytes([]byte(result.Recipe)) {
		t.Fatalf("typed renderer identity for %s is not bound to fixture source/recipe", fixture.id)
	}
	return result.Recipe
}

func templateSplitOutputContract(job Job) *outputContract {
	contract := &outputContract{SchemaVersion: 2}
	contract.Cohort.ID = "template-matrix"
	contract.Cohort.Revision = 1
	contract.Cohort.ManifestSHA256 = strings.Repeat("a", 64)
	contract.Outputs = []expectedOutput{
		{Name: job.PackageName, FullVersion: "1.0.0-1", Architecture: job.Architecture},
		{Name: job.PackageName + "-tool", FullVersion: "1.0.0-1", Architecture: job.Architecture},
	}
	contract.RuntimeGroups = [][]string{{job.PackageName, job.PackageName + "-tool"}}
	return contract
}

func fixtureMissingCapacity(err error) bool {
	return fixtureMissingCapacityText(err.Error())
}

func fixtureMissingCapacityText(value string) bool {
	message := strings.ToLower(value)
	for _, marker := range []string{"command not found", "required tool", "exec format error"} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func templateMatrixFixtures() []templateMatrixFixture {
	return []templateMatrixFixture{
		{id: "autotools-v1", arch: "any", sourceName: "autotools-1.0.tar.gz", source: func(t *testing.T) []byte { return autotoolsArchive(t, "autotools-1.0", true) }, smoke: []string{"/usr/bin/demo --version"}, needs: []string{"cc", "make"}},
		{id: "autotools-autoreconf-v1", arch: "any", sourceName: "autotools-autoreconf-1.0.tar.gz", source: func(t *testing.T) []byte { return autotoolsArchive(t, "autotools-autoreconf-1.0", false) }, smoke: []string{"/usr/bin/demo --version"}, needs: []string{"cc", "make", "autoreconf"}},
		{id: "plain-make-v1", arch: "any", sourceName: "plain-make-1.0.tar.gz", source: func(t *testing.T) []byte {
			return sourceArchive(t, "plain-make-1.0", map[string]fixtureFile{"Makefile": {nativeMakefile(), 0o644}, "demo.c": {demoC(), 0o644}})
		}, smoke: []string{"/usr/bin/demo --version"}, needs: []string{"cc", "make"}, plainInstallTarget: "stage-install"},
		{id: "cmake-v1", arch: "any", sourceName: "cmake-1.0.tar.gz", source: func(t *testing.T) []byte {
			return sourceArchive(t, "cmake-1.0", map[string]fixtureFile{"CMakeLists.txt": {"cmake_minimum_required(VERSION 3.10)\nproject(demo C)\nenable_testing()\nadd_library(demo_shared SHARED demo-lib.c)\nadd_executable(demo demo.c)\ntarget_link_libraries(demo PRIVATE demo_shared)\nadd_test(NAME demo COMMAND demo --version)\ninstall(TARGETS demo demo_shared RUNTIME DESTINATION bin LIBRARY DESTINATION lib)\n", 0o644}, "demo.c": {demoC(), 0o644}, "demo-lib.c": {"int demo_value(void) { return 1; }\n", 0o644}})
		}, smoke: []string{"/usr/bin/demo --version"}, needs: []string{"cmake", "cc"}},
		{id: "meson-v1", arch: "any", sourceName: "meson-1.0.tar.gz", source: func(t *testing.T) []byte {
			return sourceArchive(t, "meson-1.0", map[string]fixtureFile{"meson.build": {"project('demo', 'c', version: '1.0')\ndemo_dep = subproject('demo').get_variable('demo_dep')\ne = executable('demo', 'demo.c', dependencies: demo_dep, install: true)\ntest('demo', e, args: ['--version'])\n", 0o644}, "demo.c": {demoC(), 0o644}, "subprojects/demo/meson.build": {"project('demo-subproject', 'c')\ndemo_lib = static_library('demo-sub', 'demo-lib.c')\ndemo_dep = declare_dependency(link_with: demo_lib)\n", 0o644}, "subprojects/demo/demo-lib.c": {"int demo_value(void) { return 1; }\n", 0o644}})
		}, smoke: []string{"/usr/bin/demo --version"}, needs: []string{"meson", "ninja", "cc"}},
		{id: "rust-v1", arch: "any", sourceName: "rust-1.0.tar.gz", source: func(t *testing.T) []byte {
			return sourceArchive(t, "rust-1.0", map[string]fixtureFile{"Cargo.toml": {"[workspace]\nmembers = ['app', 'tool']\nresolver = '2'\n", 0o644}, "Cargo.lock": {"# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = 'app'\nversion = '1.0.0'\n\n[[package]]\nname = 'tool'\nversion = '1.0.0'\n", 0o644}, "app/Cargo.toml": {"[package]\nname = 'app'\nversion = '1.0.0'\nedition = '2021'\nbuild = 'build.rs'\n", 0o644}, "app/build.rs": {"fn main() { println!(\"cargo:rustc-env=FIXTURE_BUILD=workspace\"); }\n", 0o644}, "app/src/main.rs": {"fn main() { println!(\"app {}\", env!(\"FIXTURE_BUILD\")); }\n", 0o644}, "tool/Cargo.toml": {"[package]\nname = 'tool'\nversion = '1.0.0'\nedition = '2021'\n", 0o644}, "tool/src/main.rs": {"fn main() { println!(\"tool 1.0\"); }\n", 0o644}})
		}, smoke: []string{"/usr/bin/app"}, needs: []string{"cargo", "rustc"}, split: true},
		{id: "python-v1", arch: "any", sourceName: "python-1.0.tar.gz", source: func(t *testing.T) []byte {
			return sourceArchive(t, "python-1.0", map[string]fixtureFile{"pyproject.toml": {"[build-system]\nrequires = ['setuptools', 'wheel']\nbuild-backend = 'setuptools.build_meta'\n[project]\nname = 'demo'\nversion = '1.0.0'\n", 0o644}, "setup.py": {"from setuptools import Extension, setup\nsetup(name='demo', version='1.0.0', py_modules=['demo'], ext_modules=[Extension('demo_native', ['demo_native.c'])])\n", 0o644}, "demo.py": {"VALUE = 'demo'\n", 0o644}, "demo_native.c": {"#include <Python.h>\nstatic PyObject *value(PyObject *self, PyObject *args) { return PyLong_FromLong(1); }\nstatic PyMethodDef methods[] = {{\"value\", value, METH_NOARGS, \"fixture\"}, {NULL, NULL, 0, NULL}};\nstatic struct PyModuleDef definition = {PyModuleDef_HEAD_INIT, \"demo_native\", NULL, -1, methods};\nPyMODINIT_FUNC PyInit_demo_native(void) { return PyModule_Create(&definition); }\n", 0o644}})
		}, smoke: []string{"test -f /usr/lib/python3.*/site-packages/demo_native*.so"}, needs: []string{"python", "python-build"}},
		{id: "node-npm-v1", arch: "any", sourceName: "node-npm-1.0.tar.gz", source: func(t *testing.T) []byte { return nodeArchive(t, "node-npm-1.0", "npm") }, smoke: []string{"test -f /usr/share/demo/index.js"}, needs: []string{"npm", "node"}},
		{id: "node-pnpm-v1", arch: "any", sourceName: "node-pnpm-1.0.tar.gz", source: func(t *testing.T) []byte { return nodeArchive(t, "node-pnpm-1.0", "pnpm") }, smoke: []string{"test -f /usr/share/demo/index.js"}, needs: []string{"pnpm", "node"}},
		{id: "node-yarn-v1", arch: "any", sourceName: "node-yarn-1.0.tar.gz", source: func(t *testing.T) []byte { return nodeArchive(t, "node-yarn-1.0", "yarn") }, smoke: []string{"test -f /usr/share/demo/index.js"}, needs: []string{"yarn", "node"}},
		{id: "electron-v1", arch: "any", sourceName: "electron-1.0.tar.gz", source: func(t *testing.T) []byte {
			return sourceArchive(t, "electron-1.0", map[string]fixtureFile{"package.json": {"{\"name\":\"demo\",\"version\":\"1.0.0\",\"scripts\":{\"build\":\"mkdir -p dist/linux-unpacked && cp app.js dist/linux-unpacked/demo\"}}\n", 0o644}, "package-lock.json": {"{\"name\":\"demo\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"demo\",\"version\":\"1.0.0\"}}}\n", 0o644}, "app.js": {"const { app } = require('electron'); app.whenReady().then(() => setTimeout(() => app.quit(), 100));\n", 0o644}, "demo.desktop": {"[Desktop Entry]\nName=Demo\nType=Application\nExec=demo\n", 0o644}})
		}, smoke: []string{"test -f /usr/share/applications/demo.desktop", "HOME=/tmp XDG_CONFIG_HOME=/tmp XDG_CACHE_HOME=/tmp xvfb-run --auto-servernum electron43 --no-sandbox --disable-gpu --disable-dev-shm-usage /usr/lib/demo/app.js"}, needs: []string{"npm", "electron43"}},
		{id: "archive-v1", arch: "any", sourceName: "demo-prebuilt.tar", source: func(t *testing.T) []byte {
			return tarArchive(map[string]fixtureFile{"usr/bin/demo": {"#!/bin/sh\nprintf 'demo 1.0\\n'\n", 0o755}})
		}, smoke: []string{"/usr/bin/demo"}, needs: []string{"bsdtar"}},
		{id: "deb-v1", arch: "any", sourceName: "demo.deb", sourceForArch: debFixture, smoke: []string{"test -f /usr/share/demo/payload.txt"}, needs: []string{"ar", "bsdtar"}},
		{id: "rpm-v1", arch: "any", sourceName: "demo.rpm", sourceForArch: rpmFixtureBytes, smoke: []string{"test -f /usr/share/demo/payload.txt"}, needs: []string{"rpm2cpio", "bsdtar"}},
		{id: "appimage-v1", arch: "any", sourceName: "demo.AppImage", sourceForArch: appImageFixtureBytes, smoke: []string{"test -f /usr/share/demo/payload.txt"}, needs: []string{"unsquashfs"}, appimageOffset: 131072},
		{id: "run-v1", arch: "any", sourceName: "demo.run", source: func(t *testing.T) []byte {
			return []byte("#!/bin/sh\nset -eu\nif [ \"${1:-}\" = --extract-only ]; then mkdir -p \"$3/usr/share/demo\"; printf 'run payload\\n' > \"$3/usr/share/demo/payload.txt\"; exit 0; fi\nexit 64\n")
		}, smoke: []string{"test -f /usr/share/demo/payload.txt"}, needs: []string{"sh"}},
		{id: "script-data-v1", arch: "any", sourceName: "script-data-1.0.tar.gz", source: func(t *testing.T) []byte {
			return sourceArchive(t, "script-data-1.0", map[string]fixtureFile{"demo.txt": {"script-data fixture\n", 0o644}})
		}, smoke: []string{"test -f /usr/share/demo/demo.txt"}, needs: []string{"makepkg"}},
		{id: "go-v2", arch: "any", sourceName: "go-1.0.tar.gz", source: func(t *testing.T) []byte {
			return sourceArchive(t, "go-1.0", map[string]fixtureFile{"go.mod": {"module example.invalid/demo\n\ngo 1.22\n", 0o644}, "go.work": {"go 1.22\n\nuse .\n", 0o644}, "main.go": {"package main\n/*\n#include <stdio.h>\n*/\nimport \"C\"\nfunc main(){ C.puts(C.CString(\"demo 1.0\")) }\n", 0o644}, "vendor/modules.txt": {"## workspace\n", 0o644}})
		}, smoke: []string{"/usr/bin/demo"}, needs: []string{"go", "cc"}, locks: map[string]string{"vendor/modules.txt": hashBytes([]byte("## workspace\n"))}},
	}
}

type fixtureFile struct {
	body string
	mode int64
}

func sourceArchive(t *testing.T, root string, files map[string]fixtureFile) []byte {
	t.Helper()
	entries := make(map[string]fixtureFile, len(files))
	for name, file := range files {
		entries[root+"/"+name] = file
	}
	return tarGzArchive(entries)
}

func autotoolsArchive(t *testing.T, root string, release bool) []byte {
	t.Helper()
	work := t.TempDir()
	source := filepath.Join(work, root)
	if err := os.MkdirAll(filepath.Join(source, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]fixtureFile{
		"configure.ac": {"AC_INIT([demo],[1.0])\nAM_INIT_AUTOMAKE([foreign])\nAC_PROG_CC\nAC_CONFIG_FILES([Makefile])\nAC_OUTPUT\n", 0o644},
		"Makefile.am":  {"bin_PROGRAMS = demo\ndemo_SOURCES = src/demo.c\nTESTS = demo\n", 0o644},
		"src/demo.c":   {demoC(), 0o644},
	}
	for name, file := range files {
		path := filepath.Join(source, name)
		if err := os.WriteFile(path, []byte(file.body), os.FileMode(file.mode)); err != nil {
			t.Fatal(err)
		}
	}
	if release {
		command := exec.Command("autoreconf", "-fi")
		command.Dir = source
		if output, err := command.CombinedOutput(); err != nil {
			t.Skipf("incomplete: autoreconf fixture preparation: %v (%s)", err, output)
		}
	}
	result := map[string]fixtureFile{}
	if err := filepath.WalkDir(source, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		mode := int64(0o644)
		if info, statErr := entry.Info(); statErr == nil && info.Mode()&0o111 != 0 {
			mode = 0o755
		}
		relative, relErr := filepath.Rel(work, path)
		if relErr != nil {
			return relErr
		}
		result[filepath.ToSlash(relative)] = fixtureFile{string(body), mode}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return tarGzArchive(result)
}
func nodeArchive(t *testing.T, root, manager string) []byte {
	t.Helper()
	lock := map[string]string{"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "yarn": "yarn.lock"}[manager]
	files := map[string]fixtureFile{"package.json": {fmt.Sprintf("{\"name\":\"demo\",\"version\":\"1.0.0\",\"scripts\":{\"build\":\"cp index.js dist.js\"}}\n"), 0o644}, "index.js": {"console.log('demo');\n", 0o644}}
	files[lock] = fixtureFile{map[string]string{"package-lock.json": "{\"name\":\"demo\",\"version\":\"1.0.0\",\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"demo\",\"version\":\"1.0.0\"}}}\n", "pnpm-lock.yaml": "lockfileVersion: '9.0'\n", "yarn.lock": "# yarn lockfile v1\n"}[lock], 0o644}
	return sourceArchive(t, root, files)
}
func tarArchive(files map[string]fixtureFile) []byte { return tarGzArchive(files) }
func tarGzArchive(files map[string]fixtureFile) []byte {
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		file := files[name]
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: file.mode, Size: int64(len(file.body)), ModTime: time.Unix(1_700_000_000, 0).UTC()})
		_, _ = io.WriteString(tw, file.body)
	}
	_ = tw.Close()
	_ = gz.Close()
	return output.Bytes()
}
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func demoC() string {
	return "#include <stdio.h>\nint main(int argc, char **argv) { if (argc > 1) puts(\"demo 1.0\"); else puts(\"demo 1.0\"); return 0; }\n"
}
func nativeMakefile() string {
	return "PREFIX ?= /usr\nCC ?= cc\nall: demo\ndemo: demo.c\n\t$(CC) $(CFLAGS) -o demo demo.c\ntest: demo\n\t./demo\ncheck: test\nstage-install: demo\n\tinstall -Dm755 demo $(DESTDIR)$(PREFIX)/bin/demo\ninstall: stage-install\n"
}
func debFixture(_ *testing.T, architecture string) []byte {
	debianArchitecture := "amd64"
	if architecture == "aarch64" {
		debianArchitecture = "arm64"
	}
	data := tarGzArchive(map[string]fixtureFile{"usr/share/demo/payload.txt": {"deb payload\n", 0o644}})
	control := tarGzArchive(map[string]fixtureFile{"control": {"Package: demo\nVersion: 1.0\nArchitecture: " + debianArchitecture + "\n\n", 0o644}})
	return arArchive(map[string][]byte{"debian-binary": []byte("2.0\n"), "control.tar.gz": control, "data.tar.gz": data})
}
func arArchive(files map[string][]byte) []byte {
	var out bytes.Buffer
	out.WriteString("!<arch>\n")
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sortStrings(names)
	for _, name := range names {
		body := files[name]
		header := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d%2s", name+"/", 0, 0, 0, 0o100644, len(body), "`\n")
		out.WriteString(header)
		out.Write(body)
		if len(body)%2 != 0 {
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}
func rpmFixtureBytes(t *testing.T, architecture string) []byte {
	t.Helper()
	image := os.Getenv("OPR_WORKER_TEMPLATE_MATRIX_IMAGE")
	if image == "" {
		t.Skip("incomplete: a digest-pinned matrix image is required to generate RPM fixture")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "SPECS"), 0o700); err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile(filepath.Join("testdata", "template-matrix", "demo.spec"))
	if err != nil {
		t.Fatal(err)
	}
	if architecture == "aarch64" {
		spec = bytes.Replace(spec, []byte("BuildArch: x86_64"), []byte("BuildArch: aarch64"), 1)
	}
	if err := os.WriteFile(filepath.Join(root, "SPECS", "demo.spec"), spec, 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := os.Getenv("OPR_WORKER_TEMPLATE_MATRIX_RUNTIME")
	if runtime == "" {
		runtime = "podman"
	}
	mount := root + ":/root/rpmbuild:Z"
	rpmbuildRoot := "/root/rpmbuild"
	args := []string{"run", "--rm"}
	if runtime == "docker" {
		mount = root + ":/tmp/rpmbuild"
		rpmbuildRoot = "/tmp/rpmbuild"
		args = append(args, "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()))
	}
	args = append(args, "-v", mount, image, "rpmbuild", "--define", "_topdir "+rpmbuildRoot, "-bb", rpmbuildRoot+"/SPECS/demo.spec")
	output, err := exec.Command(runtime, args...).CombinedOutput()
	if err != nil {
		t.Skipf("incomplete: generate RPM fixture in pinned image: %v (%s)", err, output)
	}
	packageArchitecture := "x86_64"
	if architecture == "aarch64" {
		packageArchitecture = "aarch64"
	}
	path := filepath.Join(root, "RPMS", packageArchitecture, "demo-1.0-1."+packageArchitecture+".rpm")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("generated RPM fixture missing: %v (%s)", err, output)
	}
	return bytes
}

func appImageFixtureBytes(t *testing.T, architecture string) []byte {
	t.Helper()
	if _, err := exec.LookPath("mksquashfs"); err != nil {
		t.Skip("incomplete: mksquashfs is unavailable to create AppImage fixture")
	}
	root := t.TempDir()
	app := filepath.Join(root, "app")
	if err := os.MkdirAll(filepath.Join(app, "usr/share/demo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "usr/share/demo/payload.txt"), []byte("appimage payload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	squash := filepath.Join(root, "root.squashfs")
	if output, err := exec.Command("mksquashfs", app, squash, "-noappend", "-no-progress", "-all-root").CombinedOutput(); err != nil {
		t.Skipf("incomplete: create AppImage squashfs: %v (%s)", err, output)
	}
	runtime := filepath.Join(root, "runtime")
	command := exec.Command("cc", "-x", "c", "-O2", "-o", runtime, "-")
	command.Stdin = strings.NewReader("int main(void) { return 0; }\n")
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("incomplete: create AppImage runtime: %v (%s)", err, output)
	}
	runtimeBytes, _ := os.ReadFile(runtime)
	squashBytes, _ := os.ReadFile(squash)
	if len(runtimeBytes) > 131072 {
		t.Skip("incomplete: AppImage runtime exceeds fixture offset")
	}
	runtimeBytes = append(runtimeBytes, make([]byte, 131072-len(runtimeBytes))...)
	result := append(runtimeBytes, squashBytes...)
	if len(result) < 11 {
		t.Fatal("AppImage fixture is too small")
	}
	result[8], result[9], result[10] = 0x41, 0x49, 0x02
	return result
}

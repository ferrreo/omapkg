package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPreservedSourceObjectsBindOriginalTreeAndNativePlan(t *testing.T) {
	objects := map[string][]byte{}
	object := func(data []byte) inputObject {
		ref := inputObject{SHA256: hashBytes(data), Size: int64(len(data))}
		objects[ref.SHA256] = data
		return ref
	}
	pack := func(value any) inputObject {
		data, _ := encodeJSON(value)
		var canonical any
		json.Unmarshal(data, &canonical)
		data, _ = encodeJSON(canonical)
		return object(data)
	}
	recipe := "pkgname=demo\npkgver=1.0\npkgrel=1\narch=('x86_64')\npackage() { :; }\n"
	capture := recipeCaptureManifest{SchemaVersion: 1, Kind: "recipe-capture", Pkgbase: "demo", Origin: "opr", Repository: "https://github.com/example/recipes"}
	var tree bytes.Buffer
	for _, file := range []struct{ name, mode, text string }{{"PKGBUILD", "100644", recipe}, {"fix.patch", "100755", "local bytes\n"}, {"patch-link", "120000", "fix.patch"}} {
		data := []byte(file.text)
		ref := object(data)
		capture.Files = append(capture.Files, recipeCaptureFile{Path: file.name, Mode: file.mode, Object: ref})
		fmt.Fprintf(&tree, "%s %s\x00", file.mode, file.name)
		sha, _ := hex.DecodeString(recipeGitHash("blob", data))
		tree.Write(sha)
	}
	commit := []byte("tree " + recipeGitHash("tree", tree.Bytes()) + "\ncommitter Test <test@example.invalid> 1700000000 +0000\n\nFixture\n")
	capture.Commit = recipeGitHash("commit", commit)
	capture.Git.Commit = object(commit)
	capture.Git.Trees = []inputObject{object(tree.Bytes())}
	captureRef := pack(capture)
	plan := recipeSourcePlan{SchemaVersion: 1, Kind: "recipe-source-plan", Pkgbase: "demo", Version: "1.0-1", Architecture: "x86_64", Capture: captureRef,
		Sources: []plannedRecipeSource{{Kind: "local", Name: "fix.patch", Path: "fix.patch", Source: "fix.patch", Checksums: map[string]string{"sha256": "SKIP"}},
			{Kind: "file", Name: "empty", URL: "https://example.org/empty", Source: "https://example.org/empty", Checksums: map[string]string{"sha256": emptyRecipeSHA}}}, ValidPGPKeys: []string{}}
	plan.Inspection.JobID, plan.Inspection.Attempt = "inspection", 1
	plan.Inspection.ReportSHA256, plan.Inspection.SrcinfoSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	bundle := map[string]any{"schemaVersion": 1, "kind": "recipe-source-bundle", "plan": pack(plan), "sources": []any{
		map[string]any{"kind": "file", "name": "empty", "object": object(nil), "redirects": []string{"https://example.org/empty"}}}, "caches": []any{}, "keys": []any{}}
	lock := inputObject{SHA256: strings.Repeat("c", 64), Size: 10}
	job := Job{ID: "preserved-test", Attempt: 1, RevisionID: "preserved-revision", LeaseToken: "test", Recipe: recipe, RecipeSHA256: hashBytes([]byte(recipe)),
		PackageName: "demo", Version: "1.0", Pkgrel: 1, Surface: "binary", Architecture: "x86_64", ImageDigest: "sha256:" + strings.Repeat("d", 64),
		InputLock: &lock, SmokeCommands: []string{"test -f /usr/share/demo"}, OutputContract: testOutputContract("x86_64"), Sources: []Source{}}
	job.ImageRef = "registry.example/helper@" + job.ImageDigest
	job.LeaseExpiresAt = time.Now().Add(time.Minute).Format(time.RFC3339)
	job.OutputContract.Outputs = []expectedOutput{{Name: "demo", FullVersion: "1.0-1", Architecture: "x86_64"}}
	job.OutputContract.RuntimeGroups = [][]string{{"demo"}}
	job.PreservedRecipe = &preservedBuildInputs{Capture: captureRef, SourceBundle: pack(bundle)}
	load := func(job Job, tamper bool) (*materializedRecipe, string, error) {
		root := t.TempDir()
		work := filepath.Join(root, "work")
		os.Mkdir(work, 0o700)
		result, err := materializePreservedRecipe(context.Background(), job, filepath.Join(root, "inputs"), work, func(_ context.Context, ref inputObject, path string) error {
			if ref.Size == 0 {
				t.Fatal("empty source must not request a private object")
			}
			data := objects[ref.SHA256]
			if tamper && ref == capture.Files[0].Object {
				data = bytes.Repeat([]byte("x"), len(data))
			}
			return os.WriteFile(path, data, 0o600)
		})
		return result, work, err
	}
	if err := validateJob(job, Config{Architecture: "x86_64"}); err != nil {
		t.Fatal(err)
	}
	job.RuntimeDependencies = []string{"lib:libc.so.6", "libOpenCL.so=1-64"}
	if err := validateJob(job, Config{Architecture: "x86_64"}); err != nil {
		t.Fatalf("preserved native SONAME relations rejected: %v", err)
	}
	job.RuntimeDependencies = []string{"lib:libc.so.6=6-64"}
	if validateJob(job, Config{Architecture: "x86_64"}) == nil {
		t.Fatal("accepted malformed native SONAME relation")
	}
	job.RuntimeDependencies = nil
	result, work, err := load(job, false)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	mounts, err := result.buildMounts(work, t.TempDir(), env)
	if err != nil {
		t.Fatal(err)
	}
	runner := Runner{Runtime: "podman"}
	runner.baseContainerArgsForImage("preserved-args", "none", "/opr/work", mounts, env, workerContainerUser(), job.ImageRef)
	if string(mustReadFile(t, filepath.Join(work, "PKGBUILD"))) != recipe || len(mustReadFile(t, filepath.Join(result.Directory, "sources", "empty"))) != 0 {
		t.Fatal("original recipe or empty source changed")
	}
	if link, _ := os.Readlink(filepath.Join(work, "patch-link")); link != "fix.patch" {
		t.Fatal("original symlink was not retained")
	}
	if info, _ := os.Stat(filepath.Join(work, "fix.patch")); info.Mode().Perm() != 0o755 {
		t.Fatal("original executable mode changed")
	}
	if _, _, err := load(job, true); err == nil {
		t.Fatal("accepted substituted recipe bytes")
	}
	for _, mutation := range []string{"architecture", "version", "capture", "extra-source", "key"} {
		changed := plan
		switch mutation {
		case "architecture":
			changed.Architecture = "aarch64"
		case "version":
			changed.Version = "2.0-1"
		case "capture":
			changed.Capture = lock
		case "extra-source":
			changed.Sources = changed.Sources[:1]
		case "key":
			changed.ValidPGPKeys = []string{strings.Repeat("A", 40)}
		}
		bundle["plan"] = pack(changed)
		job.PreservedRecipe.SourceBundle = pack(bundle)
		if _, _, err := load(job, false); err == nil {
			t.Fatalf("accepted changed %s source scope", mutation)
		}
	}
	bundle["plan"] = pack(plan)
	repeated := []any{}
	for index := 0; index < 9; index++ {
		repeated = append(repeated, map[string]any{"kind": "file", "name": fmt.Sprint("source-", index), "object": inputObject{SHA256: strings.Repeat("e", 64), Size: maxRecipeSourceObject}, "redirects": []string{"https://example.org/source"}})
	}
	bundle["sources"] = repeated
	job.PreservedRecipe.SourceBundle = pack(bundle)
	if _, _, err := load(job, false); err == nil || !strings.Contains(err.Error(), "total byte budget") {
		t.Fatalf("repeated source objects bypassed total disk budget: %v", err)
	}
	for _, mutation := range []string{"no-lock", "flat-source", "no-contract", "no-smoke"} {
		changed := job
		switch mutation {
		case "no-lock":
			changed.InputLock = nil
		case "flat-source":
			changed.Sources = []Source{{Name: "flat", SHA256: emptyRecipeSHA, URL: "https://example.org/flat"}}
		case "no-contract":
			changed.OutputContract = nil
		case "no-smoke":
			changed.SmokeCommands = nil
		}
		if validateJob(changed, Config{Architecture: "x86_64"}) == nil {
			t.Fatalf("accepted preserved job %s", mutation)
		}
	}
}

func TestSourceArchiveRejectsEscapesSpecialFilesAndFalseBudgets(t *testing.T) {
	for _, mutation := range []string{"", "path", "duplicate", "device", "hardlink", "mode", "size", "count", "parent", "link", "chain", "cancel"} {
		t.Run(mutation, func(t *testing.T) {
			root := t.TempDir()
			file, err := os.Create(filepath.Join(root, "cache.tar"))
			if err != nil {
				t.Fatal(err)
			}
			archive := tar.NewWriter(file)
			headers := []tar.Header{{Name: "git/db/HEAD", Mode: 0o644, Size: 4, Typeflag: tar.TypeReg}, {Name: "link", Mode: 0o755, Typeflag: tar.TypeSymlink, Linkname: "git/db/HEAD"}}
			entries, size := 2, int64(4)
			switch mutation {
			case "path":
				headers[0].Name = "../escape"
			case "duplicate":
				headers[1].Name = headers[0].Name
			case "device":
				headers[1].Typeflag = tar.TypeChar
			case "hardlink":
				headers[1].Typeflag = tar.TypeLink
			case "mode":
				headers[0].Mode = 0o4755
			case "size":
				size--
			case "count":
				entries++
			case "parent":
				headers[1].Name = "git/db"
			case "link":
				headers[1].Linkname = "../escape"
			case "chain":
				headers[1].Linkname = "git/db"
				headers = append(headers, tar.Header{Name: "second", Mode: 0o755, Typeflag: tar.TypeSymlink, Linkname: "link/../../../escape"})
				entries++
			}
			for _, header := range headers {
				if err := archive.WriteHeader(&header); err != nil {
					t.Fatal(err)
				}
				if header.Size > 0 {
					archive.Write([]byte("test"))
				}
			}
			archive.Close()
			file.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mutation == "cancel" {
				cancel()
			}
			err = extractRecipeSource(ctx, file.Name(), filepath.Join(root, "cache"), entries, size)
			if (err == nil) != (mutation == "") {
				t.Fatalf("source archive %q: %v", mutation, err)
			}
			if _, err := os.Stat(filepath.Join(root, "escape")); !os.IsNotExist(err) {
				t.Fatal("archive wrote outside its directory")
			}
		})
	}
}

// Explicit native acceptance input contains job.json and all retained objects,
// including signed frozen packages. No mirror or source network is available.
func TestRunnerPreservedRecipeNativeOCI(t *testing.T) {
	directory := os.Getenv("OPR_PRESERVED_E2E_CAPTURE")
	if directory == "" {
		t.Skip("OPR_PRESERVED_E2E_CAPTURE is not set")
	}
	var job Job
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(directory, "job.json")), &job); err != nil {
		t.Fatal(err)
	}
	job.LeaseToken = "local-preserved-test-lease"
	job.LeaseExpiresAt = time.Now().Add(time.Hour).Format(time.RFC3339)
	key, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(request.Body, 1024))
		signature, _ := base64.StdEncoding.DecodeString(request.Header.Get("X-OPR-Signature"))
		payload := makeSignaturePayload(request.Method, canonicalRequestPath(request.URL), request.Header.Get("X-OPR-Timestamp"), request.Header.Get("X-OPR-Nonce"), hashBytes(body))
		var input HeartbeatRequest
		if request.Method != "POST" || json.Unmarshal(body, &input) != nil || input.LeaseToken != job.LeaseToken || !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, signature) {
			http.Error(w, "invalid signed input access", 403)
			return
		}
		digest := strings.TrimPrefix(request.URL.Path, "/api/worker/jobs/"+job.ID+"/inputs/")
		if !sha256Pattern.MatchString(digest) {
			http.NotFound(w, request)
			return
		}
		file, err := os.Open(filepath.Join(directory, "objects", digest))
		if err != nil {
			http.NotFound(w, request)
			return
		}
		defer file.Close()
		info, _ := file.Stat()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(info.Size()))
		requests++
		io.Copy(w, file)
	}))
	defer server.Close()
	origin, _ := url.Parse(server.URL)
	client := &Client{Origin: origin, WorkerID: "preserved-native-worker", PrivateKey: key, HTTP: server.Client()}
	state, err := os.MkdirTemp(filepath.Dir(directory), "worker-preserved-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(state)
	runner := Runner{Runtime: "podman", Origin: server.URL, StateDir: state}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	started := time.Now().UTC().Format(time.RFC3339)
	result, err := runner.ExecuteWithClient(ctx, job, nil, client)
	if expected := os.Getenv("OPR_PRESERVED_E2E_ERROR"); expected != "" {
		if result.Cleanup != nil {
			defer result.Cleanup()
		}
		if err == nil || !strings.Contains(err.Error()+result.Log, expected) || len(result.Outputs) != 0 {
			t.Fatalf("expected source rejection %q: %v\n%s", expected, err, result.Log)
		}
		t.Logf("rejected before package output: %s", expected)
		return
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, result.Log)
	}
	defer result.Cleanup()
	if !result.SmokePassed || len(result.Outputs) != len(job.OutputContract.Outputs) || result.InputEvidence == nil || result.PreservedRecipe == nil || *result.PreservedRecipe != *job.PreservedRecipe || requests < 4 {
		t.Fatal("preserved native build omitted outputs, input access or runtime evidence")
	}
	for _, output := range result.Outputs {
		t.Logf("built %s %s", output.Filename, output.ArtifactSHA256)
	}
	report, err := provenanceForOutputs(job, client.WorkerID, result, started, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "native-provenance.json"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
}

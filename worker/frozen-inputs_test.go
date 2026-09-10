package main

import (
	"archive/tar"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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

func TestFrozenHelperArchivePinsManifestAndBlobs(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2}`)
	digest := hashBytes(manifest)
	image := "registry.example/helper@sha256:" + digest
	for _, mutation := range []string{"", "digest", "blob", "path"} {
		filename := filepath.Join(t.TempDir(), "helper.tar")
		file, err := os.Create(filename)
		if err != nil {
			t.Fatal(err)
		}
		archive := tar.NewWriter(file)
		index := fmt.Sprintf(`{"schemaVersion":2,"manifests":[{"digest":"sha256:%s"}]}`, digest)
		entries := map[string][]byte{"index.json": []byte(index), "oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "blobs/sha256/" + digest: manifest}
		if mutation == "blob" {
			entries["blobs/sha256/"+digest] = []byte("changed")
		}
		if mutation == "path" {
			entries["../escape"] = []byte("bad")
		}
		for name, data := range entries {
			if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := archive.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		file.Close()
		ref := image
		if mutation == "digest" {
			ref = "registry.example/helper@sha256:" + strings.Repeat("f", 64)
		}
		err = verifyHelperArchive(filename, ref)
		if (err == nil) != (mutation == "") {
			t.Fatalf("helper archive %q: %v", mutation, err)
		}
	}
}

func TestFrozenInputPagesBindCompleteInventoryAndBudget(t *testing.T) {
	ctx := context.Background()
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
	item := frozenPackage{Name: "base", Version: "1:1.0-1", Architecture: "any", Filename: "base-1.0-1-any.pkg.tar.zst",
		Package: object([]byte("package")), Signature: object([]byte("signature")), PublicKey: object([]byte("public-key")),
		Fingerprint: strings.Repeat("A", 40), Origin: "external-bootstrap", OriginEvidence: strings.Repeat("b", 64)}
	page := pack([]frozenPackage{item})
	manifest := frozenInputManifest{SchemaVersion: 1, Purpose: "bootstrap", Architecture: "x86_64", RecipeSHA256: strings.Repeat("c", 64),
		CohortSHA256: strings.Repeat("d", 64), SourceDateEpoch: 1700000000, HelperImage: "registry.example/helper@sha256:" + strings.Repeat("e", 64),
		HelperArchive: object([]byte("OCI archive")), MakepkgConfig: object([]byte("CARCH=x86_64")), TransferLimitBytes: 1 << 20}
	for _, name := range []string{"build", "runtime-0"} {
		manifest.Environments = append(manifest.Environments, frozenEnvironment{Name: name, PackageCount: 1, TotalBytes: item.Package.Size,
			InventorySHA256: hashBytes([]byte("base 1:1.0-1\n")), Chunks: []inputObject{page}})
	}
	job := Job{Architecture: manifest.Architecture, ImageRef: manifest.HelperImage, RecipeSHA256: manifest.RecipeSHA256, SourceDateEpoch: manifest.SourceDateEpoch,
		OutputContract: &outputContract{RuntimeGroups: [][]string{{"result"}}}}
	job.OutputContract.Cohort.ManifestSHA256 = manifest.CohortSHA256
	load := func(m frozenInputManifest, tamper bool) (*materializedInputs, error) {
		ref := pack(m)
		job.InputLock = &ref
		return materializeFrozenInputs(ctx, job, filepath.Join(t.TempDir(), "inputs"), func(_ context.Context, ref inputObject, path string) error {
			data := objects[ref.SHA256]
			if tamper && ref == item.Package {
				data = []byte("changed")
			}
			return os.WriteFile(path, data, 0o600)
		})
	}
	inputs, err := load(manifest, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs.Environments["build"]) != 1 {
		t.Fatal("input page was not materialized")
	}
	withHelper := manifest
	withHelper.ShellAnalysis = "helper"
	if _, err := load(withHelper, false); err != nil {
		t.Fatal(err)
	}
	xz := item
	xz.Filename = strings.TrimSuffix(xz.Filename, ".zst") + ".xz"
	withXZ := manifest
	withXZ.Environments = append([]frozenEnvironment{}, manifest.Environments...)
	for index := range withXZ.Environments {
		withXZ.Environments[index].Chunks = []inputObject{pack([]frozenPackage{xz})}
	}
	if _, err := load(withXZ, false); err != nil {
		t.Fatal(err)
	}
	if err := inputs.verifyEnvironment("build", environmentEvidence{Packages: []string{"base 1:1.0-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := inputs.verifyEnvironment("build", environmentEvidence{Packages: []string{"base 1:1.0-1", "hidden 1.0-1"}}); err == nil {
		t.Fatal("accepted hidden base package")
	}
	if _, err := load(manifest, true); err == nil {
		t.Fatal("accepted changed retained package")
	}
	for _, mutate := range []func(*frozenInputManifest){
		func(m *frozenInputManifest) { m.ShellAnalysis = "skip" },
		func(m *frozenInputManifest) { m.Purpose = "owned" },
		func(m *frozenInputManifest) { m.TransferLimitBytes = 1 },
		func(m *frozenInputManifest) { m.RecipeSHA256 = strings.Repeat("f", 64) },
		func(m *frozenInputManifest) { m.Environments[0].PackageCount++ },
		func(m *frozenInputManifest) { m.Environments[0].TotalBytes++ },
		func(m *frozenInputManifest) { m.Environments[0].Chunks = append(m.Environments[0].Chunks, page) },
	} {
		changed := manifest
		changed.Environments = append([]frozenEnvironment{}, manifest.Environments...)
		mutate(&changed)
		if _, err := load(changed, false); err == nil {
			t.Fatal("accepted changed manifest eligibility, budget or inventory")
		}
	}
}

// The capture directory must contain the retained helper, key/signature/package
// objects and a lock for testdata/frozen. Nothing is fetched from a mirror here.
func TestRunnerFrozenInputsNativeOCI(t *testing.T) {
	directory := os.Getenv("OPR_FROZEN_E2E_CAPTURE")
	if directory == "" {
		t.Skip("OPR_FROZEN_E2E_CAPTURE is not set")
	}
	var manifest frozenInputManifest
	var reference inputObject
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(directory, "manifest.json")), &manifest); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(directory, "reference.json")), &reference); err != nil {
		t.Fatal(err)
	}
	key, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	job := Job{ID: "frozen-native-test", Attempt: 1, LeaseToken: "local-frozen-test-lease", LeaseExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339),
		RevisionID: "frozen-native-revision", PackageName: "opr-frozen-fixture", Version: "1.0", Pkgrel: 1, Architecture: manifest.Architecture,
		Recipe: string(mustReadFile(t, "testdata/frozen/PKGBUILD")), RecipeSHA256: manifest.RecipeSHA256,
		SourceDateEpoch: manifest.SourceDateEpoch, ImageRef: manifest.HelperImage, ImageDigest: manifest.HelperImage[strings.LastIndex(manifest.HelperImage, "@")+1:],
		InputLock: &reference, RuntimeDependencies: []string{"glibc"}, MakeDependencies: []string{"gcc"}, Surface: "binary",
		SmokeCommands:  []string{`/usr/bin/frozen-hello | grep -Fx 'built from frozen inputs'`, `test -f /usr/share/doc/opr-frozen-fixture/main.c`, `test ! -e /usr/bin/gcc`, `test ! -e /usr/bin/make`},
		OutputContract: &outputContract{SchemaVersion: 2, Outputs: []expectedOutput{{Name: "opr-frozen-native", FullVersion: "1.0-1", Architecture: manifest.Architecture}, {Name: "opr-frozen-docs", FullVersion: "1.0-1", Architecture: "any"}}, RuntimeGroups: [][]string{{"opr-frozen-native", "opr-frozen-docs"}}}}
	job.OutputContract.Cohort.ID = "frozen-native-cohort"
	job.OutputContract.Cohort.Revision = 1
	job.OutputContract.Cohort.ManifestSHA256 = manifest.CohortSHA256
	source := Source{Name: "main.c", URL: "https://sources.example/main.c", SHA256: hashBytes(mustReadFile(t, "testdata/frozen/main.c"))}
	job.Sources = []Source{source}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(request.Body, 1024))
		signature, _ := base64.StdEncoding.DecodeString(request.Header.Get("X-OPR-Signature"))
		payload := makeSignaturePayload(request.Method, canonicalRequestPath(request.URL), request.Header.Get("X-OPR-Timestamp"), request.Header.Get("X-OPR-Nonce"), hashBytes(body))
		if request.Method != "POST" || !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, signature) || !strings.Contains(string(body), job.LeaseToken) {
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
	client := &Client{Origin: origin, WorkerID: "frozen-native-worker", PrivateKey: key, HTTP: server.Client()}
	state, err := os.MkdirTemp(filepath.Dir(directory), "worker-frozen-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(state)
	runner := Runner{Runtime: "podman", Origin: server.URL, StateDir: state}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	sourcePath, _ := filepath.Abs("testdata/frozen/main.c")
	result, err := runner.ExecuteWithClient(ctx, job, []fetchedSource{{Source: source, Path: sourcePath}}, client)
	if err != nil {
		t.Fatalf("%v\n%s", err, result.Log)
	}
	defer result.Cleanup()
	if !result.SmokePassed || len(result.Outputs) != 2 || len(result.RuntimeTests) != 1 || result.InputEvidence == nil || requests < 3 {
		t.Fatal("frozen native build omitted outputs, input access or runtime evidence")
	}
	for _, output := range result.Outputs {
		t.Logf("built %s %s", output.Filename, output.ArtifactSHA256)
	}
	report, err := provenanceForOutputs(job, client.WorkerID, result, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "native-provenance.json"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	var page []frozenPackage
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(directory, "objects", manifest.Environments[0].Chunks[0].SHA256)), &page); err != nil {
		t.Fatal(err)
	}
	wrongKey := page[0]
	for _, item := range page {
		if item.Fingerprint != wrongKey.Fingerprint {
			wrongKey.PublicKey = item.PublicKey
			wrongKey.Fingerprint = item.Fingerprint
			break
		}
	}
	if wrongKey.Fingerprint == page[0].Fingerprint {
		t.Fatal("native signature test needs two distinct input signing keys")
	}
	badInputs := &materializedInputs{Manifest: manifest, Directory: filepath.Join(directory, "objects"), Environments: map[string][]frozenPackage{"build": {wrongKey}}}
	bad, err := runner.prepareFrozenEnvironment(ctx, "wrong-frozen-key", badInputs, "build")
	if err == nil {
		bad.cleanup()
		t.Fatal("accepted another retained package's signing identity")
	}
	if !strings.Contains(bad.log, "No public key") {
		t.Fatalf("signature substitution failed for an unrelated reason: %v\n%s", err, bad.log)
	}
}

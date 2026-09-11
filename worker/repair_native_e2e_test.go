package main

// This acceptance test is opt-in because it loads the cached native builder
// archive. It exercises the same Runner.ExecuteWithClient path used by a
// leased repaired preserved build, including a derived lock and recipe input.

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func repairObject(data []byte) inputObject {
	return inputObject{SHA256: hashBytes(data), Size: int64(len(data))}
}

func repairCanonical(value any) []byte {
	data, _ := encodeJSON(value)
	var canonical any
	json.Unmarshal(data, &canonical)
	data, _ = encodeJSON(canonical)
	return data
}

func repairGitHash(kind string, data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d\x00", kind, len(data))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func repairHelperReference(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	var index struct {
		Manifests []struct {
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if strings.TrimPrefix(header.Name, "./") != "index.json" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(reader, 1<<20+1))
		if err != nil {
			return "", err
		}
		if len(data) > 1<<20 || json.Unmarshal(data, &index) != nil || len(index.Manifests) != 1 {
			return "", fmt.Errorf("helper archive has invalid OCI index")
		}
		break
	}
	if len(index.Manifests) != 1 || !strings.HasPrefix(index.Manifests[0].Digest, "sha256:") || len(strings.TrimPrefix(index.Manifests[0].Digest, "sha256:")) != 64 {
		return "", fmt.Errorf("helper archive omits a valid OCI manifest digest")
	}
	name := index.Manifests[0].Annotations["org.opencontainers.image.ref.name"]
	if at := strings.LastIndex(name, "@"); at >= 0 {
		name = name[:at]
	} else if slash := strings.LastIndex(name, "/"); strings.LastIndex(name, ":") > slash {
		name = name[:strings.LastIndex(name, ":")]
	}
	if name == "" {
		name = "localhost/opr-template-matrix"
	}
	return name + "@" + index.Manifests[0].Digest, nil
}

func TestPreservedRepairNativeRunner(t *testing.T) {
	if os.Getenv("OPR_REPAIR_NATIVE") != "1" {
		t.Skip("set OPR_REPAIR_NATIVE=1 with cached native images to run")
	}
	root, err := os.MkdirTemp(filepath.Join("..", ".local", "repair-native"), "runner-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	objects := map[string][]byte{}
	object := func(data []byte) inputObject { ref := repairObject(data); objects[ref.SHA256] = data; return ref }
	readPath := func(name string) []byte {
		value, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	builder := os.Getenv("OPR_REPAIR_BUILDER_IMAGE")
	runtimeImage := os.Getenv("OPR_REPAIR_RUNTIME_IMAGE")
	helperPath := os.Getenv("OPR_REPAIR_HELPER_ARCHIVE")
	if runtimeImage == "" {
		runtimeImage = "localhost/opr-template-matrix-runtime@sha256:ae22cd0d6dc6ce18d4e373b407d6566270f9c68f3a6eeb03958aa66ab340d940"
	}
	if helperPath == "" {
		helperPath = filepath.Join("..", ".local", "repair-native", "helper.tar")
	}
	if _, err := os.Stat(helperPath); err != nil {
		t.Skipf("cached helper archive is unavailable: %v", err)
	}
	if builder == "" {
		builder, err = repairHelperReference(helperPath)
		if err != nil {
			t.Fatal(err)
		}
	}
	original := []byte("pkgname=opr-repair-fixture\npkgver=1.0\npkgrel=1\narch=('x86_64')\nlicense=('MIT')\nsource=()\nsha256sums=()\nbuild() { :; }\npackage() { install -Dm644 /etc/hostname \"$pkgdir/usr/share/opr-repair-fixture/hostname\"; }\n")
	repaired := bytes.Replace(original, []byte("pkgrel=1"), []byte("pkgrel=2"), 1)
	repaired = append(repaired, []byte("# bounded repair\n")...)
	recipeRef := object(repaired)
	// Build a complete one-file Git capture proof around original recipe bytes.
	blob := repairGitHash("blob", original)
	blobBytes, _ := hex.DecodeString(blob)
	recipeTreeBytes := append([]byte("100644 PKGBUILD\x00"), blobBytes...)
	recipeTree := repairGitHash("tree", recipeTreeBytes)
	recipeTreeBytesRef, _ := hex.DecodeString(recipeTree)
	rootTreeBytes := append([]byte("40000 recipe\x00"), recipeTreeBytesRef...)
	rootTree := repairGitHash("tree", rootTreeBytes)
	commitBytes := []byte("tree " + rootTree + "\ncommitter repair <repair@example.invalid> 1700000000 +0000\n\nfixture\n")
	commit := repairGitHash("commit", commitBytes)
	capture := recipeCaptureManifest{SchemaVersion: 1, Kind: "recipe-capture", Pkgbase: "opr-repair-fixture", Origin: "opr", Repository: "https://github.com/example/recipes", Commit: commit, Directory: "recipe", Git: struct {
		Commit inputObject   `json:"commit"`
		Trees  []inputObject `json:"trees"`
	}{Commit: object(commitBytes), Trees: []inputObject{object(rootTreeBytes), object(recipeTreeBytes)}}, Files: []recipeCaptureFile{{Path: "PKGBUILD", Mode: "100644", Object: object(original)}}}
	captureBytes := repairCanonical(capture)
	captureRef := object(captureBytes)
	srcinfo := "pkgbase = opr-repair-fixture\n\tpkgver = 1.0\n\tpkgrel = 2\n\tarch = x86_64\n\tlicense = MIT\n\npkgname = opr-repair-fixture\n"
	plan := recipeSourcePlan{SchemaVersion: 1, Kind: "recipe-source-plan", Capture: captureRef, Pkgbase: "opr-repair-fixture", Version: "1.0-1", Architecture: "x86_64", Sources: []plannedRecipeSource{}, ValidPGPKeys: []string{}}
	plan.Inspection.JobID, plan.Inspection.Attempt, plan.Inspection.ReportSHA256, plan.Inspection.SrcinfoSHA256 = "repair-inspection", 1, hashBytes([]byte("repair-report")), hashBytes([]byte(srcinfo))
	planRef := object(repairCanonical(plan))
	bundle := recipeSourceBundle{SchemaVersion: 1, Kind: "recipe-source-bundle", Plan: planRef, Sources: []retainedRecipeSource{}, Caches: []struct {
		Kind          string      `json:"kind"`
		Object        inputObject `json:"object"`
		Entries       int         `json:"entries"`
		ExpandedBytes int64       `json:"expandedBytes"`
	}{}, Keys: []struct {
		Fingerprint string      `json:"fingerprint"`
		Object      inputObject `json:"object"`
	}{}}
	bundleRef := object(repairCanonical(bundle))
	inputObjects := map[string]string{}
	for digest, data := range objects {
		path := filepath.Join(root, digest)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		inputObjects[digest] = path
	}
	// A valid frozen package is built and signed by the setup command; the test
	// only reads its retained immutable bytes.
	packagePath := filepath.Join("..", ".local", "repair-native", "pkg", "opr-frozen-base-1.0-1-x86_64.pkg.tar.zst")
	signaturePath := packagePath + ".sig"
	publicKeyPath := filepath.Join(filepath.Dir(packagePath), "public-key.asc")
	packageBytes, signatureBytes, publicKeyBytes := readPath(packagePath), readPath(signaturePath), readPath(publicKeyPath)
	packageRef, signatureRef, publicKeyRef := object(packageBytes), object(signatureBytes), object(publicKeyBytes)
	frozenPkg := frozenPackage{Name: "opr-frozen-base", Version: "1.0-1", Architecture: "x86_64", Filename: "opr-frozen-base-1.0-1-x86_64.pkg.tar.zst", Package: packageRef, Signature: signatureRef, PublicKey: publicKeyRef, Fingerprint: os.Getenv("OPR_REPAIR_GPG_FINGERPRINT"), Origin: "external-bootstrap", OriginEvidence: hashBytes([]byte("repair-origin"))}
	if frozenPkg.Fingerprint == "" {
		frozenPkg.Fingerprint = "3FD1FF01FA743782A4569DA36456E2AFA57BE2ED"
	}
	pageRef := object(repairCanonical([]frozenPackage{frozenPkg}))
	helperSha, helperSize, err := hashFile(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	helperRef := inputObject{SHA256: helperSha, Size: helperSize}
	makepkgRef := object([]byte("CARCH=\"x86_64\"\nCHOST=\"x86_64-pc-linux-gnu\"\nBUILDENV=(!distcc !color !ccache check !sign)\nOPTIONS=(!strip !debug !lto)\nSRCEXT=\".src.tar.gz\"\nBUILDDIR=\"/opr/work/build\"\nPKGDEST=\"/opr/output\"\nSRCDEST=\"/opr/work\"\nSRCPKGDEST=\"/opr/output\"\nLOGDEST=\"/opr/output\"\n"))
	cohortSha := hashBytes([]byte("repair-cohort"))
	inventorySha := hashBytes([]byte("opr-frozen-base 1.0-1\n"))
	environments := []frozenEnvironment{{Name: "build", PackageCount: 1, TotalBytes: packageRef.Size, InventorySHA256: inventorySha, Chunks: []inputObject{pageRef}}, {Name: "runtime-0", PackageCount: 1, TotalBytes: packageRef.Size, InventorySHA256: inventorySha, Chunks: []inputObject{pageRef}}}
	manifest := frozenInputManifest{SchemaVersion: 1, Purpose: "bootstrap", Architecture: "x86_64", RecipeSHA256: recipeRef.SHA256, CohortSHA256: cohortSha, SourceDateEpoch: 1700000000, HelperImage: builder, HelperArchive: helperRef, MakepkgConfig: makepkgRef, TransferLimitBytes: 4 << 30, Environments: environments}
	lockBytes := repairCanonical(manifest)
	lockRef := object(lockBytes)
	for digest, data := range objects {
		path := filepath.Join(root, digest)
		if _, err := os.Stat(path); err != nil {
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		inputObjects[digest] = path
	}
	inputObjects[helperRef.SHA256] = helperPath
	job := Job{ID: "repair-native", LeaseToken: "repair-lease", LeaseExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Attempt: 2, RevisionID: "repair-successor", PackageName: "opr-repair-fixture", Version: "1.0", Pkgrel: 2, Architecture: "x86_64", Recipe: string(repaired), RecipeSHA256: recipeRef.SHA256, SourceDateEpoch: manifest.SourceDateEpoch, ImageRef: builder, ImageDigest: builder[strings.LastIndex(builder, "@"):][1:], Sources: []Source{}, SmokeCommands: []string{"find /usr/share/opr-repair-fixture -maxdepth 1 -ls || true", "test -f /usr/share/opr-repair-fixture/hostname"}, Surface: "binary", InputLock: &lockRef, OutputContract: &outputContract{SchemaVersion: 2, Cohort: struct {
		ID             string `json:"id"`
		Revision       int64  `json:"revision"`
		ManifestSHA256 string `json:"manifestSha256"`
	}{ID: "repair-cohort", Revision: 1, ManifestSHA256: cohortSha}, Outputs: []expectedOutput{{Name: "opr-repair-fixture", FullVersion: "1.0-2", Architecture: "x86_64"}}, RuntimeGroups: [][]string{{"opr-repair-fixture"}}}, PreservedRecipe: &preservedBuildInputs{Capture: captureRef, SourceBundle: bundleRef, Recipe: &recipeRef}}
	objects[lockRef.SHA256] = lockBytes
	inputObjects[lockRef.SHA256] = filepath.Join(root, lockRef.SHA256)
	os.WriteFile(inputObjects[lockRef.SHA256], lockBytes, 0o600)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasSuffix(req.URL.Path, "/registry-credentials") {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"registry":"registry.cloudflare.com","username":"fixture","password":"fixture","expiresAt":"2099-01-01T00:00:00Z"}`)
			return
		}
		digest := filepath.Base(req.URL.Path)
		path := inputObjects[digest]
		file, err := os.Open(path)
		if err != nil {
			fmt.Printf("missing input %s path=%s err=%v\\n", digest, path, err)
			http.NotFound(w, req)
			return
		}
		defer file.Close()
		info, _ := file.Stat()
		w.Header().Set("Content-Length", fmt.Sprint(info.Size()))
		io.Copy(w, file)
	}))
	defer server.Close()
	runner := Runner{Runtime: "podman", Origin: server.URL, Image: builder, ImageDigest: builder[strings.LastIndex(builder, "@"):][1:], RuntimeImage: runtimeImage, StateDir: filepath.Join(root, "state"), BuildTimeout: 20 * time.Minute}
	key, _ := generateKey()
	client := &Client{Origin: mustURL(t, server.URL), WorkerID: "repair-fixture", PrivateKey: key, HTTP: server.Client()}
	if _, err := runner.run(context.Background(), "load", "-i", helperPath); err != nil {
		t.Fatalf("load inspection helper: %v", err)
	}
	inspectionJob := Job{Kind: "recipe-inspection", ID: "repair-native-inspection", LeaseToken: "inspection-lease", LeaseExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Attempt: 1, PackageName: job.PackageName, Architecture: job.Architecture, RecipeCapture: &captureRef, RecipeOverride: &recipeRef, ImageRef: builder, ImageDigest: job.ImageDigest}
	inspectionReport := recipeInspectionReport{SchemaVersion: 1, Kind: "recipe-inspection", JobID: inspectionJob.ID, Attempt: inspectionJob.Attempt, Capture: captureRef, RecipeOverride: &recipeRef, Architecture: inspectionJob.Architecture, ImageRef: builder, StartedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := runner.inspectRecipeCapture(context.Background(), client, inspectionJob, &inspectionReport); err != nil {
		t.Fatalf("repaired recipe inspection failed: %v\n%s", err, inspectionReport.Log)
	}
	inspectionReport.SrcinfoSHA256 = hashBytes([]byte(inspectionReport.Srcinfo))
	if inspectionReport.Error != nil || inspectionReport.SrcinfoSHA256 == "" || inspectionReport.SrcinfoSHA256 != hashBytes([]byte(inspectionReport.Srcinfo)) {
		t.Fatalf("inspection did not produce a fresh observed source hash: error=%v hash=%s", inspectionReport.Error, inspectionReport.SrcinfoSHA256)
	}
	job.PreservedRecipe.Inspection = &struct {
		SrcinfoSHA256 string            `json:"srcinfoSha256"`
		Architectures map[string]string `json:"architectures,omitempty"`
	}{SrcinfoSHA256: inspectionReport.SrcinfoSHA256, Architectures: map[string]string{"x86_64": inspectionReport.SrcinfoSHA256}}
	result, err := runner.ExecuteWithClient(context.Background(), job, nil, client)
	if err != nil {
		if result.Cleanup != nil {
			result.Cleanup()
		}
		t.Fatalf("repaired preserved runner failed: %v\n%s", err, result.Log)
	}
	if len(result.Outputs) != 1 || !result.SmokePassed {
		t.Fatalf("repaired preserved runner omitted output or smoke: %+v", result)
	}
	if result.Cleanup != nil {
		result.Cleanup()
	}
}

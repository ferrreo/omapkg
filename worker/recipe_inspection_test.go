package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRecipeInspectionPreservesGitBytesAndFencesUnsafeMaterialization(t *testing.T) {
	for input, expected := range map[string]string{"vendor_id\t: AuthenticAMD\n": "x86_64", "CPU architecture: 8\n": "aarch64",
		"vendor_id: GenuineIntel\nCPU architecture: 8\n": "", "model name: unknown\n": ""} {
		if actual := cpuInfoArchitecture([]byte(input)); actual != expected {
			t.Fatalf("CPU family %q = %q, want %q", input, actual, expected)
		}
	}
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(filepath.Join(repo, "recipe", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("git", append([]string{"-C", repo, "-c", "core.hooksPath=/dev/null"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("Git fixture: %s: %v", out, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init")
	for name, text := range map[string]string{
		"PKGBUILD": `pkgname=demo
pkgver=1.0
pkgrel=1
epoch=2
arch=('x86_64' 'aarch64')
pkgdesc='Original recipe with native isolation checks'
test "$(id -u):$(id -g)" = 65534:65534 || exit 71
test "$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n')" = lo || exit 72
if timeout 2 bash -c 'exec 3<>/dev/tcp/198.51.100.1/80'; then exit 73; fi
if touch /etc/inspection-escape /recipe/inspection-escape 2>/dev/null; then exit 74; fi
test ! -e /etc/inspection-escape && test ! -e /recipe/inspection-escape || exit 75
test ! -e /var/run/docker.sock && test ! -e /run/podman/podman.sock || exit 76
test -x sub/tool && test -L tool-link && ./tool-link || exit 77
test -f 'Notes with spaces.md' && test -f empty || exit 78
package() { :; }
`,
		"Notes with spaces.md": "Original bytes: café\n", "sub/tool": "#!/bin/sh\ntrue\n", "empty": "",
	} {
		if err := os.WriteFile(filepath.Join(repo, "recipe", name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(repo, "recipe", "sub", "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub/tool", filepath.Join(repo, "recipe", "tool-link")); err != nil {
		t.Fatal(err)
	}
	commit := func() {
		git("add", ".")
		git("-c", "user.name=Inspection fixture", "-c", "user.email=test@example.invalid", "commit", "-m", "Fixture")
	}
	commit()
	capture := func(name string) (string, inputObject) {
		t.Helper()
		directory := filepath.Join(root, name)
		out, err := exec.Command("python3", "../services/pipeline/capture-recipe.py", "--git-directory", repo, "--repository", "https://github.com/example/recipes",
			"--commit", git("rev-parse", "HEAD"), "--directory", "recipe", "--pkgbase", "demo", "--origin", "opr", "--output", directory).CombinedOutput()
		if err != nil {
			t.Fatalf("Capture fixture: %s: %v", out, err)
		}
		var ref inputObject
		if err := json.Unmarshal(mustReadFile(t, filepath.Join(directory, "reference.json")), &ref); err != nil {
			t.Fatal(err)
		}
		return directory, ref
	}
	directory, ref := capture("capture")
	materialize := func(directory string, ref inputObject) (string, error) {
		t.Helper()
		job := t.TempDir()
		workdir := filepath.Join(job, "work")
		if err := os.Mkdir(workdir, 0o700); err != nil {
			t.Fatal(err)
		}
		old := syscall.Umask(0o077)
		defer syscall.Umask(old)
		_, err := materializeRecipeCapture(context.Background(), ref, "demo", filepath.Join(job, "objects"), workdir,
			func(_ context.Context, ref inputObject, path string) error {
				return os.WriteFile(path, mustReadFile(t, filepath.Join(directory, "objects", ref.SHA256)), 0o600)
			})
		return workdir, err
	}
	workdir, err := materialize(directory, ref)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"PKGBUILD", "Notes with spaces.md", "empty", "sub/tool"} {
		if string(mustReadFile(t, filepath.Join(workdir, name))) != string(mustReadFile(t, filepath.Join(repo, "recipe", name))) {
			t.Fatalf("file bytes changed: %s", name)
		}
	}
	for path, mode := range map[string]os.FileMode{"PKGBUILD": 0o644, "sub": 0o755, "sub/tool": 0o755} {
		stat, err := os.Stat(filepath.Join(workdir, path))
		if err != nil || stat.Mode().Perm() != mode {
			t.Fatalf("inspection cannot read original mode after restrictive umask: %s", path)
		}
	}
	if target, err := os.Readlink(filepath.Join(workdir, "tool-link")); err != nil || target != "sub/tool" {
		t.Fatal("original symlink changed")
	}
	t.Run("nativeOCI", func(t *testing.T) { testNativeRecipeInspection(t, directory, ref) })
	data := mustReadFile(t, filepath.Join(directory, "objects", ref.SHA256))
	changed := []byte(strings.Replace(string(data), `"kind"`, `"Kind"`, 1))
	wrong := inputObject{SHA256: hashBytes(changed), Size: int64(len(changed))}
	if err := os.WriteFile(filepath.Join(directory, "objects", wrong.SHA256), changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := materialize(directory, wrong); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("case-aliased JSON accepted: %v", err)
	}
	if err := os.Symlink("../../outside", filepath.Join(repo, "recipe", "escape")); err != nil {
		t.Fatal(err)
	}
	commit()
	unsafeDirectory, unsafeRef := capture("unsafe")
	unsafeWorkdir, err := materialize(unsafeDirectory, unsafeRef)
	if err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("escaping original symlink accepted: %v", err)
	}
	if entries, _ := os.ReadDir(unsafeWorkdir); len(entries) != 0 {
		t.Fatal("recipe files materialized before complete proof validation")
	}
	job := Job{Kind: "recipe-inspection", ID: "inspection-test", PackageName: "demo", Architecture: "x86_64", RecipeCapture: &ref, Attempt: 1,
		ImageRef: "registry.example.org/inspection@sha256:" + strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("a", 64), LeaseToken: "lease", LeaseExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339)}
	if err := validateRecipeInspectionJob(job, Config{Architecture: "x86_64"}); err != nil {
		t.Fatal(err)
	}
	if err := validateJob(job, Config{Architecture: "x86_64"}); err == nil {
		t.Fatal("inspection accepted by build protocol")
	}
	job.InputLock = &ref
	if err := validateRecipeInspectionJob(job, Config{Architecture: "x86_64"}); err == nil {
		t.Fatal("inspection accepted mixed build authority")
	}
}

func testNativeRecipeInspection(t *testing.T, directory string, ref inputObject) {
	image := os.Getenv("OPR_WORKER_E2E_IMAGE")
	if image == "" {
		t.Skip("OPR_WORKER_E2E_IMAGE is not set")
	}
	architecture := os.Getenv("OPR_WORKER_E2E_ARCH")
	if architecture == "" {
		architecture = "x86_64"
	}
	runtime := os.Getenv("OPR_WORKER_E2E_RUNTIME")
	if runtime == "" {
		runtime = "podman"
	}
	key, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	job := Job{Kind: "recipe-inspection", ID: "native-inspection", PackageName: "demo", Architecture: architecture, RecipeCapture: &ref,
		ImageRef: image, ImageDigest: image[strings.LastIndex(image, "@")+1:], Attempt: 1, LeaseToken: "native-test-lease",
		LeaseExpiresAt: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)}
	completed := make(chan recipeInspectionReport, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(request.Body, 2<<20))
		signature, _ := base64.StdEncoding.DecodeString(request.Header.Get("X-OPR-Signature"))
		payload := makeSignaturePayload(request.Method, canonicalRequestPath(request.URL), request.Header.Get("X-OPR-Timestamp"), request.Header.Get("X-OPR-Nonce"), hashBytes(body))
		var input struct {
			LeaseToken string `json:"leaseToken"`
			Report     string `json:"report"`
			Signature  string `json:"signature"`
		}
		if request.Method != "POST" || !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, signature) ||
			json.Unmarshal(body, &input) != nil || input.LeaseToken != job.LeaseToken {
			http.Error(w, "invalid signed inspection request", 403)
			return
		}
		prefix := "/api/worker/inspections/" + job.ID + "/"
		switch {
		case strings.HasPrefix(request.URL.Path, prefix+"inputs/"):
			digest := strings.TrimPrefix(request.URL.Path, prefix+"inputs/")
			if !sha256Pattern.MatchString(digest) {
				http.NotFound(w, request)
				return
			}
			data, err := os.ReadFile(filepath.Join(directory, "objects", digest))
			if err != nil {
				http.NotFound(w, request)
				return
			}
			w.Write(data)
		case request.URL.Path == prefix+"heartbeat":
			io.WriteString(w, `{"cancel":false}`)
		case request.URL.Path == prefix+"complete":
			var report recipeInspectionReport
			signature, _ := base64.StdEncoding.DecodeString(input.Signature)
			if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(input.Report), signature) || json.Unmarshal([]byte(input.Report), &report) != nil {
				http.Error(w, "invalid signed report", 403)
				return
			}
			completed <- report
			t.Logf("Native inspection evidence: %s; signature=%s; publicKey=%s", input.Report, input.Signature, base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
			io.WriteString(w, `{"status":"succeeded"}`)
		default:
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	origin, _ := url.Parse(server.URL)
	client := &Client{Origin: origin, WorkerID: "inspection-fixture", PrivateKey: key, HTTP: server.Client()}
	runner := &Runner{Runtime: runtime, StateDir: t.TempDir()}
	if err := runRecipeInspection(context.Background(), client, runner, Config{Architecture: architecture}, job); err != nil {
		t.Fatal(err)
	}
	select {
	case report := <-completed:
		if report.Error != nil || report.Host == nil || report.Host.Architecture != architecture || report.Capture != ref ||
			report.SrcinfoSHA256 != hashBytes([]byte(report.Srcinfo)) || !strings.Contains(report.Srcinfo, "pkgbase = demo") || !strings.Contains(report.Srcinfo, "epoch = 2") {
			t.Fatalf("native inspection evidence incomplete: %+v", report)
		}
	default:
		t.Fatal("native inspection omitted signed completion")
	}
}

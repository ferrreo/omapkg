package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T, dir string, private ed25519.PrivateKey) Config {
	t.Helper()
	return Config{
		Origin:         "http://127.0.0.1:8787",
		WorkerID:       "worker-1",
		PrivateKey:     encodePrivateKey(private),
		Image:          "ghcr.io/omarchy/opr-builder@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ImageDigest:    "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Architecture:   "x86_64",
		Runtime:        "podman",
		StateDir:       dir,
		MaxSourceBytes: 1024,
	}
}

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSignaturePayload(t *testing.T) {
	key := testKey(t)
	payload := makeSignaturePayload("POST", "/api/worker/claim", "1700000000", "0123456789abcdef0123456789abcdef", hashBytes([]byte("{}")))
	signature := ed25519.Sign(key, payload)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, signature) {
		t.Fatal("signature did not verify")
	}
	if ed25519.Verify(key.Public().(ed25519.PublicKey), makeSignaturePayload("GET", "/api/worker/claim", "1700000000", "0123456789abcdef0123456789abcdef", hashBytes([]byte("{}"))), signature) {
		t.Fatal("signature verified after method change")
	}
	if got := base64.StdEncoding.EncodeToString(signature); got == "" {
		t.Fatal("empty signature")
	}
}

func TestDaemonMetadataIsFixedAndIndependent(t *testing.T) {
	metadata, err := daemonMetadata("podman")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Version != workerVersion || metadata.Runtime != "podman" {
		t.Fatalf("metadata identity = %+v", metadata)
	}
	want := []string{"offline-oci", "multipart-upload", "registry-pull"}
	if strings.Join(metadata.Capabilities, ",") != strings.Join(want, ",") {
		t.Fatalf("capabilities = %v, want %v", metadata.Capabilities, want)
	}
	metadata.Capabilities[0] = "tampered"
	second, err := daemonMetadata("docker")
	if err != nil {
		t.Fatal(err)
	}
	if second.Capabilities[0] != want[0] {
		t.Fatal("capability declaration aliases mutable state")
	}
	if _, err := daemonMetadata("invalid"); err == nil {
		t.Fatal("invalid runtime accepted")
	}
}

func TestSaveLoadConfigIsPrivateAndAtomic(t *testing.T) {
	dir := t.TempDir()
	key := testKey(t)
	cfg := testConfig(t, dir, key)
	filename := filepath.Join(dir, "config.json")
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(relative, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 600", info.Mode().Perm())
	}
	loaded, err := loadConfig(relative)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.WorkerID != cfg.WorkerID || loaded.PrivateKey != cfg.PrivateKey {
		t.Fatal("loaded config differs")
	}
	if err := os.Chmod(filename, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(filename); err == nil {
		t.Fatal("group-readable config was accepted")
	}
}

func TestValidateJobRejectsRecipeAndSourceTampering(t *testing.T) {
	key := testKey(t)
	cfg := testConfig(t, t.TempDir(), key)
	recipe := "pkgname=demo\npkgver=1\n"
	job := Job{
		ID:             "job-1",
		LeaseToken:     "lease",
		LeaseExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
		RevisionID:     "rev-1",
		PackageName:    "demo",
		Version:        "1",
		Architecture:   cfg.Architecture,
		Recipe:         recipe,
		RecipeSHA256:   hashBytes([]byte(recipe)),
		ImageDigest:    cfg.ImageDigest,
		Sources:        []Source{{Name: "demo.tar.gz", URL: "https://example.com/demo.tar.gz", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
		Surface:        "binary",
	}
	if err := validateJob(job, cfg); err != nil {
		t.Fatal(err)
	}
	job.Recipe += "# changed"
	if err := validateJob(job, cfg); err == nil {
		t.Fatal("recipe tampering was accepted")
	}
	job.Recipe = recipe
	job.RecipeSHA256 = hashBytes([]byte(recipe))
	job.Sources[0].Name = "../escape"
	if err := validateJob(job, cfg); err == nil {
		t.Fatal("unsafe source name was accepted")
	}
}

func TestValidateJobDependencyGrammarAndPkgver(t *testing.T) {
	key := testKey(t)
	cfg := testConfig(t, t.TempDir(), key)
	recipe := "pkgname=demo\npkgver=1.0\n"
	job := Job{
		ID: "job-dependencies", LeaseToken: "lease", LeaseExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
		RevisionID: "rev-dependencies", PackageName: "demo", Version: "1.0", Architecture: cfg.Architecture,
		Recipe: recipe, RecipeSHA256: hashBytes([]byte(recipe)), ImageDigest: cfg.ImageDigest,
		Sources:      []Source{{Name: "demo.tar.gz", URL: "https://example.com/demo.tar.gz", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
		Dependencies: []string{"libfoo>=2.0-1"}, RuntimeDependencies: []string{"runtime=1:2.0"}, MakeDependencies: []string{"base-devel"}, Surface: "binary",
	}
	if err := validateJob(job, cfg); err != nil {
		t.Fatalf("valid Arch dependency constraints rejected: %v", err)
	}
	for _, dependency := range []string{"libfoo>>2", "libfoo>", "libfoo>=2:0:1", "lib foo", "libfoo:bar"} {
		job.Dependencies = []string{dependency}
		job.RuntimeDependencies = nil
		job.MakeDependencies = nil
		if err := validateJob(job, cfg); err == nil {
			t.Fatalf("unsafe Arch dependency accepted: %q", dependency)
		}
	}
	for _, version := range []string{"1-rc1", "1:2.0", "1.0-1"} {
		job.Dependencies = nil
		job.Version = version
		if err := validateJob(job, cfg); err == nil {
			t.Fatalf("invalid Arch pkgver accepted: %q", version)
		}
	}
}

func TestJobImageReferenceUsesReviewedImageAndLegacyFallback(t *testing.T) {
	key := testKey(t)
	cfg := testConfig(t, t.TempDir(), key)
	updatedDigest := "sha256:" + strings.Repeat("f", 64)
	updatedRef := "registry.example/opr-builder:stable@" + updatedDigest
	job := Job{ImageDigest: updatedDigest, ImageRef: updatedRef}
	got, err := imageReferenceForJob(job, cfg)
	if err != nil || got != updatedRef {
		t.Fatalf("reviewed image = %q, err=%v", got, err)
	}
	job.ImageRef = ""
	job.ImageDigest = cfg.ImageDigest
	got, err = imageReferenceForJob(job, cfg)
	if err != nil || got != cfg.Image {
		t.Fatalf("legacy image = %q, err=%v", got, err)
	}
	job.ImageRef = "registry.example/opr-builder:stable@sha256:" + strings.Repeat("0", 64)
	if _, err := imageReferenceForJob(job, cfg); err == nil {
		t.Fatal("mismatched image reference was accepted")
	}
}

func TestConfigMayDeferImageSelectionToClaim(t *testing.T) {
	key := testKey(t)
	cfg := testConfig(t, t.TempDir(), key)
	cfg.Image = ""
	cfg.ImageDigest = ""
	if err := validateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	job := Job{ImageDigest: "sha256:" + strings.Repeat("f", 64), ImageRef: "registry.example/opr-builder@sha256:" + strings.Repeat("f", 64)}
	if got, err := imageReferenceForJob(job, cfg); err != nil || got != job.ImageRef {
		t.Fatalf("deferred image = %q, err=%v", got, err)
	}
}

func TestOriginRejectsCredentialsAndQuery(t *testing.T) {
	for _, origin := range []string{
		"https://worker.example.test/?token=secret",
		"https://worker.example.test/#fragment",
		"https://user:pass@worker.example.test",
	} {
		if err := validateOrigin(origin); err == nil {
			t.Fatalf("unsafe origin accepted: %s", origin)
		}
	}
}

func TestClientRequestsEphemeralRegistryCredentials(t *testing.T) {
	key := testKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/worker/jobs/job-1/registry-credentials" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.StdEncoding.DecodeString(request.Header.Get("X-OPR-Signature"))
		if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), makeSignaturePayload(request.Method, request.URL.RequestURI(), request.Header.Get("X-OPR-Timestamp"), request.Header.Get("X-OPR-Nonce"), hashBytes(body)), signature) {
			t.Fatal("registry credential request signature did not verify")
		}
		if string(body) != `{"leaseToken":"lease"}` {
			t.Fatalf("registry credential body = %s", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"registry":"registry.cloudflare.com","username":"worker","password":"ephemeral-secret","expiresAt":"2099-01-01T00:00:00Z"}`))
	}))
	defer server.Close()
	client := &Client{Origin: mustURL(t, server.URL), WorkerID: "worker-1", PrivateKey: key, HTTP: server.Client()}
	credentials, err := client.registryCredentials(context.Background(), "job-1", "lease")
	if err != nil {
		t.Fatal(err)
	}
	if credentials.Registry != "registry.cloudflare.com" || credentials.Username != "worker" || credentials.Password != "ephemeral-secret" {
		t.Fatalf("unexpected credentials response: %+v", credentials)
	}
}

func TestClientSignsClaim(t *testing.T) {
	key := testKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/worker/claim" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.String())
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"version":"v0.1.0","runtime":"podman","capabilities":["offline-oci","multipart-upload","registry-pull"]}` {
			t.Fatalf("claim metadata body = %s", body)
		}
		timestamp := request.Header.Get("X-OPR-Timestamp")
		nonce := request.Header.Get("X-OPR-Nonce")
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(timestamp) || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(nonce) {
			t.Fatal("invalid signed request headers")
		}
		signature, err := base64.StdEncoding.DecodeString(request.Header.Get("X-OPR-Signature"))
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(key.Public().(ed25519.PublicKey), makeSignaturePayload(request.Method, request.URL.RequestURI(), timestamp, nonce, hashBytes(body)), signature) {
			t.Fatal("request signature did not verify")
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"job":null}`))
	}))
	defer server.Close()
	client := &Client{
		Origin:     mustURL(t, server.URL),
		WorkerID:   "worker-1",
		PrivateKey: key,
		Metadata:   WorkerMetadata{Version: "v0.1.0", Runtime: "podman", Capabilities: []string{"offline-oci", "multipart-upload", "registry-pull"}},
		HTTP:       server.Client(),
	}
	job, err := client.claim(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if job != nil {
		t.Fatal("expected empty queue")
	}
}

func TestClientEnrollmentReportsMetadata(t *testing.T) {
	key := testKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"token":"enrollment-token","name":"worker-1","architecture":"x86_64","publicKey":"`+encodeStandardBase64(key.Public().(ed25519.PublicKey))+`","version":"v0.1.0","runtime":"podman","capabilities":["offline-oci","multipart-upload","registry-pull"]}` {
			t.Fatalf("enrollment body = %s", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"worker-1"}`))
	}))
	defer server.Close()
	client := &Client{Origin: mustURL(t, server.URL), WorkerID: "unused", PrivateKey: key, HTTP: server.Client()}
	metadata := WorkerMetadata{Version: "v0.1.0", Runtime: "podman", Capabilities: []string{"offline-oci", "multipart-upload", "registry-pull"}}
	workerID, err := client.postEnrollment(context.Background(), "enrollment-token", "worker-1", "x86_64", key.Public().(ed25519.PublicKey), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if workerID != "worker-1" {
		t.Fatalf("worker ID = %q", workerID)
	}
}

func TestClientHeartbeatReportsMetadata(t *testing.T) {
	key := testKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != `{"leaseToken":"lease","version":"v0.1.0","runtime":"docker","capabilities":["offline-oci","multipart-upload","registry-pull"]}` {
			t.Fatalf("heartbeat metadata body = %s", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"leaseExpiresAt":"2099-01-01T00:00:00Z","cancel":false}`))
	}))
	defer server.Close()
	client := &Client{
		Origin:     mustURL(t, server.URL),
		WorkerID:   "worker-1",
		PrivateKey: key,
		Metadata:   WorkerMetadata{Version: "v0.1.0", Runtime: "docker", Capabilities: []string{"offline-oci", "multipart-upload", "registry-pull"}},
		HTTP:       server.Client(),
	}
	response, err := client.heartbeat(context.Background(), "job-1", "lease")
	if err != nil {
		t.Fatal(err)
	}
	if response.Cancel {
		t.Fatal("heartbeat unexpectedly cancelled job")
	}
}

func TestClientUploadsArtifactInBoundedChunks(t *testing.T) {
	key := testKey(t)
	content := []byte("0123456789")
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			return
		}
		signature, err := base64.StdEncoding.DecodeString(request.Header.Get("X-OPR-Signature"))
		if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), makeSignaturePayload(request.Method, request.URL.RequestURI(), request.Header.Get("X-OPR-Timestamp"), request.Header.Get("X-OPR-Nonce"), hashBytes(body)), signature) {
			t.Error("invalid upload request signature")
			return
		}
		seen = append(seen, request.Method+" "+request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/worker/jobs/job-1/uploads":
			_, _ = writer.Write([]byte(`{"uploadId":"upload-1","partSize":4,"maxSize":100,"filename":"opr-hello-1-1-x86_64.pkg.tar.zst","size":10,"sha256":"84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882","parts":[]}`))
		case request.Method == http.MethodPut && strings.HasSuffix(request.URL.Path, "/1"):
			_, _ = writer.Write([]byte(`{"partNumber":1,"sha256":"1be2e452b46d7a0d9656bbb1f768e8248eba1b75baed65f5d99eafa948899a6a","size":4,"etag":"e1"}`))
		case request.Method == http.MethodPut && strings.HasSuffix(request.URL.Path, "/2"):
			_, _ = writer.Write([]byte(`{"partNumber":2,"sha256":"db2e7f1bd5ab9968ae76199b7cc74795ca7404d5a08d78567715ce532f9d2669","size":4,"etag":"e2"}`))
		case request.Method == http.MethodPut && strings.HasSuffix(request.URL.Path, "/3"):
			_, _ = writer.Write([]byte(`{"partNumber":3,"sha256":"cd70bea023f752a0564abb6ed08d42c1440f2e33e29914e55e0be1595e24f45a","size":2,"etag":"e3"}`))
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/complete"):
			_, _ = writer.Write([]byte(`{"key":"private/builds/job-1/artifact","sha256":"84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882","size":10,"filename":"opr-hello-1-1-x86_64.pkg.tar.zst"}`))
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	filename := filepath.Join(t.TempDir(), "opr-hello-1-1-x86_64.pkg.tar.zst")
	if err := os.WriteFile(filename, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := hashBytes(content)
	client := &Client{Origin: mustURL(t, server.URL), WorkerID: "worker-1", PrivateKey: key, HTTP: server.Client()}
	if _, err := client.uploadArtifact(context.Background(), "job-1", "lease", filepath.Base(filename), file, int64(len(content)), digest); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 5 {
		t.Fatalf("saw %d upload requests, want 5", len(seen))
	}
}

func TestClientResumesCompletedMultipartUpload(t *testing.T) {
	key := testKey(t)
	content := []byte("already complete")
	filename := "opr-hello-1-1-x86_64.pkg.tar.zst"
	digest := hashBytes(content)
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Method != http.MethodPost || request.URL.Path != "/api/worker/jobs/job-1/uploads" {
			t.Fatalf("unexpected retry request %s %s", request.Method, request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"completed":{"key":"private/builds/job-1/artifact","sha256":"` + digest + `","size":16,"filename":"` + filename + `"}}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), filename)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	client := &Client{Origin: mustURL(t, server.URL), WorkerID: "worker-1", PrivateKey: key, HTTP: server.Client()}
	artifact, err := client.uploadArtifact(context.Background(), "job-1", "lease", filename, file, int64(len(content)), digest)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Key == "" || artifact.SHA256 != digest || artifact.Size != int64(len(content)) || artifact.Filename != filename || requests != 1 {
		t.Fatalf("completed artifact = %+v, requests = %d", artifact, requests)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

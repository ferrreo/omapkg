package main

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func factoryContextTar(t *testing.T, name string, data []byte, mode int64) string {
	t.Helper()
	var body bytes.Buffer
	writer := tar.NewWriter(&body)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "context.tar")
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestFactoryImageContextExtractionRejectsUnsafeArchives(t *testing.T) {
	archivePath := factoryContextTar(t, "packages/fixture.pkg.tar.zst", []byte("package"), 0o644)
	destination := filepath.Join(t.TempDir(), "context")
	if err := extractFactoryImageContext(context.Background(), archivePath, destination); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(destination, "packages/fixture.pkg.tar.zst")); err != nil || string(got) != "package" {
		t.Fatalf("extracted context = %q, err=%v", got, err)
	}
	unsafe := factoryContextTar(t, "../escape", []byte("no"), 0o644)
	if err := extractFactoryImageContext(context.Background(), unsafe, filepath.Join(t.TempDir(), "unsafe")); err == nil {
		t.Fatal("unsafe context path was accepted")
	}
}

func TestFactoryImageContextLockIsBoundToExtractedContext(t *testing.T) {
	source := filepath.Join(t.TempDir(), "candidate-lock.json")
	contents := []byte(`{"authority":"factory-candidate-v1"}`)
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	expected := factoryImageObject{SHA256: hashBytes(contents), Size: int64(len(contents))}
	contextDir := t.TempDir()
	destination := filepath.Join(contextDir, "candidate-lock.json")
	if err := bindFactoryImageContextFile(source, destination, expected); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(destination); err != nil || !bytes.Equal(got, contents) {
		t.Fatalf("bound context lock = %q, err=%v", got, err)
	}
	if err := os.WriteFile(destination, []byte(`{"authority":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bindFactoryImageContextFile(source, destination, expected); err == nil {
		t.Fatal("mismatched extracted context lock was accepted")
	}
}

func TestFactoryImagePrivilegesAreScopedToFilesystemAssembly(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"gpg", "podman"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	cfg := testConfig(t, dir, testKey(t))
	cfg.FactoryImage = true
	cfg.FactoryImageBuilderPath = filepath.Join(dir, "image-builder")
	cfg.FactoryImageBuilderSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if !factoryImageSupported(cfg) {
		t.Fatal("image capability must not depend on host UID or KVM")
	}
	for _, kind := range []string{"oci", "system"} {
		job := &factoryImageJob{ID: "fixture", Candidate: factoryImageCandidate{Kind: kind, CandidateLock: factoryImageObject{File: "candidate-lock.json"}, Context: &factoryImageObject{}, Dockerfile: &factoryImageObject{}}}
		command, _, err := factoryImageBuilderCommand(context.Background(), cfg, job, dir, dir)
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(command.Args, "--privileged") != (kind == "system") {
			t.Fatalf("unexpected privilege scope for %s: %v", kind, command.Args)
		}
		if slices.Contains(command.Args, "/dev/kvm") {
			t.Fatal("construction must not request a VM boot device")
		}
		if kind == "system" {
			for index, arg := range command.Args {
				if arg == "--candidate-lock" && (index+1 >= len(command.Args) || command.Args[index+1] != "/opr/input/context/candidate-lock.json") {
					t.Fatalf("system candidate lock is not resolved inside context: %v", command.Args)
				}
			}
		}
	}
}

func TestFactoryImageStartupValidationChecksScriptAndBuilderImage(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"gpg"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	imageDigest := "sha256:" + strings.Repeat("a", 64)
	imageRuntime := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo podman; exit 0; fi\nif [ \"$1\" = image ] && [ \"$2\" = inspect ]; then echo '" + imageDigest + "\tlinux\tamd64'; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "podman"), []byte(imageRuntime), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	builder := filepath.Join(dir, "image-builder")
	builderBytes := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(builder, builderBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, dir, testKey(t))
	cfg.FactoryImage = true
	cfg.ImageDigest = imageDigest
	cfg.Image = "localhost/opr-builder@" + imageDigest
	cfg.FactoryImageBuilderPath = builder
	cfg.FactoryImageBuilderSHA256 = hashBytes(builderBytes)
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("valid factory image config rejected: %v", err)
	}
	if metadata, err := daemonMetadataForConfig(cfg); err != nil || !slices.Contains(metadata.Capabilities, "factory-image-v1") {
		t.Fatalf("valid factory image capability missing: metadata=%+v err=%v", metadata, err)
	}
	missingImage := cfg
	missingImage.Image = ""
	missingImage.ImageDigest = ""
	metadata, err := daemonMetadataForConfig(missingImage)
	if err != nil || slices.Contains(metadata.Capabilities, "factory-image-v1") {
		t.Fatalf("missing builder image was advertised: metadata=%+v err=%v", metadata, err)
	}

	if err := os.WriteFile(builder, []byte("changed\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("changed builder accepted: %v", err)
	}
	if err := os.WriteFile(builder, builderBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "podman"), []byte("#!/bin/sh\nif [ \"$1\" = --version ]; then echo podman; exit 0; fi\nif [ \"$1\" = image ] && [ \"$2\" = inspect ]; then echo '"+imageDigest+"\tlinux\tarm64'; exit 0; fi\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("mismatched builder image accepted: %v", err)
	}
}

func TestPackageWorkerDoesNotContactImageQueue(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/api/worker/claim" {
			t.Errorf("package worker contacted image endpoint: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"job":null}`)
	}))
	defer server.Close()
	client := &Client{Origin: mustURL(t, server.URL), WorkerID: "worker-1", PrivateKey: testKey(t), HTTP: server.Client()}
	if err := runLoop(context.Background(), client, &Runner{}, Config{}, true, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("got %d requests, want one ordinary package claim", requests)
	}
}

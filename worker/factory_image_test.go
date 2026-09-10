package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

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
		job := &factoryImageJob{ID: "fixture", Candidate: factoryImageCandidate{Kind: kind, Context: &factoryImageObject{}, Dockerfile: &factoryImageObject{}}}
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

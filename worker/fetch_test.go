package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchSourceChecksSizeAndDigest(t *testing.T) {
	body := []byte("source bytes\n")
	hash := sha256.Sum256(body)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	client := server.Client()
	destination := t.TempDir()
	source := Source{Name: "demo.tar.gz", URL: server.URL, SHA256: hex.EncodeToString(hash[:])}
	if err := fetchSource(context.Background(), client, source, filepath.Join(destination, source.Name), 1024); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(destination, source.Name))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("saved source = %q", got)
	}
	if err := fetchSource(context.Background(), client, source, filepath.Join(t.TempDir(), source.Name), 4); err == nil {
		t.Fatal("oversized source was accepted")
	}
	bad := source
	bad.SHA256 = strings.Repeat("0", 64)
	if err := fetchSource(context.Background(), client, bad, filepath.Join(destination, "bad.tar.gz"), 1024); err == nil {
		t.Fatal("digest mismatch was accepted")
	}
}

func TestSafeSourceValidationRejectsLocalNames(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/source.tar.gz",
		"https://localhost/source.tar.gz",
		"https://repo.local/source.tar.gz",
		"https://user:password@example.com/source.tar.gz",
	} {
		if err := validateSourceURL(raw); err == nil {
			t.Fatalf("unsafe source URL accepted: %s", raw)
		}
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"} {
		if !blockedIP(net.ParseIP(raw)) {
			t.Fatalf("private address accepted: %s", raw)
		}
	}
}

func TestPlatformSourceUsesSignedRequestAndNoRedirect(t *testing.T) {
	body := []byte("verified archive")
	digest := sha256.Sum256(body)
	hexDigest := hex.EncodeToString(digest[:])
	key := testKey(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/sources/"+hexDigest+".tar" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		if request.Header.Get("X-OPR-Worker") != "worker-1" || request.Header.Get("X-OPR-Signature") == "" {
			t.Errorf("platform source request was not signed")
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	origin := mustURL(t, server.URL)
	coordinator := &Client{Origin: origin, WorkerID: "worker-1", PrivateKey: key, HTTP: server.Client()}
	destination := t.TempDir()
	source := Source{Name: "source.tar", URL: server.URL + "/sources/" + hexDigest + ".tar", SHA256: hexDigest}
	fetched, err := fetchSourcesForClient(context.Background(), []Source{source}, destination, 1024, 0, coordinator)
	if err != nil {
		t.Fatal(err)
	}
	if len(fetched) != 1 {
		t.Fatalf("fetched %d sources", len(fetched))
	}
	if got, err := os.ReadFile(fetched[0].Path); err != nil || string(got) != string(body) {
		t.Fatalf("fetched platform source = %q, err=%v", got, err)
	}
}

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type catalogFixtureTransport func(*http.Request) (*http.Response, error)

func (transport catalogFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestCatalogCapturePreservesTargetsRecipesBoundsAndCanonicalHashes(t *testing.T) {
	source := catalogSource{ID: "arch-upstream-extra-aarch64", Target: "aarch64", Collection: "extra"}
	metadata := "%NAME%\nexample\n\n%VERSION%\n2:1.0-1\n\n%ARCH%\nany\n\n%SHA256SUM%\n" + strings.Repeat("a", 64) + "\n\n%FILENAME%\nexample-2:1.0-1-any.pkg.tar.zst\n\n%CSIZE%\n10\n\n%DESC%\nUnicode separator \u2028 and literal \\u2028\n\n"
	archive := func(name, text string) []byte {
		t.Helper()
		var data bytes.Buffer
		writer := tar.NewWriter(&data)
		if err := writer.WriteHeader(&tar.Header{Name: name, Size: int64(len(text)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return data.Bytes()
	}
	entries, err := parseCatalogTar(bytes.NewReader(archive("example-1.0-1/desc", metadata)), source)
	if err != nil || len(entries) != 1 || entries[0].Architecture != "any" || entries[0].Target != "aarch64" || entries[0].Version != "2:1.0-1" {
		t.Fatalf("catalog identity: %+v %v", entries, err)
	}
	for _, name := range []string{"../desc", "root/unexpected", "/root/desc"} {
		if _, err := parseCatalogTar(bytes.NewReader(archive(name, metadata)), source); err == nil {
			t.Fatalf("accepted unsafe catalog entry %q", name)
		}
	}
	if _, err := parseCatalogTar(bytes.NewReader(archive("example/desc", strings.Repeat("a", 512*1024+1))), source); err == nil {
		t.Fatal("accepted oversized catalog entry")
	}
	if _, err := parseCatalogTar(bytes.NewReader(archive("example/desc", strings.Replace(metadata, "any", "x86_64", 1))), source); err == nil {
		t.Fatal("accepted wrong target")
	}
	plan, err := catalogSources("arch", "upstream", []string{"x86_64", "aarch64"}, "", "omapkg")
	if err != nil || len(plan) != 5 {
		t.Fatal("full source plan is missing a repository")
	}
	plan, err = catalogSources("opr", "stable", []string{"x86_64", "aarch64"}, "https://catalog.example.org", "omapkg")
	if err != nil || len(plan) != 4 || plan[1].Format != "recipe-catalog" {
		t.Fatal("OPR plan omits recipe-only outputs")
	}
	directory := t.TempDir()
	if err := writeCatalogCapture(directory, "arch", "upstream", []catalogSourceResult{{catalogSource: source, Status: "captured", Entries: 1, Signature: "missing"}}, entries); err != nil {
		t.Fatal(err)
	}
	index, _ := os.ReadFile(filepath.Join(directory, "index.json"))
	var refs [][]string
	if err := json.Unmarshal(index, &refs); err != nil {
		t.Fatal(err)
	}
	entry, err := catalogJSON(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0][2] != hashBytes(entry) {
		t.Fatal("catalog index does not bind entry bytes")
	}
	if !bytes.Contains(entry, []byte("separator \u2028 and literal \\\\u2028")) {
		t.Fatalf("catalog canonical Unicode changed: %s", entry)
	}
	client := &http.Client{Transport: catalogFixtureTransport(func(request *http.Request) (*http.Response, error) {
		body := `{"items":[{"id":"release-1","name":"example","version":"2:1.0-1","architecture":"x86_64","channel":"stable","surface":"recipe","recipeUrl":"https://catalog.example.org/recipe/PKGBUILD"}],"nextCursor":null}`
		if request.URL.Path == "/recipe/PKGBUILD" {
			body = "pkgname=example\n"
		}
		if request.URL.Path == "/api/catalog/example" {
			body = `{"versions":[{"id":"release-1","dependencies":["bash"]}]}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	data, recipes, err := captureRecipeCatalog(context.Background(), client, plan[1], directory)
	if err != nil || len(recipes) != 1 || recipes[0].Filename != "PKGBUILD" || recipes[0].PackageSignature != nil || recipes[0].Dependencies[0] != "bash" || len(data) == 0 {
		t.Fatalf("recipe capture: %+v %v", recipes, err)
	}
	if body, err := os.ReadFile(filepath.Join(directory, "recipe-"+recipes[0].SHA256+".PKGBUILD")); err != nil || hashBytes(body) != recipes[0].SHA256 {
		t.Fatal("retained recipe bytes changed")
	}
	client.Transport = catalogFixtureTransport(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"items":[{"id":"release-1","name":"example","version":"2:1.0-1","architecture":"x86_64","channel":"dev","surface":"recipe","recipeUrl":"https://catalog.example.org/recipe/PKGBUILD"}],"nextCursor":null}`)), Header: make(http.Header)}, nil
	})
	if _, _, err := captureRecipeCatalog(context.Background(), client, plan[1], directory); err == nil {
		t.Fatal("accepted recipe from a different channel")
	}
	client.Transport = catalogFixtureTransport(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte{'{', '"', 'i', 't', 'e', 'm', 's', '"', ':', '[', 0xff})), Header: make(http.Header)}, nil
	})
	if _, _, err := captureRecipeCatalog(context.Background(), client, plan[1], directory); err == nil {
		t.Fatal("accepted invalid UTF-8 recipe catalog page")
	}
	var unsafe bytes.Buffer
	unsafeWriter := tar.NewWriter(&unsafe)
	if err := unsafeWriter.WriteHeader(&tar.Header{Name: "../", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := unsafeWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := parseCatalogTar(bytes.NewReader(unsafe.Bytes()), source); err == nil {
		t.Fatal("accepted unsafe catalog directory")
	}
	for _, address := range []string{"http://catalog.example.org/db", "https://localhost/db", "https://user:password@catalog.example.org/db", "https://catalog.example.org/db?token=secret", "https://catalog.example.org:8443/db"} {
		if catalogURL(address) == nil {
			t.Fatalf("accepted unsafe catalog URL %q", address)
		}
	}
	client.Transport = catalogFixtureTransport(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"items":[],"nextCursor":"repeat"}`)), Header: make(http.Header)}, nil
	})
	if _, _, err := captureRecipeCatalog(context.Background(), client, plan[1], directory); err == nil {
		t.Fatal("cyclic catalog cursor was accepted")
	}
}

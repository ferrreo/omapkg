package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadHTTPErrorPrefersJSONAndSanitizes(t *testing.T) {
	response := &http.Response{
		Status:     "503 Service Unavailable",
		StatusCode: http.StatusServiceUnavailable,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"error":"registry token=secret\nretry"}`)),
	}
	err := readHTTPError(response)
	if err == nil {
		t.Fatal("readHTTPError returned nil")
	}
	message := err.Error()
	if strings.Contains(message, "token=secret") || strings.ContainsAny(message, "\r\n\x00") {
		t.Fatalf("unsanitized API error: %q", message)
	}
	if !strings.Contains(message, "token=REDACTED retry") {
		t.Fatalf("JSON error message was not preserved: %q", message)
	}
}

func TestReadHTTPErrorUsesHTMLTitle(t *testing.T) {
	response := &http.Response{
		Status:     "503 Service Unavailable",
		StatusCode: http.StatusServiceUnavailable,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader("<!doctype html><html><head><title>Origin &amp; retry</title></head><body>large proxy page</body></html>")),
	}
	err := readHTTPError(response)
	if err == nil || !strings.Contains(err.Error(), "Origin & retry") || strings.Contains(err.Error(), "large proxy page") {
		t.Fatalf("HTML error was not reduced to title: %v", err)
	}
}

func TestCompactErrorBoundsAndRedactsFailureText(t *testing.T) {
	message := "password=secret " + strings.Repeat("x", maxErrorBytes+100)
	compact := compactErrorText(message)
	if len(compact) > maxErrorBytes || strings.Contains(compact, "password=secret") || strings.ContainsAny(compact, "\r\n\x00") {
		t.Fatalf("failure text was not safely compacted: len=%d text=%q", len(compact), compact)
	}
}

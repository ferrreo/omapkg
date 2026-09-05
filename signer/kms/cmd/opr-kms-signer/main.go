// Command opr-kms-signer exposes the KMS-backed OpenPGP signer to the private
// Cloudflare signer Worker. It never accepts a caller-supplied signature or
// artifact digest; it hashes the request body itself before signing.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"opr/signer/kms"
)

const defaultMaxArtifactBytes int64 = 4 * 1024 * 1024 * 1024

type server struct {
	backend          *kms.Backend
	publicKey        []byte
	fingerprint      string
	token            string
	name             string
	email            string
	spoolDir         string
	maxArtifactBytes int64
}

type signResponse struct {
	Mode             string `json:"mode"`
	ArtifactSha256   string `json:"artifactSha256"`
	ArtifactSize     int64  `json:"artifactSize"`
	SignatureBase64  string `json:"signatureBase64"`
	SignatureSha256  string `json:"signatureSha256"`
	PublicKeyArmored string `json:"publicKey"`
	Fingerprint      string `json:"fingerprint"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	region := requiredEnv("AWS_REGION")
	keyARN := requiredEnv("OPR_KMS_KEY_ARN")
	backend, err := kms.New(ctx, region, keyARN)
	if err != nil {
		slog.Error("initialize KMS signer", "error", err)
		os.Exit(1)
	}
	name := env("OPR_SIGNING_NAME", "omarpkg")
	email := env("OPR_SIGNING_EMAIL", "packages@example.com")
	publicKey, err := backend.PublicKeyArmor(ctx, name, email)
	if err != nil {
		slog.Error("create OpenPGP public certificate", "error", err)
		os.Exit(1)
	}
	fingerprintBytes, err := backend.Fingerprint()
	if err != nil {
		slog.Error("read OpenPGP fingerprint", "error", err)
		os.Exit(1)
	}
	maxBytes, err := positiveInt64(env("OPR_KMS_MAX_ARTIFACT_BYTES", strconv.FormatInt(defaultMaxArtifactBytes, 10)))
	if err != nil {
		slog.Error("invalid artifact size limit", "error", err)
		os.Exit(1)
	}
	token := requiredEnv("OPR_KMS_TOKEN")
	listen := env("OPR_KMS_LISTEN_ADDR", "127.0.0.1:8788")
	s := &server{
		backend: backend, publicKey: publicKey, fingerprint: hex.EncodeToString(fingerprintBytes),
		token: token, name: name, email: email, spoolDir: env("OPR_KMS_SPOOL_DIR", os.TempDir()),
		maxArtifactBytes: maxBytes,
	}
	httpServer := &http.Server{
		Addr: listen, Handler: s, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
	}
	slog.Info("KMS signer listening", "addr", listen, "keyFingerprint", s.fingerprint)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("KMS signer stopped", "error", err)
		os.Exit(1)
	}
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func requiredEnv(name string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		slog.Error("required environment variable is missing", "name", name)
		os.Exit(1)
	}
	return value
}

func positiveInt64(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, errors.New("must be a positive integer")
	}
	return parsed, nil
}

func (s *server) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/healthz":
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "managed-kms"})
	case request.Method == http.MethodGet && request.URL.Path == "/v1/public-key":
		if !s.authorized(request) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]string{
			"publicKey": string(s.publicKey), "fingerprint": s.fingerprint,
		})
	case request.Method == http.MethodPost && request.URL.Path == "/v1/sign":
		s.sign(w, request)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (s *server) authorized(request *http.Request) bool {
	header := request.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	left := sha256.Sum256([]byte(strings.TrimPrefix(header, "Bearer ")))
	right := sha256.Sum256([]byte(s.token))
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

func (s *server) sign(w http.ResponseWriter, request *http.Request) {
	if !s.authorized(request) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if request.ContentLength > s.maxArtifactBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "artifact is too large"})
		return
	}
	file, err := os.CreateTemp(s.spoolDir, "opr-kms-artifact-")
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "artifact spool is unavailable"})
		return
	}
	path := file.Name()
	defer func() {
		_ = file.Close()
		_ = os.Remove(path)
	}()

	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, digest), io.LimitReader(request.Body, s.maxArtifactBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "artifact upload failed"})
		return
	}
	if written <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "artifact is empty"})
		return
	}
	if written > s.maxArtifactBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "artifact is too large"})
		return
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "artifact spool is unavailable"})
		return
	}
	signature, err := s.backend.SignDetached(request.Context(), file)
	if err != nil {
		slog.Error("sign artifact", "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "KMS signing failed"})
		return
	}
	artifactDigest := hex.EncodeToString(digest.Sum(nil))
	signatureDigest := sha256.Sum256(signature)
	writeJSON(w, http.StatusOK, signResponse{
		Mode: "managed-kms", ArtifactSha256: artifactDigest, ArtifactSize: written,
		SignatureBase64: base64.StdEncoding.EncodeToString(signature), SignatureSha256: hex.EncodeToString(signatureDigest[:]),
		PublicKeyArmored: string(s.publicKey), Fingerprint: s.fingerprint,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

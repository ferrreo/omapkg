package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

const (
	maxRecipeBytes = 2 << 20
	maxLogChunk    = 16 << 10
	maxErrorBytes  = 4 << 10
)

var (
	sha256Pattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestPattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	idPattern            = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	archPattern          = regexp.MustCompile(`^(x86_64|aarch64)$`)
	namePattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+@%=-]{0,254}$`)
	depNamePattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9@._+-]{0,63}$`)
	archVersionPattern   = regexp.MustCompile(`^([0-9]+:)?[A-Za-z0-9][A-Za-z0-9@._+%~^:-]{0,127}$`)
	pkgverPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+%]{0,127}$`)
	workerVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	errorCredentialURL   = regexp.MustCompile(`(?i)https?://[^/\s:@]+:[^@\s]+@`)
	errorSecretField     = regexp.MustCompile(`(?i)\b(token|secret|password|signature|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+`)
	errorBearer          = regexp.MustCompile(`(?i)\bBearer\s+[^\s,;]+`)
)

type Config struct {
	Origin           string `json:"origin"`
	WorkerID         string `json:"workerId"`
	PrivateKey       string `json:"privateKey"`
	Image            string `json:"image,omitempty"`
	ImageDigest      string `json:"imageDigest"`
	Architecture     string `json:"architecture"`
	Runtime          string `json:"containerRuntime"`
	StateDir         string `json:"stateDir"`
	MaxSourceBytes   int64  `json:"maxSourceBytes,omitempty"`
	SourceTimeoutSec int    `json:"sourceTimeoutSeconds,omitempty"`
}

type Enrollment struct {
	Token        string `json:"token"`
	Name         string `json:"name"`
	Architecture string `json:"architecture"`
	PublicKey    string `json:"publicKey"`
	WorkerMetadata
}

// WorkerMetadata is sent on enrollment and signed control-plane requests so
// the coordinator can identify daemon versions and runtime capabilities. Keep
// this list fixed: capabilities describe code paths compiled into this
// daemon, not host supplied claims.
type WorkerMetadata struct {
	Version      string   `json:"version,omitempty"`
	Runtime      string   `json:"runtime,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

var supportedWorkerCapabilities = [...]string{
	"offline-oci",
	"multipart-upload",
	"registry-pull",
}

func daemonMetadata(runtime string) (WorkerMetadata, error) {
	if runtime != "podman" && runtime != "docker" {
		return WorkerMetadata{}, errors.New("runtime must be podman or docker")
	}
	if !workerVersionPattern.MatchString(workerVersion) {
		return WorkerMetadata{}, errors.New("worker version is invalid")
	}
	capabilities := make([]string, len(supportedWorkerCapabilities))
	copy(capabilities, supportedWorkerCapabilities[:])
	return WorkerMetadata{Version: workerVersion, Runtime: runtime, Capabilities: capabilities}, nil
}

type EnrollmentResponse struct {
	ID string `json:"id"`
}

type RegistryCredentials struct {
	Registry  string `json:"registry"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	ExpiresAt string `json:"expiresAt"`
}

type Source struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type DependencyPlan struct {
	Channel              string              `json:"channel"`
	PublicKeyURL         string              `json:"publicKeyUrl"`
	PublicKeyFingerprint string              `json:"publicKeyFingerprint"`
	Packages             []DependencyPackage `json:"packages"`
}

type DependencyPackage struct {
	ReleaseID       string `json:"releaseId"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Architecture    string `json:"architecture"`
	Filename        string `json:"filename"`
	URL             string `json:"url"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
	SignatureURL    string `json:"signatureUrl"`
	SignatureSHA256 string `json:"signatureSha256"`
}

type Job struct {
	ID                  string          `json:"id"`
	LeaseToken          string          `json:"leaseToken"`
	LeaseExpiresAt      string          `json:"leaseExpiresAt"`
	RevisionID          string          `json:"revisionId"`
	PackageName         string          `json:"packageName"`
	Version             string          `json:"version"`
	Pkgrel              int64           `json:"pkgrel,omitempty"`
	Architecture        string          `json:"architecture"`
	Recipe              string          `json:"recipe"`
	RecipeSHA256        string          `json:"recipeSha256"`
	SourceDateEpoch     int64           `json:"sourceDateEpoch"`
	ImageDigest         string          `json:"imageDigest"`
	ImageRef            string          `json:"imageRef,omitempty"`
	Sources             []Source        `json:"sources"`
	Dependencies        []string        `json:"dependencies"`
	RuntimeDependencies []string        `json:"runtimeDependencies,omitempty"`
	MakeDependencies    []string        `json:"makeDependencies,omitempty"`
	DependencyPlan      *DependencyPlan `json:"dependencyPlan,omitempty"`
	SmokeCommands       []string        `json:"smokeCommands"`
	Surface             string          `json:"surface"`
}

type ClaimResponse struct {
	Job *Job `json:"job"`
}

type HeartbeatRequest struct {
	LeaseToken string `json:"leaseToken"`
	WorkerMetadata
}

type HeartbeatResponse struct {
	LeaseExpiresAt string `json:"leaseExpiresAt"`
	Cancel         bool   `json:"cancel"`
}

type LogRequest struct {
	LeaseToken string `json:"leaseToken"`
	Sequence   int    `json:"sequence"`
	Text       string `json:"text"`
}

type Artifact struct {
	Key      string `json:"key"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Filename string `json:"filename"`
}

type ArtifactResponse struct {
	Key      string `json:"key"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Filename string `json:"filename"`
}

type UploadPart struct {
	PartNumber int    `json:"partNumber"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	ETag       string `json:"etag"`
}

type ProvenanceSource struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Provenance struct {
	BuildID         string             `json:"buildId"`
	RevisionID      string             `json:"revisionId"`
	WorkerID        string             `json:"workerId"`
	RecipeSHA256    string             `json:"recipeSha256"`
	Pkgrel          int64              `json:"pkgrel,omitempty"`
	InstalledSize   int64              `json:"installedSize"`
	PackageMetadata packageMetadata    `json:"packageMetadata"`
	DependencyPlan  *DependencyPlan    `json:"dependencyPlan,omitempty"`
	ArtifactSHA256  string             `json:"artifactSha256"`
	Architecture    string             `json:"architecture"`
	ImageDigest     string             `json:"imageDigest"`
	SourceDateEpoch int64              `json:"sourceDateEpoch"`
	Sources         []ProvenanceSource `json:"sources"`
	Network         string             `json:"network"`
	StartedAt       string             `json:"startedAt"`
	FinishedAt      string             `json:"finishedAt"`
}

type CompleteRequest struct {
	LeaseToken          string    `json:"leaseToken"`
	Status              string    `json:"status"`
	Error               string    `json:"error,omitempty"`
	Artifact            *Artifact `json:"artifact,omitempty"`
	Provenance          string    `json:"provenance,omitempty"`
	ProvenanceSignature string    `json:"provenanceSignature,omitempty"`
	InstalledSize       *int64    `json:"installedSize,omitempty"`
	SmokePassed         bool      `json:"smokePassed"`
}

type fetchedSource struct {
	Source
	Path string
}

func decodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key has %d bytes, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

func encodePrivateKey(key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

func generateKey() (ed25519.PrivateKey, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate worker key: %w", err)
	}
	return private, nil
}

func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hashFile(filename string) (string, int64, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", n, fmt.Errorf("hash %s: %w", filename, err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func validateConfig(cfg Config) error {
	if err := validateOrigin(cfg.Origin); err != nil {
		return err
	}
	if !idPattern.MatchString(cfg.WorkerID) {
		return errors.New("workerId must be a safe identifier")
	}
	if !archPattern.MatchString(cfg.Architecture) {
		return errors.New("architecture must be x86_64 or aarch64")
	}
	if cfg.ImageDigest != "" && !digestPattern.MatchString(cfg.ImageDigest) {
		return errors.New("imageDigest must be sha256:<64 lowercase hex characters>")
	}
	if (cfg.Image == "") != (cfg.ImageDigest == "") {
		return errors.New("image and imageDigest must be provided together")
	}
	if cfg.Image != "" {
		if err := validateImageReference(cfg.Image, cfg.ImageDigest); err != nil {
			return fmt.Errorf("image: %w", err)
		}
	}
	if cfg.Runtime != "podman" && cfg.Runtime != "docker" {
		return errors.New("containerRuntime must be podman or docker")
	}
	if cfg.StateDir == "" {
		return errors.New("stateDir is required")
	}
	if _, err := decodePrivateKey(cfg.PrivateKey); err != nil {
		return err
	}
	if cfg.MaxSourceBytes < 0 {
		return errors.New("maxSourceBytes cannot be negative")
	}
	if cfg.SourceTimeoutSec < 0 {
		return errors.New("sourceTimeoutSeconds cannot be negative")
	}
	return nil
}

func validateOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("origin must be an absolute URL without credentials")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return errors.New("origin must use HTTPS (HTTP is allowed only for loopback tests)")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validArchVersion(value string) bool {
	if !archVersionPattern.MatchString(value) {
		return false
	}
	colon := strings.IndexByte(value, ':')
	if colon < 0 {
		return true
	}
	if colon == 0 || strings.Contains(value[colon+1:], ":") {
		return false
	}
	for _, character := range value[:colon] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validArchDependency(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	for _, operator := range []string{">=", "<=", "=", ">", "<"} {
		if index := strings.Index(value, operator); index >= 0 {
			return depNamePattern.MatchString(value[:index]) && validArchVersion(value[index+len(operator):])
		}
	}
	return depNamePattern.MatchString(value)
}

func validateJob(job Job, cfg Config) error {
	if !idPattern.MatchString(job.ID) || job.LeaseToken == "" || job.RevisionID == "" {
		return errors.New("job has invalid identity or lease")
	}
	if !archPattern.MatchString(job.Architecture) || job.Architecture != cfg.Architecture {
		return errors.New("job architecture does not match worker")
	}
	if !namePattern.MatchString(job.PackageName) || !pkgverPattern.MatchString(job.Version) {
		return errors.New("job package name and Arch pkgver are invalid; pkgrel is separate")
	}
	if job.Pkgrel != 0 && (job.Pkgrel < 1 || job.Pkgrel > 9999) {
		return errors.New("job pkgrel must be between 1 and 9999")
	}
	if len(job.Recipe) == 0 || len(job.Recipe) > maxRecipeBytes || strings.IndexByte(job.Recipe, 0) >= 0 {
		return errors.New("recipe is empty, too large, or contains NUL")
	}
	if job.SourceDateEpoch < 0 {
		return errors.New("sourceDateEpoch cannot be negative")
	}
	if !sha256Pattern.MatchString(job.RecipeSHA256) || hashBytes([]byte(job.Recipe)) != job.RecipeSHA256 {
		return errors.New("recipe SHA256 does not match")
	}
	if !digestPattern.MatchString(job.ImageDigest) {
		return errors.New("job image digest is invalid")
	}
	if job.ImageRef == "" && cfg.ImageDigest != "" && job.ImageDigest != cfg.ImageDigest {
		return errors.New("job image digest does not match legacy worker image")
	}
	if _, err := imageReferenceForJob(job, cfg); err != nil {
		return err
	}
	if job.Surface != "binary" && job.Surface != "recipe" {
		return errors.New("job surface must be binary or recipe")
	}
	if len(job.Sources) == 0 {
		return errors.New("job must contain at least one source")
	}
	seen := make(map[string]struct{}, len(job.Sources))
	for _, source := range job.Sources {
		if !namePattern.MatchString(source.Name) || source.Name == "." || source.Name == ".." {
			return fmt.Errorf("unsafe source name %q", source.Name)
		}
		if _, ok := seen[source.Name]; ok {
			return fmt.Errorf("duplicate source name %q", source.Name)
		}
		seen[source.Name] = struct{}{}
		if err := validateSourceURL(source.URL); err != nil {
			return fmt.Errorf("source %q: %w", source.Name, err)
		}
		if !sha256Pattern.MatchString(source.SHA256) {
			return fmt.Errorf("source %q has invalid SHA256", source.Name)
		}
	}
	allDependencies := append(append(append([]string{}, job.Dependencies...), job.RuntimeDependencies...), job.MakeDependencies...)
	for _, dependency := range allDependencies {
		if !validArchDependency(dependency) {
			return fmt.Errorf("unsafe dependency %q", dependency)
		}
	}
	if err := validateDependencyPlan(job.DependencyPlan, job, cfg.Origin); err != nil {
		return err
	}
	for _, command := range job.SmokeCommands {
		if command == "" || len(command) > 8192 || strings.IndexByte(command, 0) >= 0 {
			return errors.New("smoke command is empty, too large, or contains NUL")
		}
	}
	if _, err := time.Parse(time.RFC3339, job.LeaseExpiresAt); err != nil {
		return fmt.Errorf("invalid lease expiry: %w", err)
	}
	return nil
}

func validateSourceURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("source URL must be HTTPS and contain no credentials")
	}
	if strings.EqualFold(u.Hostname(), "localhost") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".localhost") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".local") || strings.HasSuffix(strings.ToLower(u.Hostname()), ".internal") {
		return errors.New("source URL resolves to a local hostname")
	}
	return nil
}

func validateImageReference(ref, digest string) error {
	if len(ref) > 1024 || ref == "" || strings.ContainsAny(ref, "\x00\r\n\t ?#\\,;") || strings.HasPrefix(ref, "-") {
		return errors.New("image reference contains unsafe characters")
	}
	if !digestPattern.MatchString(digest) || !strings.HasSuffix(ref, "@"+digest) {
		return errors.New("image reference must include its pinned image digest")
	}
	if strings.TrimSuffix(ref, "@"+digest) == "" {
		return errors.New("image reference name is empty")
	}
	return nil
}

func imageReferenceForJob(job Job, cfg Config) (string, error) {
	if !digestPattern.MatchString(job.ImageDigest) {
		return "", errors.New("job image digest is invalid")
	}
	if job.ImageRef != "" {
		if err := validateImageReference(job.ImageRef, job.ImageDigest); err != nil {
			return "", fmt.Errorf("job image: %w", err)
		}
		return job.ImageRef, nil
	}
	if cfg.Image == "" {
		return "", errors.New("job imageRef is required when no legacy worker image is configured")
	}
	if cfg.ImageDigest != job.ImageDigest {
		return "", errors.New("job image digest does not match legacy worker image")
	}
	if err := validateImageReference(cfg.Image, job.ImageDigest); err != nil {
		return "", fmt.Errorf("legacy worker image: %w", err)
	}
	return cfg.Image, nil
}

func validateArtifactFilename(filename string) error {
	if len(filename) > 128 || !namePattern.MatchString(filename) || path.Base(filename) != filename || !strings.HasSuffix(filename, ".pkg.tar.zst") {
		return errors.New("artifact filename must be a safe .pkg.tar.zst basename")
	}
	return nil
}

func makeSignaturePayload(method, requestPath, timestamp, nonce, bodyHash string) []byte {
	return []byte(strings.Join([]string{method, requestPath, timestamp, nonce, bodyHash}, "\n"))
}

func randomNonce() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", fmt.Errorf("generate request nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func canonicalRequestPath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}

func parseLeaseExpiry(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return t, nil
}

func decodeJSON(r io.Reader, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(r, 2<<20))
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}

func encodeJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func compactError(err error) string {
	if err == nil {
		return ""
	}
	return compactErrorText(err.Error())
}

func compactErrorText(message string) string {
	message = errorCredentialURL.ReplaceAllString(message, "https://REDACTED@")
	message = errorSecretField.ReplaceAllString(message, "$1=REDACTED")
	message = errorBearer.ReplaceAllString(message, "Bearer REDACTED")
	message = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, message)
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > maxErrorBytes {
		message = message[:maxErrorBytes]
	}
	return strings.TrimSpace(message)
}

func provenanceFor(job Job, workerID, artifactSHA string, installedSize int64, metadata packageMetadata, started, finished string) (string, error) {
	if metadata.InstalledSize != installedSize {
		return "", errors.New("package metadata installed size does not match provenance")
	}
	sources := make([]ProvenanceSource, len(job.Sources))
	for i, source := range job.Sources {
		sources[i] = ProvenanceSource{Name: source.Name, URL: source.URL, SHA256: source.SHA256}
	}
	value := Provenance{
		BuildID:         job.ID,
		RevisionID:      job.RevisionID,
		WorkerID:        workerID,
		RecipeSHA256:    job.RecipeSHA256,
		Pkgrel:          job.Pkgrel,
		InstalledSize:   installedSize,
		PackageMetadata: metadata,
		DependencyPlan:  job.DependencyPlan,
		ArtifactSHA256:  artifactSHA,
		Architecture:    job.Architecture,
		ImageDigest:     job.ImageDigest,
		SourceDateEpoch: job.SourceDateEpoch,
		Sources:         sources,
		Network:         "disabled",
		StartedAt:       started,
		FinishedAt:      finished,
	}
	b, err := encodeJSON(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func signProvenance(provenance string, key ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, []byte(provenance)))
}

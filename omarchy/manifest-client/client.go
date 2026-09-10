package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	maxManifestBytes  = 4 << 20
	maxSignatureBytes = 2 << 20
	maxKeyBytes       = 2 << 20
	maxPlanBytes      = 2 << 20
	clockSkew         = 5 * time.Minute
)

var (
	sha256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	namePattern        = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	fingerprintPattern = regexp.MustCompile(`^[A-Fa-f0-9]{16,64}$`)
	channelPattern     = regexp.MustCompile(`^(stable|rc|edge)$`)
)

type Options struct {
	HTTP                 *http.Client
	TrustedKey           string
	TrustedFingerprint   string
	AllowHTTP            bool
	Architecture         string
	ManifestSignatureURL string
	ExpectedChannel      string
	DiscoveryOrigin      string
	Now                  func() time.Time
}

type Client struct {
	http             *http.Client
	key              string
	fingerprint      string
	allowHTTP        bool
	now              func() time.Time
	architecture     string
	rootSignatureURL string
	expectedChannel  string
	discoveryOrigin  string
}

type LocalState struct {
	SchemaVersion        int                     `json:"schemaVersion"`
	ManifestSHA256       string                  `json:"manifestSha256"`
	ReleaseID            string                  `json:"releaseId"`
	SystemVersion        string                  `json:"systemVersion"`
	OPRGeneration        string                  `json:"oprGeneration"`
	SystemManifestSHA256 string                  `json:"systemManifestSha256"`
	OPRManifestSHA256    string                  `json:"oprManifestSha256"`
	Architecture         string                  `json:"architecture"`
	Sequence             uint64                  `json:"sequence"`
	SystemSequence       uint64                  `json:"systemSequence"`
	OPRSequence          uint64                  `json:"oprSequence"`
	AppliedAt            int64                   `json:"appliedAt"`
	ConfigSHA256         string                  `json:"configSha256"`
	RecoveryTarget       string                  `json:"recoveryTarget,omitempty"`
	RecoveryLimits       string                  `json:"recoveryLimits,omitempty"`
	Channel              string                  `json:"channel,omitempty"`
	Channels             map[string]ChannelState `json:"channels,omitempty"`
}

type ChannelState struct {
	ManifestSHA256       string `json:"manifestSha256"`
	ReleaseID            string `json:"releaseId"`
	SystemVersion        string `json:"systemVersion"`
	OPRGeneration        string `json:"oprGeneration"`
	SystemManifestSHA256 string `json:"systemManifestSha256"`
	OPRManifestSHA256    string `json:"oprManifestSha256"`
	Architecture         string `json:"architecture"`
	Sequence             uint64 `json:"sequence"`
	SystemSequence       uint64 `json:"systemSequence"`
	OPRSequence          uint64 `json:"oprSequence"`
	AppliedAt            int64  `json:"appliedAt"`
	ConfigSHA256         string `json:"configSha256"`
	RecoveryTarget       string `json:"recoveryTarget,omitempty"`
	RecoveryLimits       string `json:"recoveryLimits,omitempty"`
}

func stateForChannel(state LocalState, channel string) LocalState {
	if channel != "" && state.Channels != nil {
		if selected, ok := state.Channels[channel]; ok {
			return localStateFromChannel(selected)
		}
	}
	if state.Channel == channel || (state.Channel == "" && channel == "stable") {
		return state
	}
	return LocalState{}
}

func channelStateFromLocal(state LocalState) ChannelState {
	return ChannelState{ManifestSHA256: state.ManifestSHA256, ReleaseID: state.ReleaseID, SystemVersion: state.SystemVersion, OPRGeneration: state.OPRGeneration,
		SystemManifestSHA256: state.SystemManifestSHA256, OPRManifestSHA256: state.OPRManifestSHA256, Architecture: state.Architecture,
		Sequence: state.Sequence, SystemSequence: state.SystemSequence, OPRSequence: state.OPRSequence, AppliedAt: state.AppliedAt,
		ConfigSHA256: state.ConfigSHA256, RecoveryTarget: state.RecoveryTarget, RecoveryLimits: state.RecoveryLimits}
}

func localStateFromChannel(state ChannelState) LocalState {
	return LocalState{SchemaVersion: 1, ManifestSHA256: state.ManifestSHA256, ReleaseID: state.ReleaseID, SystemVersion: state.SystemVersion, OPRGeneration: state.OPRGeneration,
		SystemManifestSHA256: state.SystemManifestSHA256, OPRManifestSHA256: state.OPRManifestSHA256, Architecture: state.Architecture,
		Sequence: state.Sequence, SystemSequence: state.SystemSequence, OPRSequence: state.OPRSequence, AppliedAt: state.AppliedAt,
		ConfigSHA256: state.ConfigSHA256, RecoveryTarget: state.RecoveryTarget, RecoveryLimits: state.RecoveryLimits}
}

func saveChannelState(state *LocalState, channel string, selected LocalState) {
	if state.Channels == nil {
		state.Channels = map[string]ChannelState{}
	}
	state.Channels[channel] = channelStateFromLocal(selected)
	state.Channel = channel
	state.SchemaVersion = selected.SchemaVersion
	state.ManifestSHA256 = selected.ManifestSHA256
	state.ReleaseID = selected.ReleaseID
	state.SystemVersion = selected.SystemVersion
	state.OPRGeneration = selected.OPRGeneration
	state.SystemManifestSHA256 = selected.SystemManifestSHA256
	state.OPRManifestSHA256 = selected.OPRManifestSHA256
	state.Architecture = selected.Architecture
	state.Sequence = selected.Sequence
	state.SystemSequence = selected.SystemSequence
	state.OPRSequence = selected.OPRSequence
	state.AppliedAt = selected.AppliedAt
	state.ConfigSHA256 = selected.ConfigSHA256
	state.RecoveryTarget = selected.RecoveryTarget
	state.RecoveryLimits = selected.RecoveryLimits
}

type Transaction struct {
	SchemaVersion int
	Kind          string
	Lane          string
	Channel       string
	ReleaseID     string
	Architecture  string
	Architectures []string
	Identity      Identity
	Parent        Parent
	CreatedAt     int64
	ExpiresAt     int64
	Sequence      uint64
	Repositories  []Repository
	Compatibility Compatibility
	Recovery      Recovery
	SystemRef     ManifestRef
	OPRRef        ManifestRef
	RollbackRef   *ManifestRef
	PackageChunks []packageChunk
	PackageCount  int
	Digest        string
	Raw           []byte
}

type Identity struct {
	Version    string
	Generation string
}

type Parent struct {
	Digest   string
	Sequence uint64
}

type ManifestRef struct {
	URL          string
	Digest       string
	SignatureURL string
	Channel      string
	Sequence     uint64
	Version      string
	Generation   string
}

type Repository struct {
	Name           string
	Architecture   string
	SnapshotDigest string
	DBURL          string
	SignatureURL   string
	PackageBaseURL string
}

type Compatibility struct {
	SystemManifestDigest  string
	SystemSnapshotDigests []string
	OPRManifestDigest     string
	OPRSnapshotDigest     string
}

type Recovery struct {
	FromDigest  string
	Target      *ManifestRef
	Authorized  bool
	Reason      string
	Constraints []string
}

type signatureInfo struct {
	URL    string
	SHA256 string
}

type signedDocument struct {
	Raw       []byte
	Canonical []byte
	Digest    string
}

type packageChunk struct {
	URL          string
	Digest       string
	Size         int64
	Index        int
	Count        int
	PackageCount int
}

type rawManifest struct {
	Object       map[string]any
	Document     signedDocument
	Signature    []byte
	SignatureURL string
}

type discoveryReference struct {
	ManifestURL  string
	SignatureURL string
}

func New(options Options) (*Client, error) {
	if options.TrustedKey == "" || options.TrustedFingerprint == "" {
		return nil, errors.New("trusted OpenPGP key and fingerprint are required")
	}
	if !fingerprintPattern.MatchString(options.TrustedFingerprint) {
		return nil, errors.New("trusted OpenPGP fingerprint is invalid")
	}
	keyInfo, err := os.Stat(options.TrustedKey)
	if err != nil || !keyInfo.Mode().IsRegular() {
		return nil, errors.New("trusted OpenPGP key is not a regular file")
	}
	if keyInfo.Size() <= 0 || keyInfo.Size() > maxKeyBytes {
		return nil, errors.New("trusted OpenPGP key is empty or too large")
	}
	httpClient := options.HTTP
	if httpClient == nil {
		httpClient = &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	} else {
		copy := *httpClient
		copy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
		httpClient = &copy
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	architecture := options.Architecture
	if architecture == "" {
		switch runtime.GOARCH {
		case "amd64":
			architecture = "x86_64"
		case "arm64":
			architecture = "aarch64"
		default:
			return nil, fmt.Errorf("unsupported client architecture %q", runtime.GOARCH)
		}
	}
	if architecture != "x86_64" && architecture != "aarch64" {
		return nil, errors.New("client architecture must be x86_64 or aarch64")
	}
	if options.ExpectedChannel != "" && !channelPattern.MatchString(options.ExpectedChannel) {
		return nil, errors.New("expected channel must be stable, rc, or edge")
	}
	discoveryOrigin := strings.TrimRight(options.DiscoveryOrigin, "/")
	if discoveryOrigin != "" {
		if err := validateDiscoveryURL(discoveryOrigin+"/repo/channels/stable/manifest.json", options.AllowHTTP); err != nil {
			return nil, fmt.Errorf("discovery origin is invalid: %w", err)
		}
	}
	return &Client{http: httpClient, key: options.TrustedKey, fingerprint: strings.ToUpper(options.TrustedFingerprint), allowHTTP: options.AllowHTTP, architecture: architecture, rootSignatureURL: options.ManifestSignatureURL, expectedChannel: options.ExpectedChannel, discoveryOrigin: discoveryOrigin, now: now}, nil
}

func (c *Client) Resolve(ctx context.Context, manifestURL string) (Transaction, error) {
	return c.resolveAt(ctx, manifestURL, c.rootSignatureURL)
}

func (c *Client) resolveAt(ctx context.Context, manifestURL, signatureURL string) (Transaction, error) {
	root, err := c.fetchSignedAt(ctx, manifestURL, signatureURL, maxManifestBytes)
	if err != nil {
		return Transaction{}, err
	}
	tx, err := parseTransaction(root)
	if err != nil {
		return Transaction{}, err
	}
	tx.Raw = root.Document.Canonical
	tx.Digest = root.Document.Digest
	if c.expectedChannel != "" && tx.Channel != c.expectedChannel {
		return Transaction{}, fmt.Errorf("manifest channel %q does not match expected channel %q", tx.Channel, c.expectedChannel)
	}
	if err := selectArchitecture(c.architecture, &tx); err != nil {
		return Transaction{}, err
	}
	if err := c.validateTransactionURL(manifestURL, tx); err != nil {
		return Transaction{}, err
	}
	if tx.SystemRef.URL == "" || tx.OPRRef.URL == "" {
		return Transaction{}, errors.New("resolved transaction must reference signed system and OPR manifests")
	}
	system, err := c.fetchReference(ctx, tx.SystemRef, "system")
	if err != nil {
		return Transaction{}, err
	}
	opr, err := c.fetchReference(ctx, tx.OPRRef, "opr")
	if err != nil {
		return Transaction{}, err
	}
	if err := validateChild(tx, system, opr); err != nil {
		return Transaction{}, err
	}
	if tx.RollbackRef != nil {
		rollback, err := c.fetchReferenceAny(ctx, *tx.RollbackRef)
		if err != nil {
			return Transaction{}, err
		}
		if err := validateRecoveryTarget(tx, rollback, *tx.RollbackRef, c.architecture); err != nil {
			return Transaction{}, err
		}
	}
	if err := c.validateTimes(tx); err != nil {
		return Transaction{}, err
	}
	return tx, nil
}

// ResolveRequested accepts either an immutable manifest URL or a channel
// discovery URL. Discovery is allowed to move, but the returned URL must be
// an immutable manifest before signature verification starts.
func (c *Client) ResolveRequested(ctx context.Context, manifestURL, discoveryURL string) (Transaction, error) {
	ref, err := c.resolveRequestedRef(ctx, manifestURL, discoveryURL)
	if err != nil {
		return Transaction{}, err
	}
	return c.resolveAt(ctx, ref.ManifestURL, ref.SignatureURL)
}

func (c *Client) resolveRequestedRef(ctx context.Context, manifestURL, discoveryURL string) (discoveryReference, error) {
	target := manifestURL
	if target == "" {
		target = discoveryURL
	}
	if target == "" && c.discoveryOrigin != "" {
		if c.expectedChannel == "" {
			return discoveryReference{}, errors.New("channel is required for origin discovery")
		}
		paths := []string{c.discoveryOrigin + "/repo/channels/" + c.expectedChannel + "/manifest.json", c.discoveryOrigin + "/repo/channels/" + c.expectedChannel + "/transaction.json", c.discoveryOrigin + "/repo/transactions/" + c.expectedChannel + "/manifest.json", c.discoveryOrigin + "/repo/transactions/" + c.expectedChannel + "/transaction.json", c.discoveryOrigin + "/repo/transactions/" + c.expectedChannel + "/current/manifest.json", c.discoveryOrigin + "/repo/transactions/current/manifest.json"}
		var last error
		for _, candidate := range paths {
			ref, err := c.discoverReference(ctx, candidate)
			if err == nil {
				return ref, nil
			}
			last = err
		}
		if last != nil {
			return discoveryReference{}, fmt.Errorf("channel discovery failed: %w", last)
		}
	}
	if target == "" {
		return discoveryReference{}, errors.New("an immutable manifest or channel discovery URL is required")
	}
	if mutableURL(target) {
		return c.discoverReference(ctx, target)
	}
	if err := validateURL(target, c.allowHTTP); err != nil {
		return discoveryReference{}, err
	}
	return discoveryReference{ManifestURL: target, SignatureURL: c.rootSignatureURL}, nil
}

func (c *Client) discoverReference(ctx context.Context, discoveryURL string) (discoveryReference, error) {
	if err := validateDiscoveryURL(discoveryURL, c.allowHTTP); err != nil {
		return discoveryReference{}, err
	}
	base, err := url.Parse(discoveryURL)
	if err != nil {
		return discoveryReference{}, err
	}
	var finalURL string
	discoveryClient := *c.http
	discoveryClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errors.New("channel discovery redirected too many times")
		}
		if err := validateDiscoveryURL(request.URL.String(), c.allowHTTP); err != nil {
			return err
		}
		if err := validateSameOrigin(discoveryURL, request.URL.String()); err != nil {
			return err
		}
		finalURL = request.URL.String()
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return discoveryReference{}, err
	}
	response, err := discoveryClient.Do(request)
	if err != nil {
		return discoveryReference{}, err
	}
	defer response.Body.Close()
	if finalURL != "" {
		if mutableURL(finalURL) {
			return discoveryReference{}, errors.New("channel discovery did not resolve to an immutable manifest")
		}
		return discoveryReference{ManifestURL: finalURL}, nil
	}
	if response.StatusCode != http.StatusOK {
		return discoveryReference{}, fmt.Errorf("channel discovery returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxManifestBytes+1))
	if err != nil || int64(len(body)) > maxManifestBytes {
		return discoveryReference{}, errors.New("channel discovery response is too large")
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return discoveryReference{}, errors.New("channel discovery response is invalid JSON")
	}
	if channel, ok := stringField(object, "channel"); ok && c.expectedChannel != "" && channel != c.expectedChannel {
		return discoveryReference{}, fmt.Errorf("discovery channel %q does not match expected channel %q", channel, c.expectedChannel)
	}
	if target, ok := stringField(object, "manifestUrl"); ok {
		if err := validateSameOrigin(discoveryURL, target); err != nil {
			return discoveryReference{}, err
		}
		if mutableURL(target) {
			return discoveryReference{}, errors.New("discovery manifest URL is mutable")
		}
		signature, _ := stringField(object, "signatureUrl")
		return discoveryReference{ManifestURL: target, SignatureURL: signature}, nil
	}
	if target, ok := stringField(object, "manifestURL"); ok {
		if err := validateSameOrigin(discoveryURL, target); err != nil {
			return discoveryReference{}, err
		}
		if mutableURL(target) {
			return discoveryReference{}, errors.New("discovery manifest URL is mutable")
		}
		signature, _ := stringField(object, "signatureURL")
		return discoveryReference{ManifestURL: target, SignatureURL: signature}, nil
	}
	releaseID, releaseOK := stringField(object, "releaseId")
	kind, kindOK := stringField(object, "kind")
	if !releaseOK || !kindOK || kind != "resolved-transaction" || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(releaseID) {
		return discoveryReference{}, errors.New("discovery response has no immutable transaction reference")
	}
	if c.expectedChannel != "" {
		channel, _ := stringField(object, "channel")
		if channel != c.expectedChannel {
			return discoveryReference{}, fmt.Errorf("discovery channel %q does not match expected channel %q", channel, c.expectedChannel)
		}
	}
	channel, _ := stringField(object, "channel")
	if channel == "" {
		channel = c.expectedChannel
	}
	if !channelPattern.MatchString(channel) {
		return discoveryReference{}, errors.New("discovery response has no valid transaction channel")
	}
	target := fmt.Sprintf("%s://%s/repo/transactions/%s/%s/manifest.json", base.Scheme, base.Host, channel, url.PathEscape(releaseID))
	if mutableURL(target) {
		return discoveryReference{}, errors.New("derived discovery URL is mutable")
	}
	return discoveryReference{ManifestURL: target}, nil
}

func (c *Client) fetchReference(ctx context.Context, ref ManifestRef, expectedKind string) (rawManifest, error) {
	if ref.URL == "" || !sha256Pattern.MatchString(ref.Digest) {
		return rawManifest{}, fmt.Errorf("%s manifest reference is incomplete", expectedKind)
	}
	doc, err := c.fetchSignedAt(ctx, ref.URL, ref.SignatureURL, maxManifestBytes)
	if err != nil {
		return rawManifest{}, fmt.Errorf("verify %s manifest: %w", expectedKind, err)
	}
	if doc.Document.Digest != strings.ToLower(ref.Digest) {
		return rawManifest{}, fmt.Errorf("%s manifest digest does not match resolved transaction", expectedKind)
	}
	kind, _ := stringField(doc.Object, "kind")
	if kind != expectedKind && !(expectedKind == "rollback-control" && kind == "rollback") {
		return rawManifest{}, fmt.Errorf("expected %s manifest, got %q", expectedKind, kind)
	}
	if created, ok := int64Field(doc.Object, "createdAt"); !ok || c.now().Before(time.Unix(created, 0).Add(-clockSkew)) {
		return rawManifest{}, fmt.Errorf("%s manifest is dated in the future or missing creation time", expectedKind)
	}
	if expires, ok := int64Field(doc.Object, "expiresAt"); !ok || expires <= 0 || c.now().Unix() >= expires {
		return rawManifest{}, fmt.Errorf("%s manifest is expired or missing expiry", expectedKind)
	}
	if err := validateManifestObject(doc.Object, expectedKind, c.architecture); err != nil {
		return rawManifest{}, err
	}
	if ref.Channel != "" {
		channel, _ := stringField(doc.Object, "channel")
		if channel != ref.Channel {
			return rawManifest{}, fmt.Errorf("%s manifest channel differs from reference", expectedKind)
		}
	}
	return doc, nil
}

func (c *Client) fetchReferenceAny(ctx context.Context, ref ManifestRef) (rawManifest, error) {
	if ref.URL == "" || !sha256Pattern.MatchString(ref.Digest) {
		return rawManifest{}, errors.New("recovery target reference is incomplete")
	}
	doc, err := c.fetchSignedAt(ctx, ref.URL, ref.SignatureURL, maxManifestBytes)
	if err != nil {
		return rawManifest{}, fmt.Errorf("verify recovery target: %w", err)
	}
	if doc.Document.Digest != strings.ToLower(ref.Digest) {
		return rawManifest{}, errors.New("recovery target digest does not match reference")
	}
	kind, _ := stringField(doc.Object, "kind")
	if kind != "system" && kind != "opr" && kind != "resolved-transaction" {
		return rawManifest{}, fmt.Errorf("invalid recovery target kind %q", kind)
	}
	if created, ok := int64Field(doc.Object, "createdAt"); !ok || c.now().Before(time.Unix(created, 0).Add(-clockSkew)) {
		return rawManifest{}, errors.New("recovery target is dated in the future or missing creation time")
	}
	if expires, ok := int64Field(doc.Object, "expiresAt"); !ok || expires <= 0 || c.now().Unix() >= expires {
		return rawManifest{}, errors.New("recovery target is expired or missing expiry")
	}
	return doc, nil
}

func validateManifestObject(object map[string]any, expectedKind, architecture string) error {
	if numberField(object, "schemaVersion") != 1 {
		return errors.New("referenced manifest schema version is unsupported")
	}
	lane, _ := stringField(object, "lane")
	if lane != expectedKind {
		return fmt.Errorf("%s manifest lane is invalid", expectedKind)
	}
	channel, _ := stringField(object, "channel")
	if expectedKind == "system" && !channelPattern.MatchString(channel) {
		return errors.New("system manifest channel is invalid")
	}
	if expectedKind == "opr" && channel != "stable" && channel != "quarantine" {
		return errors.New("OPR manifest channel is invalid")
	}
	architectures := stringSlicePreserve(object, "architectures")
	found := false
	for _, value := range architectures {
		if value == architecture {
			found = true
		}
		if value != "x86_64" && value != "aarch64" {
			return errors.New("referenced manifest architecture is invalid")
		}
	}
	if !found {
		return fmt.Errorf("%s manifest does not support architecture %s", expectedKind, architecture)
	}
	policy, policyOK := objectField(object, "policy")
	version, versionOK := stringField(policy, "version")
	if !policyOK || numberField(policy, "schemaVersion") != 1 || !versionOK || version != "distribution-release-v1" {
		return errors.New("referenced manifest policy is unsupported")
	}
	changelog, changelogOK := objectField(object, "changelog")
	changelogDigest, digestOK := stringField(changelog, "sha256")
	approvedBy, approvedOK := stringField(changelog, "approvedBy")
	if !changelogOK || !digestOK || !sha256Pattern.MatchString(changelogDigest) || !approvedOK || approvedBy == "" {
		return errors.New("referenced manifest changelog approval is incomplete")
	}
	if err := validateCohortDigests(changelog); err != nil {
		return fmt.Errorf("referenced manifest %w", err)
	}
	if _, ok := object["packageChunks"].([]any); !ok {
		return errors.New("referenced manifest package chunks are missing")
	}
	if _, ok := numberFieldOK(object, "packageCount"); !ok {
		return errors.New("referenced manifest package count is missing")
	}
	return nil
}

func validateCohortDigests(changelog map[string]any) error {
	values, ok := changelog["cohortDigests"].([]any)
	if !ok {
		return errors.New("cohort changelog digests are missing")
	}
	seen := map[string]bool{}
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("cohort changelog digest is invalid")
		}
		cohortID, ok := stringField(object, "cohortId")
		if !ok || cohortID == "" || seen[cohortID] {
			return errors.New("cohort changelog identity is invalid")
		}
		seen[cohortID] = true
		revision, ok := numberFieldOK(object, "revision")
		if !ok || revision < 1 {
			return errors.New("cohort changelog revision is invalid")
		}
		digest, ok := stringField(object, "digest")
		if !ok || !sha256Pattern.MatchString(digest) {
			return errors.New("cohort changelog digest is invalid")
		}
	}
	return nil
}

func (c *Client) fetchSignedAt(ctx context.Context, documentURL, expectedSignatureURL string, limit int64) (rawManifest, error) {
	if mutableURL(documentURL) {
		return rawManifest{}, errors.New("signed manifest URL is a mutable channel pointer")
	}
	if err := validateURL(documentURL, c.allowHTTP); err != nil {
		return rawManifest{}, err
	}
	raw, err := c.fetch(ctx, documentURL, limit)
	if err != nil {
		return rawManifest{}, err
	}
	canonical, object, err := canonicalDocument(raw)
	if err != nil {
		return rawManifest{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return rawManifest{}, errors.New("signed manifest is not canonical JSON")
	}
	info, err := signatureInfoFromObject(object, documentURL)
	if err != nil {
		return rawManifest{}, err
	}
	if expectedSignatureURL != "" {
		if mutableURL(expectedSignatureURL) {
			return rawManifest{}, errors.New("manifest signature URL is mutable")
		}
		if err := validateURL(expectedSignatureURL, c.allowHTTP); err != nil {
			return rawManifest{}, err
		}
		if err := validateSameOrigin(documentURL, expectedSignatureURL); err != nil {
			return rawManifest{}, err
		}
		info.URL = expectedSignatureURL
	}
	sig, err := c.fetch(ctx, info.URL, maxSignatureBytes)
	if err != nil {
		return rawManifest{}, fmt.Errorf("fetch manifest signature: %w", err)
	}
	if info.SHA256 != "" && sha256Hex(sig) != strings.ToLower(info.SHA256) {
		return rawManifest{}, errors.New("manifest signature digest mismatch")
	}
	if err := verifyOpenPGP(c.key, c.fingerprint, canonical, sig); err != nil {
		return rawManifest{}, err
	}
	return rawManifest{Object: object, Document: signedDocument{Raw: raw, Canonical: canonical, Digest: sha256Hex(canonical)}, Signature: sig, SignatureURL: info.URL}, nil
}

func (c *Client) fetch(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	if err := validateURL(rawURL, c.allowHTTP); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned HTTP %d", rawURL, response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("GET %s exceeds size limit", rawURL)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GET %s exceeds size limit", rawURL)
	}
	return data, nil
}

func canonicalDocument(raw []byte) ([]byte, map[string]any, error) {
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return nil, nil, fmt.Errorf("manifest JSON is invalid: %w", err)
	}
	if object == nil {
		return nil, nil, errors.New("manifest must be a JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, nil, errors.New("manifest contains trailing JSON")
	}
	canonical, err := canonicalMarshal(object)
	if err != nil {
		return nil, nil, err
	}
	return canonical, object, nil
}

func canonicalMarshal(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}

func verifyOpenPGP(keyPath, fingerprint string, message, signature []byte) error {
	tmp, err := os.MkdirTemp("", "omarchy-gpg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	home := filepath.Join(tmp, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		return err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	keyFile := filepath.Join(tmp, "trusted-key.asc")
	messageFile := filepath.Join(tmp, "manifest.json")
	signatureFile := filepath.Join(tmp, "manifest.sig")
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(messageFile, message, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(signatureFile, signature, 0o600); err != nil {
		return err
	}
	if output, err := runCommand(context.Background(), "gpg", "--batch", "--no-tty", "--homedir", home, "--import", keyFile); err != nil {
		return fmt.Errorf("import trusted OpenPGP key: %w (%s)", err, strings.TrimSpace(output))
	}
	output, err := runCommand(context.Background(), "gpg", "--batch", "--no-tty", "--homedir", home, "--status-fd", "1", "--verify", signatureFile, messageFile)
	if err != nil {
		return fmt.Errorf("manifest OpenPGP signature is invalid: %w", err)
	}
	found := ""
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "[GNUPG:] REVKEYSIG ") || strings.HasPrefix(line, "[GNUPG:] EXPKEYSIG ") || strings.HasPrefix(line, "[GNUPG:] EXPSIG ") || strings.HasPrefix(line, "[GNUPG:] BADSIG ") {
			return errors.New("manifest OpenPGP signature uses a revoked, expired, or bad key")
		}
		if !strings.HasPrefix(line, "[GNUPG:] VALIDSIG ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			return errors.New("manifest OpenPGP signature has incomplete VALIDSIG status")
		}
		if found != "" {
			return errors.New("manifest OpenPGP signature contains multiple valid signatures")
		}
		found = strings.ToUpper(fields[2])
	}
	if found == "" || found != strings.ToUpper(fingerprint) {
		return errors.New("manifest OpenPGP signature fingerprint is not the pinned key")
	}
	return nil
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func validateURL(raw string, allowHTTP bool) error {
	return validateURLMode(raw, allowHTTP, true)
}

func validateDiscoveryURL(raw string, allowHTTP bool) error {
	return validateURLMode(raw, allowHTTP, false)
}

func validateURLMode(raw string, allowHTTP, rejectMutable bool) error {
	if strings.ContainsAny(raw, "\x00\r\n\t ") {
		return fmt.Errorf("unsafe immutable URL %q", raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("unsafe immutable URL %q", raw)
	}
	if parsed.Scheme != "https" && !(allowHTTP && parsed.Scheme == "http") {
		return fmt.Errorf("URL must use HTTPS: %q", raw)
	}
	escapedPath := strings.ToLower(parsed.EscapedPath())
	if parsed.Path == "" || strings.Contains(parsed.Path, "//") || strings.Contains(parsed.Path, "\\") || strings.Contains(escapedPath, "%2e") || strings.Contains(escapedPath, "%2f") || strings.Contains(escapedPath, "%5c") {
		return fmt.Errorf("immutable URL has unsafe path: %q", raw)
	}
	for _, component := range strings.Split(parsed.Path, "/") {
		if component == "." || component == ".." || component == "$arch" {
			return fmt.Errorf("immutable URL contains mutable path component: %q", raw)
		}
		if rejectMutable && (component == "latest" || component == "current" || component == "channels" || component == "channel" || component == "dev" || component == "quarantine") {
			return fmt.Errorf("immutable URL contains mutable path component: %q", raw)
		}
	}
	return nil
}

func mutableURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return true
	}
	components := strings.Split(parsed.Path, "/")
	for index, component := range components {
		if component != "transactions" && component != "releases" && component != "opr" {
			continue
		}
		if index+1 < len(components) && (components[index+1] == "stable" || components[index+1] == "edge" || components[index+1] == "rc" || components[index+1] == "quarantine") {
			// `/repo/{lane}/{channel}/manifest.json` is a moving pointer;
			// immutable leaves include release ID between channel and filename.
			if index+3 >= len(components) || components[index+2] == "manifest.json" || strings.HasSuffix(components[index+2], ".json") {
				return true
			}
		}
	}
	for _, component := range components {
		if component == "latest" || component == "current" || component == "channels" || component == "channel" || component == "dev" || component == "quarantine" {
			return true
		}
	}
	for index, component := range components {
		if (component == "stable" || component == "edge" || component == "rc") && (index == 0 || components[index-1] != "releases" && components[index-1] != "opr" && components[index-1] != "transactions") {
			return true
		}
	}
	return false
}

func validateSameOrigin(base, candidate string) error {
	left, err := url.Parse(base)
	if err != nil {
		return err
	}
	right, err := url.Parse(candidate)
	if err != nil {
		return err
	}
	if left.Scheme != right.Scheme || !strings.EqualFold(left.Host, right.Host) {
		return fmt.Errorf("URL %q is outside manifest origin", candidate)
	}
	return nil
}

func (c *Client) validateTransactionURL(manifestURL string, tx Transaction) error {
	if err := validateURL(manifestURL, c.allowHTTP); err != nil {
		return err
	}
	for _, ref := range []ManifestRef{tx.SystemRef, tx.OPRRef} {
		if err := validateSameOrigin(manifestURL, ref.URL); err != nil {
			return err
		}
		if ref.SignatureURL != "" {
			if err := validateSameOrigin(manifestURL, ref.SignatureURL); err != nil {
				return err
			}
		}
	}
	if tx.RollbackRef != nil {
		if err := validateSameOrigin(manifestURL, tx.RollbackRef.URL); err != nil {
			return err
		}
		if tx.RollbackRef.SignatureURL != "" {
			if err := validateSameOrigin(manifestURL, tx.RollbackRef.SignatureURL); err != nil {
				return err
			}
		}
	}
	for _, repo := range tx.Repositories {
		if err := validateRepositoryURL(manifestURL, tx, repo); err != nil {
			return err
		}
	}
	for _, chunk := range tx.PackageChunks {
		if mutableURL(chunk.URL) {
			return errors.New("package chunk URL is mutable")
		}
		if err := validateURL(chunk.URL, strings.HasPrefix(manifestURL, "http://")); err != nil {
			return err
		}
		if err := validateSameOrigin(manifestURL, chunk.URL); err != nil {
			return err
		}
	}
	return nil
}

func validateRepositoryURL(manifestURL string, tx Transaction, repo Repository) error {
	if !namePattern.MatchString(repo.Name) || repo.Architecture != tx.Architecture || !sha256Pattern.MatchString(repo.SnapshotDigest) {
		return fmt.Errorf("repository %q has invalid identity or snapshot digest", repo.Name)
	}
	if repo.DBURL == "" || repo.SignatureURL == "" || repo.PackageBaseURL == "" {
		return fmt.Errorf("repository %q is missing immutable public URLs", repo.Name)
	}
	for _, candidate := range []string{repo.DBURL, repo.SignatureURL, repo.PackageBaseURL} {
		if mutableURL(candidate) {
			return fmt.Errorf("repository %q URL is mutable", repo.Name)
		}
		if err := validateURL(candidate, strings.HasPrefix(manifestURL, "http://")); err != nil {
			return err
		}
		if err := validateSameOrigin(manifestURL, candidate); err != nil {
			return err
		}
	}
	db, _ := url.Parse(repo.DBURL)
	sig, _ := url.Parse(repo.SignatureURL)
	base, _ := url.Parse(repo.PackageBaseURL)
	if !strings.HasSuffix(db.Path, ".db") && !strings.HasSuffix(db.Path, ".db.tar.gz") && !strings.HasSuffix(db.Path, ".db.tar.zst") {
		return fmt.Errorf("repository %q database URL is not an Arch database", repo.Name)
	}
	if sig.Path != db.Path+".sig" || path.Dir(db.Path) != strings.TrimSuffix(base.Path, "/") {
		return fmt.Errorf("repository %q database/signature/base URLs do not match", repo.Name)
	}
	return nil
}

func parseTransaction(raw rawManifest) (Transaction, error) {
	o := raw.Object
	if numberField(o, "schemaVersion") != 1 {
		return Transaction{}, errors.New("unsupported manifest schema version")
	}
	kind, ok := stringField(o, "kind")
	if !ok || kind != "resolved-transaction" {
		return Transaction{}, errors.New("manifest is not a resolved transaction")
	}
	tx := Transaction{SchemaVersion: 1, Kind: kind}
	tx.Lane, _ = stringField(o, "lane")
	tx.Channel, _ = stringField(o, "channel")
	tx.ReleaseID, _ = stringField(o, "releaseId")
	tx.Architecture, _ = stringField(o, "architecture")
	tx.Architectures = stringSlicePreserve(o, "architectures")
	if len(tx.Architectures) == 0 && tx.Architecture != "" {
		tx.Architectures = []string{tx.Architecture}
	}
	tx.CreatedAt, _ = int64Field(o, "createdAt")
	tx.ExpiresAt, _ = int64Field(o, "expiresAt")
	tx.Sequence, _ = uint64Field(o, "sequence")
	if identity, ok := objectField(o, "identity"); ok {
		tx.Identity.Version, _ = stringField(identity, "version")
		tx.Identity.Generation, _ = stringField(identity, "generation")
	}
	if parent, ok := objectField(o, "parent"); ok {
		tx.Parent.Digest, _ = stringField(parent, "digest")
		tx.Parent.Sequence, _ = uint64Field(parent, "sequence")
	}
	if compatibility, ok := objectField(o, "compatibility"); ok {
		tx.Compatibility.SystemManifestDigest, _ = stringField(compatibility, "systemManifestDigest")
		tx.Compatibility.OPRManifestDigest, _ = stringField(compatibility, "oprManifestDigest")
		tx.Compatibility.OPRSnapshotDigest, _ = stringField(compatibility, "oprSnapshotDigest")
		tx.Compatibility.SystemSnapshotDigests = stringSliceField(compatibility, "systemSnapshotDigests")
	}
	if recovery, ok := objectField(o, "recovery"); ok {
		tx.Recovery.FromDigest, _ = stringField(recovery, "fromDigest")
		tx.Recovery.Reason, _ = stringField(recovery, "reason")
		tx.Recovery.Authorized, _ = boolField(recovery, "authorized")
		tx.Recovery.Constraints = stringSlicePreserve(recovery, "constraints")
		if target, ok := objectField(recovery, "target"); ok {
			parsed := parseManifestRef(target)
			tx.Recovery.Target = &parsed
			tx.RollbackRef = &parsed
		}
	}
	if rollback, ok := objectField(o, "rollbackControl"); ok {
		parsed := parseManifestRef(rollback)
		tx.RollbackRef = &parsed
	}
	if system, ok := objectField(o, "systemManifest"); ok {
		tx.SystemRef = parseManifestRef(system)
	} else if system, ok := objectField(o, "system"); ok {
		tx.SystemRef = parseManifestRef(system)
	}
	if opr, ok := objectField(o, "oprManifest"); ok {
		tx.OPRRef = parseManifestRef(opr)
	} else if opr, ok := objectField(o, "opr"); ok {
		tx.OPRRef = parseManifestRef(opr)
	}
	repositories, ok := o["repositories"].([]any)
	if !ok || len(repositories) == 0 {
		return Transaction{}, errors.New("resolved transaction has no repositories")
	}
	seen := map[string]bool{}
	for _, value := range repositories {
		object, ok := value.(map[string]any)
		if !ok {
			return Transaction{}, errors.New("repository entry is not an object")
		}
		repo := Repository{}
		repo.Name, _ = stringField(object, "name")
		repo.Architecture, _ = stringField(object, "architecture")
		repo.SnapshotDigest, _ = stringField(object, "snapshotDigest")
		repo.DBURL, _ = stringField(object, "dbUrl")
		if repo.DBURL == "" {
			repo.DBURL, _ = stringField(object, "dbURL")
		}
		repo.SignatureURL, _ = stringField(object, "signatureUrl")
		if repo.SignatureURL == "" {
			repo.SignatureURL, _ = stringField(object, "signatureURL")
		}
		repo.PackageBaseURL, _ = stringField(object, "packageBaseUrl")
		if repo.PackageBaseURL == "" {
			repo.PackageBaseURL, _ = stringField(object, "packageBaseURL")
		}
		if seen[repo.Name] {
			return Transaction{}, fmt.Errorf("duplicate repository %q", repo.Name)
		}
		seen[repo.Name] = true
		tx.Repositories = append(tx.Repositories, repo)
	}
	chunksValue, chunksPresent := o["packageChunks"]
	chunks, chunksArray := chunksValue.([]any)
	if chunksPresent && !chunksArray {
		return Transaction{}, errors.New("manifest package chunk index is invalid")
	}
	if chunksArray {
		for _, value := range chunks {
			object, ok := value.(map[string]any)
			if !ok {
				return Transaction{}, errors.New("package chunk entry is not an object")
			}
			chunk := packageChunk{}
			chunk.URL, _ = stringField(object, "url")
			chunk.Digest, _ = stringField(object, "sha256")
			chunk.Size, _ = int64Field(object, "size")
			chunk.Index, _ = numberFieldOK(object, "index")
			chunk.Count, _ = numberFieldOK(object, "count")
			chunk.PackageCount, _ = numberFieldOK(object, "packageCount")
			tx.PackageChunks = append(tx.PackageChunks, chunk)
		}
	}
	var packageCountOK bool
	tx.PackageCount, packageCountOK = numberFieldOK(o, "packageCount")
	if !chunksPresent || !packageCountOK {
		return Transaction{}, errors.New("manifest package chunk index is missing")
	}
	policy, policyOK := objectField(o, "policy")
	policyVersion, versionOK := stringField(policy, "version")
	if !policyOK || numberField(policy, "schemaVersion") != 1 || !versionOK || policyVersion != "distribution-release-v1" {
		return Transaction{}, errors.New("manifest policy is unsupported")
	}
	changelog, changelogOK := objectField(o, "changelog")
	changelogDigest, digestOK := stringField(changelog, "sha256")
	approvedBy, approvedOK := stringField(changelog, "approvedBy")
	if !changelogOK || !digestOK || !sha256Pattern.MatchString(changelogDigest) || !approvedOK || approvedBy == "" {
		return Transaction{}, errors.New("manifest changelog approval is incomplete")
	}
	if err := validateCohortDigests(changelog); err != nil {
		return Transaction{}, err
	}
	if err := validateTransactionFields(tx, raw.Document.Digest); err != nil {
		return Transaction{}, err
	}
	return tx, nil
}

func selectArchitecture(target string, tx *Transaction) error {
	found := false
	for _, architecture := range tx.Architectures {
		if architecture == target {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("signed transaction does not support architecture %s", target)
	}
	tx.Architecture = target
	filtered := tx.Repositories[:0]
	for _, repository := range tx.Repositories {
		if repository.Architecture == target {
			filtered = append(filtered, repository)
		}
	}
	if len(filtered) == 0 {
		return fmt.Errorf("signed transaction has no repositories for architecture %s", target)
	}
	tx.Repositories = filtered
	return nil
}

func parseManifestRef(object map[string]any) ManifestRef {
	ref := ManifestRef{}
	ref.URL, _ = stringField(object, "url")
	if ref.URL == "" {
		ref.URL, _ = stringField(object, "manifestUrl")
	}
	if ref.URL == "" {
		ref.URL, _ = stringField(object, "manifestURL")
	}
	ref.Digest, _ = stringField(object, "digest")
	if ref.Digest == "" {
		ref.Digest, _ = stringField(object, "manifestSha256")
	}
	ref.SignatureURL, _ = stringField(object, "signatureUrl")
	if ref.SignatureURL == "" {
		ref.SignatureURL, _ = stringField(object, "signatureURL")
	}
	ref.Channel, _ = stringField(object, "channel")
	ref.Sequence, _ = uint64Field(object, "sequence")
	ref.Version, _ = stringField(object, "version")
	ref.Generation, _ = stringField(object, "generation")
	return ref
}

func signatureInfoFromObject(object map[string]any, documentURL string) (signatureInfo, error) {
	info := signatureInfo{}
	info.URL, _ = stringField(object, "signatureUrl")
	if info.URL == "" {
		info.URL, _ = stringField(object, "signatureURL")
	}
	if signature, ok := objectField(object, "signature"); ok {
		if info.URL == "" {
			info.URL, _ = stringField(signature, "url")
		}
		info.SHA256, _ = stringField(signature, "sha256")
	}
	if info.URL == "" {
		info.URL = documentURL + ".sig"
	}
	if info.SHA256 == "" {
		info.SHA256, _ = stringField(object, "signatureSha256")
	}
	if info.SHA256 != "" && !sha256Pattern.MatchString(strings.ToLower(info.SHA256)) {
		return signatureInfo{}, errors.New("manifest signature digest is invalid")
	}
	if err := validateURL(info.URL, strings.HasPrefix(documentURL, "http://")); err != nil {
		return signatureInfo{}, err
	}
	if err := validateSameOrigin(documentURL, info.URL); err != nil {
		return signatureInfo{}, err
	}
	return info, nil
}

func validateTransactionFields(tx Transaction, digest string) error {
	if tx.ReleaseID == "" || len(tx.Architectures) == 0 {
		return errors.New("manifest release or architecture is invalid")
	}
	for _, architecture := range tx.Architectures {
		if architecture != "x86_64" && architecture != "aarch64" {
			return errors.New("manifest architecture is invalid")
		}
	}
	if tx.CreatedAt <= 0 || tx.ExpiresAt <= tx.CreatedAt || tx.Sequence == 0 {
		return errors.New("manifest time or sequence fields are invalid")
	}
	if !sha256Pattern.MatchString(digest) || (tx.Parent.Digest != "" && !sha256Pattern.MatchString(tx.Parent.Digest)) {
		return errors.New("manifest digest fields are invalid")
	}
	if tx.Lane != "transaction" {
		return errors.New("resolved transaction lane is invalid")
	}
	if !channelPattern.MatchString(tx.Channel) {
		return errors.New("resolved transaction channel is invalid")
	}
	if tx.SystemRef.URL == "" || tx.SystemRef.SignatureURL == "" || tx.SystemRef.Channel == "" || tx.OPRRef.URL == "" || tx.OPRRef.SignatureURL == "" || tx.OPRRef.Channel == "" || tx.SystemRef.Sequence == 0 || tx.OPRRef.Sequence == 0 || !sha256Pattern.MatchString(tx.SystemRef.Digest) || !sha256Pattern.MatchString(tx.OPRRef.Digest) {
		return errors.New("system and OPR manifest references are incomplete")
	}
	if tx.Recovery.Authorized && len(tx.Recovery.Constraints) == 0 {
		return errors.New("authorized recovery constraints are missing")
	}
	if tx.PackageCount < 0 {
		return errors.New("manifest package count is invalid")
	}
	for _, chunk := range tx.PackageChunks {
		if chunk.URL == "" || !sha256Pattern.MatchString(chunk.Digest) || chunk.Size <= 0 || chunk.Index < 0 || chunk.Count <= 0 || chunk.Index >= chunk.Count || chunk.PackageCount < 0 {
			return errors.New("manifest package chunk is invalid")
		}
	}
	return nil
}

func (c *Client) validateTimes(tx Transaction) error {
	now := c.now()
	if now.Before(time.Unix(tx.CreatedAt, 0).Add(-clockSkew)) {
		return errors.New("manifest is dated in the future")
	}
	if !now.Before(time.Unix(tx.ExpiresAt, 0)) {
		return errors.New("manifest has expired")
	}
	return nil
}

func validateChild(tx Transaction, system, opr rawManifest) error {
	if kind, _ := stringField(system.Object, "kind"); kind != "system" {
		return errors.New("system reference is not a system manifest")
	}
	if kind, _ := stringField(opr.Object, "kind"); kind != "opr" {
		return errors.New("OPR reference is not an OPR manifest")
	}
	systemChannel, _ := stringField(system.Object, "channel")
	if systemChannel != tx.Channel || tx.SystemRef.Channel != tx.Channel {
		return errors.New("system manifest channel is incompatible with transaction")
	}
	oprChannel, _ := stringField(opr.Object, "channel")
	if (oprChannel != "stable" && !(tx.Channel != "stable" && oprChannel == "quarantine")) || tx.OPRRef.Channel != oprChannel {
		return errors.New("OPR manifest is not in stable channel")
	}
	if sequence, ok := uint64Field(system.Object, "sequence"); !ok || sequence != tx.SystemRef.Sequence {
		return errors.New("system manifest sequence is incompatible with transaction")
	}
	if sequence, ok := uint64Field(opr.Object, "sequence"); !ok || sequence != tx.OPRRef.Sequence {
		return errors.New("OPR manifest sequence is incompatible with transaction")
	}
	systemVersion, _ := stringField(system.Object, "version")
	if systemVersion == "" {
		if identity, ok := objectField(system.Object, "identity"); ok {
			systemVersion, _ = stringField(identity, "version")
		}
	}
	if tx.Identity.Version != "" && systemVersion != tx.Identity.Version {
		return errors.New("system manifest version is incompatible with transaction")
	}
	oprGeneration, _ := stringField(opr.Object, "generation")
	if oprGeneration == "" {
		if identity, ok := objectField(opr.Object, "identity"); ok {
			oprGeneration, _ = stringField(identity, "generation")
		}
	}
	if tx.Identity.Generation != "" && oprGeneration != tx.Identity.Generation {
		return errors.New("OPR manifest generation is incompatible with transaction")
	}
	if tx.Compatibility.SystemManifestDigest != "" && tx.Compatibility.SystemManifestDigest != tx.SystemRef.Digest {
		return errors.New("system compatibility digest mismatch")
	}
	if tx.Compatibility.OPRManifestDigest != "" && tx.Compatibility.OPRManifestDigest != tx.OPRRef.Digest {
		return errors.New("OPR compatibility digest mismatch")
	}
	return nil
}

func validateRecoveryTarget(tx Transaction, raw rawManifest, ref ManifestRef, architecture string) error {
	if ref.Sequence == 0 || !tx.Recovery.Authorized || tx.Recovery.Reason == "" {
		return errors.New("recovery authorization is incomplete")
	}
	kind, _ := stringField(raw.Object, "kind")
	if kind != "resolved-transaction" {
		return errors.New("recovery target must be a resolved transaction")
	}
	target, err := parseTransaction(raw)
	if err != nil {
		return fmt.Errorf("parse recovery target: %w", err)
	}
	if err := selectArchitecture(architecture, &target); err != nil {
		return err
	}
	if ref.Channel != "" && target.Channel != ref.Channel {
		return errors.New("recovery target channel differs from reference")
	}
	if target.SystemRef.Digest != tx.SystemRef.Digest || target.OPRRef.Digest != tx.OPRRef.Digest || len(target.Repositories) != len(tx.Repositories) {
		return errors.New("recovery target does not match selected system/OPR snapshots")
	}
	if target.PackageCount != tx.PackageCount || len(target.PackageChunks) != len(tx.PackageChunks) {
		return errors.New("recovery target package set differs from transaction")
	}
	for index := range tx.Repositories {
		left, right := tx.Repositories[index], target.Repositories[index]
		if left.Name != right.Name || left.SnapshotDigest != right.SnapshotDigest || left.DBURL != right.DBURL || left.SignatureURL != right.SignatureURL || left.PackageBaseURL != right.PackageBaseURL {
			return errors.New("recovery target repository set differs from transaction")
		}
	}
	for index := range tx.PackageChunks {
		left, right := tx.PackageChunks[index], target.PackageChunks[index]
		if left.URL != right.URL || left.Digest != right.Digest || left.Size != right.Size || left.Index != right.Index || left.Count != right.Count || left.PackageCount != right.PackageCount {
			return errors.New("recovery target package chunks differ from transaction")
		}
	}
	return nil
}

func validateFreshness(state LocalState, tx Transaction, rollbackAuthorized bool) error {
	if state.SchemaVersion == 0 {
		return nil
	}
	if state.Architecture != tx.Architecture {
		return errors.New("manifest architecture differs from local state")
	}
	if tx.Sequence <= state.Sequence {
		return errors.New("manifest sequence is not newer than local high-water mark")
	}
	if tx.SystemRef.Sequence < state.SystemSequence && (state.SystemManifestSHA256 == "" || tx.SystemRef.Digest != state.SystemManifestSHA256) && !rollbackAuthorized {
		return errors.New("system manifest sequence moved backwards without signed rollback control")
	}
	if tx.SystemRef.Sequence == state.SystemSequence && state.SystemManifestSHA256 != "" && tx.SystemRef.Digest != state.SystemManifestSHA256 && !rollbackAuthorized {
		return errors.New("system sequence was reused for different bytes")
	}
	if tx.OPRRef.Sequence < state.OPRSequence && (state.OPRManifestSHA256 == "" || tx.OPRRef.Digest != state.OPRManifestSHA256) && !rollbackAuthorized {
		return errors.New("OPR manifest sequence moved backwards without signed rollback control")
	}
	if tx.OPRRef.Sequence == state.OPRSequence && state.OPRManifestSHA256 != "" && tx.OPRRef.Digest != state.OPRManifestSHA256 && !rollbackAuthorized {
		return errors.New("OPR sequence was reused for different bytes")
	}
	if state.SystemVersion != "" && compareSystemVersion(tx.Identity.Version, state.SystemVersion) < 0 && !rollbackAuthorized {
		return errors.New("unsafe system downgrade blocked")
	}
	return nil
}

func compareSystemVersion(left, right string) int {
	parse := func(value string) []int {
		value = strings.SplitN(value, "-", 2)[0]
		parts := strings.Split(value, ".")
		result := make([]int, 3)
		for index := 0; index < len(parts) && index < 3; index++ {
			fmt.Sscanf(parts[index], "%d", &result[index])
		}
		return result
	}
	a, b := parse(left), parse(right)
	for index := range a {
		if a[index] < b[index] {
			return -1
		}
		if a[index] > b[index] {
			return 1
		}
	}
	return strings.Compare(left, right)
}

func numberField(object map[string]any, key string) int {
	value, ok := object[key].(json.Number)
	if !ok {
		return 0
	}
	var result int
	fmt.Sscan(value.String(), &result)
	return result
}

func numberFieldOK(object map[string]any, key string) (int, bool) {
	value, ok := object[key].(json.Number)
	if !ok {
		return 0, false
	}
	var result int
	if _, err := fmt.Sscan(value.String(), &result); err != nil {
		return 0, false
	}
	return result, true
}

func int64Field(object map[string]any, key string) (int64, bool) {
	value, ok := object[key].(json.Number)
	if !ok {
		return 0, false
	}
	result, err := value.Int64()
	return result, err == nil
}

func uint64Field(object map[string]any, key string) (uint64, bool) {
	value, ok := object[key].(json.Number)
	if !ok {
		return 0, false
	}
	result, err := strconvParseUint(value.String())
	return result, err == nil
}

func strconvParseUint(value string) (uint64, error) {
	var result uint64
	if value == "" {
		return 0, errors.New("empty number")
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return 0, errors.New("invalid number")
		}
		if result > (^uint64(0)-uint64(character-'0'))/10 {
			return 0, errors.New("number overflow")
		}
		result = result*10 + uint64(character-'0')
	}
	return result, nil
}

func stringField(object map[string]any, key string) (string, bool) {
	value, ok := object[key].(string)
	return value, ok
}

func boolField(object map[string]any, key string) (bool, bool) {
	value, ok := object[key].(bool)
	return value, ok
}

func objectField(object map[string]any, key string) (map[string]any, bool) {
	value, ok := object[key].(map[string]any)
	return value, ok
}

func stringSliceField(object map[string]any, key string) []string {
	result := stringSlicePreserve(object, key)
	sort.Strings(result)
	return result
}

func stringSlicePreserve(object map[string]any, key string) []string {
	values, ok := object[key].([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

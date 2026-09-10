package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type signedFixture struct {
	server      *httptest.Server
	client      *Client
	manifestURL string
	keyPath     string
	fingerprint string
	files       map[string][]byte
}

func TestCanonicalJSONAndConfigPreservation(t *testing.T) {
	raw := []byte(`{"z":1,"a":[true,null,"x"]}`)
	canonical, _, err := canonicalDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != `{"a":[true,null,"x"],"z":1}` {
		t.Fatalf("unexpected canonical bytes: %s", canonical)
	}
	if _, _, err := canonicalDocument(append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	base := []byte("# keep this\n[options]\nArchitecture = auto\n\n[core]\nInclude = /etc/mirrorlist\nSigLevel = Required\n[extra]\nServer = https://old.invalid\n")
	repositories := []Repository{
		{Name: "core", Architecture: "x86_64", SnapshotDigest: strings.Repeat("a", 64), DBURL: "https://repo.invalid/releases/4.0.3/core/x86_64/core.db", SignatureURL: "https://repo.invalid/releases/4.0.3/core/x86_64/core.db.sig", PackageBaseURL: "https://repo.invalid/releases/4.0.3/core/x86_64"},
		{Name: "extra", Architecture: "x86_64", SnapshotDigest: strings.Repeat("b", 64), DBURL: "https://repo.invalid/releases/4.0.3/extra/x86_64/extra.db", SignatureURL: "https://repo.invalid/releases/4.0.3/extra/x86_64/extra.db.sig", PackageBaseURL: "https://repo.invalid/releases/4.0.3/extra/x86_64"},
	}
	updated, err := rewriteConfig(base, repositories)
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	for _, expected := range []string{"# keep this", "Architecture = auto", "SigLevel = Required", "Server = https://repo.invalid/releases/4.0.3/core/x86_64", "Server = https://repo.invalid/releases/4.0.3/extra/x86_64"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("config lost %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "Include = /etc/mirrorlist") {
		t.Fatal("owned mirror include survived")
	}
}

func TestConfigRejectsUnmanagedRepositoryFallback(t *testing.T) {
	base := []byte("[options]\n\n[core]\nServer = https://old.invalid\n[alarm]\nServer = https://archlinuxarm.org/$arch/$repo\n")
	repositories := []Repository{{Name: "core", Architecture: "x86_64", SnapshotDigest: strings.Repeat("a", 64), DBURL: "https://repo.invalid/releases/4.0.3/core/x86_64/core.db", SignatureURL: "https://repo.invalid/releases/4.0.3/core/x86_64/core.db.sig", PackageBaseURL: "https://repo.invalid/releases/4.0.3/core/x86_64"}}
	_, err := rewriteConfig(base, repositories)
	if err == nil || !strings.Contains(err.Error(), "AUR/ALARM/live upstream fallback") {
		t.Fatalf("unmanaged repository was not blocked: %v", err)
	}
}

func TestResolveAuthenticatesAllSignedInputs(t *testing.T) {
	fixture := newFixture(t)
	defer fixture.server.Close()
	tx, err := fixture.client.Resolve(context.Background(), fixture.manifestURL)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Digest == "" || tx.Architecture != "x86_64" || len(tx.Repositories) != 2 {
		t.Fatalf("unexpected transaction: %+v", tx)
	}
	if tx.SystemRef.Digest == tx.OPRRef.Digest {
		t.Fatal("system and OPR manifests unexpectedly share digest")
	}
}

func TestChannelDiscoveryUsesImmutableReference(t *testing.T) {
	fixture := newFixture(t)
	defer fixture.server.Close()
	fixture.files["/final.sig"] = fixture.files["/transaction.json.sig"]
	fixture.files["/repo/channels/stable"] = []byte(`{"channel":"stable","manifestUrl":"` + fixture.manifestURL + `","signatureUrl":"` + fixture.server.URL + `/final.sig"}`)
	tx, err := fixture.client.ResolveRequested(context.Background(), "", fixture.server.URL+"/repo/channels/stable")
	if err != nil {
		t.Fatal(err)
	}
	if tx.Channel != "stable" {
		t.Fatalf("unexpected channel: %s", tx.Channel)
	}
}

func TestOriginDiscoveryFindsCurrentPointerWithoutPinnedReleaseURL(t *testing.T) {
	fixture := newFixture(t)
	defer fixture.server.Close()
	fixture.files["/repo/transactions/current/manifest.json"] = fixture.files["/transaction.json"]
	fixture.files["/repo/transactions/stable/tx-4.0.3-1/manifest.json"] = fixture.files["/transaction.json"]
	fixture.files["/repo/transactions/stable/tx-4.0.3-1/manifest.json.sig"] = fixture.files["/transaction.json.sig"]
	client, err := New(Options{HTTP: fixture.server.Client(), TrustedKey: fixture.keyPath, TrustedFingerprint: fixture.fingerprint, Architecture: "x86_64", ExpectedChannel: "stable", DiscoveryOrigin: fixture.server.URL, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := client.ResolveRequested(context.Background(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if tx.Channel != "stable" {
		t.Fatalf("unexpected discovered channel: %s", tx.Channel)
	}
}

func TestStageAndApplyUsesFakePacmanOnly(t *testing.T) {
	fixture := newFixture(t)
	defer fixture.server.Close()
	directory := t.TempDir()
	configPath := filepath.Join(directory, "pacman.conf")
	statePath := filepath.Join(directory, "state.json")
	stagePath := filepath.Join(directory, "stage")
	if err := os.WriteFile(configPath, []byte("[options]\nArchitecture = auto\n\n[core]\nInclude = /etc/mirrorlist\n[extra]\nServer = https://old.invalid\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "pacman.log")
	pacmanPath := filepath.Join(directory, "fake-pacman")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> %q\ncase \"$*\" in *--print*) echo 'core 1.0 -> 1.1';; esac\n", logPath)
	if err := os.WriteFile(pacmanPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	options := TransactionOptions{ManifestURL: fixture.manifestURL, ConfigPath: configPath, StatePath: statePath, StageDir: stagePath, Pacman: pacmanPath}
	tx, plan, err := fixture.client.Stage(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan, "core 1.0 -> 1.1") || tx.Digest == "" {
		t.Fatalf("missing review plan: %s", plan)
	}
	if _, err := fixture.client.Apply(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	state, err := readState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.ManifestSHA256 != tx.Digest || state.Sequence != tx.Sequence {
		t.Fatalf("state not committed: %+v", state)
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(config, []byte("Server = "+fixture.server.URL+"/repo/releases/4.0.3/core/x86_64")) {
		t.Fatalf("managed config not installed: %s", config)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(log), "--sync --sysupgrade") != 2 {
		t.Fatalf("fake pacman was not previewed and applied once: %s", log)
	}
}

func TestFreshnessBlocksReplayAndUnsafeDowngrade(t *testing.T) {
	state := LocalState{SchemaVersion: 1, ManifestSHA256: strings.Repeat("a", 64), Architecture: "x86_64", Sequence: 9, SystemSequence: 9, OPRSequence: 9, SystemVersion: "4.0.3"}
	tx := Transaction{Digest: strings.Repeat("b", 64), Architecture: "x86_64", Sequence: 9, SystemRef: ManifestRef{Sequence: 9}, OPRRef: ManifestRef{Sequence: 9}, Identity: Identity{Version: "4.0.3"}}
	if err := validateFreshness(state, tx, false); err == nil {
		t.Fatal("replayed sequence accepted")
	}
	tx.Sequence = 10
	tx.SystemRef.Sequence = 8
	if err := validateFreshness(state, tx, false); err == nil {
		t.Fatal("unsafe system rollback accepted")
	}
	tx.Recovery = Recovery{FromDigest: state.ManifestSHA256, Authorized: true, Reason: "security recovery", Target: &ManifestRef{Digest: strings.Repeat("c", 64), Sequence: 1}}
	if err := validateFreshness(state, tx, true); err != nil {
		t.Fatalf("authorized recovery rejected: %v", err)
	}
	state.SystemManifestSHA256 = strings.Repeat("s", 64)
	state.OPRManifestSHA256 = strings.Repeat("d", 64)
	tx.SystemRef.Sequence = 1
	tx.SystemRef.Digest = state.SystemManifestSHA256
	tx.OPRRef.Sequence = 10
	tx.OPRRef.Digest = state.OPRManifestSHA256
	tx.Identity.Version = state.SystemVersion
	if err := validateFreshness(state, tx, false); err != nil {
		t.Fatalf("independent OPR update against recovered system rejected: %v", err)
	}
}

func TestChannelStateKeepsIndependentReplayHighWaters(t *testing.T) {
	state := LocalState{SchemaVersion: 1, Channel: "stable", ManifestSHA256: strings.Repeat("a", 64), Sequence: 5, Architecture: "x86_64", Channels: map[string]ChannelState{}}
	saveChannelState(&state, "stable", state)
	rc := LocalState{SchemaVersion: 1, Channel: "rc", ManifestSHA256: strings.Repeat("b", 64), Sequence: 2, Architecture: "x86_64"}
	saveChannelState(&state, "rc", rc)
	if got := stateForChannel(state, "stable"); got.Sequence != 5 || got.ManifestSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("stable replay state changed: %+v", got)
	}
	if got := stateForChannel(state, "rc"); got.Sequence != 2 || got.ManifestSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("rc replay state missing: %+v", got)
	}
}

func TestChannelPointerIsNeverFetchedAsImmutableRoot(t *testing.T) {
	if !mutableURL("https://repo.invalid/repo/transactions/stable/manifest.json") {
		t.Fatal("channel pointer was treated as immutable")
	}
	if mutableURL("https://repo.invalid/repo/transactions/stable/txn-1/manifest.json") {
		t.Fatal("immutable channel manifest was treated as pointer")
	}
}

func newFixture(t *testing.T) *signedFixture {
	t.Helper()
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg is required for manifest signing fixtures")
	}
	root := t.TempDir()
	home := filepath.Join(root, "gpg")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	command := func(args ...string) []byte {
		cmd := exec.Command("gpg", append([]string{"--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "", "--homedir", home}, args...)...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("gpg %v: %v (%s)", args, err, output)
		}
		return output
	}
	command("--quick-generate-key", "Manifest Fixture <fixture@example.invalid>", "rsa2048", "sign", "1d")
	key := command("--armor", "--export")
	keyPath := filepath.Join(root, "trusted.asc")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := ""
	for _, line := range strings.Split(string(command("--with-colons", "--fingerprint")), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) > 9 && fields[0] == "fpr" {
			fingerprint = fields[9]
			break
		}
	}
	if fingerprint == "" {
		t.Fatal("fixture fingerprint missing")
	}
	files := map[string][]byte{}
	sign := func(name string, value map[string]any) []byte {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if canonical, _, err := canonicalDocument(data); err != nil {
			t.Fatal(err)
		} else {
			data = canonical
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		signaturePath := path + ".sig"
		command("--armor", "--detach-sign", "--output", signaturePath, path)
		signature, err := os.ReadFile(signaturePath)
		if err != nil {
			t.Fatal(err)
		}
		files["/"+name] = data
		files["/"+name+".sig"] = signature
		return data
	}
	now := time.Now().Add(-time.Minute).Truncate(time.Second)
	expires := now.Add(time.Hour).Unix()
	coreDB := []byte("core-database-fixture")
	extraDB := []byte("extra-database-fixture")
	coreDigest := sha256Hex(coreDB)
	extraDigest := sha256Hex(extraDB)
	coreRepo := map[string]any{"name": "core", "architecture": "x86_64", "snapshotDigest": coreDigest, "dbUrl": "", "signatureUrl": "", "packageBaseUrl": ""}
	extraRepo := map[string]any{"name": "extra", "architecture": "x86_64", "snapshotDigest": extraDigest, "dbUrl": "", "signatureUrl": "", "packageBaseUrl": ""}
	serverFiles := map[string][]byte{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if data, ok := serverFiles[request.URL.Path]; ok {
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write(data)
			return
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer func() { _ = server.Client() }()
	coreRepo["dbUrl"] = server.URL + "/repo/releases/4.0.3/core/x86_64/core.db"
	coreRepo["signatureUrl"] = coreRepo["dbUrl"].(string) + ".sig"
	coreRepo["packageBaseUrl"] = server.URL + "/repo/releases/4.0.3/core/x86_64"
	extraRepo["dbUrl"] = server.URL + "/repo/releases/4.0.3/extra/x86_64/extra.db"
	extraRepo["signatureUrl"] = extraRepo["dbUrl"].(string) + ".sig"
	extraRepo["packageBaseUrl"] = server.URL + "/repo/releases/4.0.3/extra/x86_64"
	serverFiles["/repo/releases/4.0.3/core/x86_64/core.db"] = coreDB
	serverFiles["/repo/releases/4.0.3/extra/x86_64/extra.db"] = extraDB
	coreSigPath := filepath.Join(root, "core.db")
	extraSigPath := filepath.Join(root, "extra.db")
	if err := os.WriteFile(coreSigPath, coreDB, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extraSigPath, extraDB, 0o600); err != nil {
		t.Fatal(err)
	}
	command("--armor", "--detach-sign", "--output", coreSigPath+".sig", coreSigPath)
	command("--armor", "--detach-sign", "--output", extraSigPath+".sig", extraSigPath)
	coreSignature, _ := os.ReadFile(coreSigPath + ".sig")
	extraSignature, _ := os.ReadFile(extraSigPath + ".sig")
	serverFiles["/repo/releases/4.0.3/core/x86_64/core.db.sig"] = coreSignature
	serverFiles["/repo/releases/4.0.3/extra/x86_64/extra.db.sig"] = extraSignature
	childBase := func(kind, version, generation, releaseID string, sequence uint64) map[string]any {
		return map[string]any{"schemaVersion": 1, "kind": kind, "lane": kind, "channel": "stable", "identity": map[string]any{"version": version, "generation": generation}, "releaseId": releaseID, "parent": map[string]any{"digest": nil, "sequence": nil}, "createdAt": now.Unix(), "expiresAt": expires, "sequence": sequence, "architectures": []string{"x86_64"}, "sourceRefs": []any{}, "repositories": []any{}, "packageChunks": []any{}, "packageCount": 0, "compatibility": map[string]any{"systemManifestDigest": nil, "systemSnapshotDigests": []string{}, "oprManifestDigest": nil}, "systemManifest": nil, "oprManifest": nil, "changelog": map[string]any{"url": server.URL + "/change.json", "sha256": strings.Repeat("c", 64), "size": 1, "approvedBy": "release", "cohortDigests": []any{}}, "approvals": map[string]any{"releaseTeam": []string{"release"}, "baseOwners": []string{}}, "recovery": map[string]any{"fromDigest": nil, "target": nil, "authorized": false, "reason": nil, "constraints": []string{"no-data-migration"}}, "policy": map[string]any{"schemaVersion": 1, "version": "distribution-release-v1"}}
	}
	systemData := sign("system.json", childBase("system", "4.0.3", "", "sys-4.0.3", 4))
	oprData := sign("opr.json", childBase("opr", "4.0.3", "opr-1", "opr-1", 6))
	systemURL := server.URL + "/system.json"
	oprURL := server.URL + "/opr.json"
	packageRefs := []map[string]any{
		{"releaseId": "linux-x86", "name": "linux", "version": "1", "architecture": "x86_64", "artifactUrl": server.URL + "/repo/releases/4.0.3/core/x86_64/linux.pkg.tar.zst", "artifactSignatureUrl": server.URL + "/repo/releases/4.0.3/core/x86_64/linux.pkg.tar.zst.sig", "artifactSha256": strings.Repeat("1", 64), "artifactSignatureSha256": strings.Repeat("2", 64), "cohortId": nil, "evidence": []any{}},
		{"releaseId": "linux-arm", "name": "linux", "version": "1", "architecture": "aarch64", "artifactUrl": server.URL + "/repo/releases/4.0.3/core/aarch64/linux.pkg.tar.zst", "artifactSignatureUrl": server.URL + "/repo/releases/4.0.3/core/aarch64/linux.pkg.tar.zst.sig", "artifactSha256": strings.Repeat("3", 64), "artifactSignatureSha256": strings.Repeat("4", 64), "cohortId": nil, "evidence": []any{}},
		{"releaseId": "docs-x86", "name": "docs", "version": "1", "architecture": "any", "artifactUrl": server.URL + "/repo/releases/4.0.3/core/x86_64/docs-any.pkg.tar.zst", "artifactSignatureUrl": server.URL + "/repo/releases/4.0.3/core/x86_64/docs-any.pkg.tar.zst.sig", "artifactSha256": strings.Repeat("5", 64), "artifactSignatureSha256": strings.Repeat("6", 64), "cohortId": nil, "evidence": []any{}},
		{"releaseId": "docs-arm", "name": "docs", "version": "1", "architecture": "any", "artifactUrl": server.URL + "/repo/releases/4.0.3/core/aarch64/docs-any.pkg.tar.zst", "artifactSignatureUrl": server.URL + "/repo/releases/4.0.3/core/aarch64/docs-any.pkg.tar.zst.sig", "artifactSha256": strings.Repeat("5", 64), "artifactSignatureSha256": strings.Repeat("6", 64), "cohortId": nil, "evidence": []any{}},
	}
	chunkData, err := json.Marshal(map[string]any{"schemaVersion": 1, "index": 0, "count": 1, "packages": packageRefs})
	if err != nil {
		t.Fatal(err)
	}
	serverFiles["/package-chunk.json"] = chunkData
	chunkRef := map[string]any{"url": server.URL + "/package-chunk.json", "sha256": sha256Hex(chunkData), "size": len(chunkData), "index": 0, "count": 1, "packageCount": len(packageRefs)}
	txObject := map[string]any{"schemaVersion": 1, "kind": "resolved-transaction", "lane": "transaction", "channel": "stable", "identity": map[string]any{"version": "4.0.3", "generation": "opr-1"}, "releaseId": "tx-4.0.3-1", "parent": map[string]any{"digest": nil, "sequence": nil}, "createdAt": now.Unix(), "expiresAt": expires, "sequence": 10, "architectures": []string{"x86_64"}, "sourceRefs": []any{}, "repositories": []any{coreRepo, extraRepo}, "packageChunks": []any{chunkRef}, "packageCount": len(packageRefs), "compatibility": map[string]any{"systemManifestDigest": sha256Hex(systemData), "systemSnapshotDigests": []string{coreDigest, extraDigest}, "oprManifestDigest": sha256Hex(oprData)}, "systemManifest": map[string]any{"url": systemURL, "digest": sha256Hex(systemData), "signatureUrl": systemURL + ".sig", "channel": "stable", "sequence": 4, "version": "4.0.3", "generation": nil}, "oprManifest": map[string]any{"url": oprURL, "digest": sha256Hex(oprData), "signatureUrl": oprURL + ".sig", "channel": "stable", "sequence": 6, "version": "4.0.3", "generation": "opr-1"}, "changelog": map[string]any{"url": server.URL + "/change.json", "sha256": strings.Repeat("c", 64), "size": 1, "approvedBy": "release", "cohortDigests": []any{}}, "approvals": map[string]any{"releaseTeam": []string{"release"}, "baseOwners": []string{}}, "recovery": map[string]any{"fromDigest": nil, "target": nil, "authorized": false, "reason": nil, "constraints": []string{"no-data-migration"}}, "policy": map[string]any{"schemaVersion": 1, "version": "distribution-release-v1"}}
	txData := sign("transaction.json", txObject)
	for path, data := range files {
		serverFiles[path] = data
	}
	serverFiles["/system.json"] = systemData
	serverFiles["/system.json.sig"] = files["/system.json.sig"]
	serverFiles["/opr.json"] = oprData
	serverFiles["/opr.json.sig"] = files["/opr.json.sig"]
	serverFiles["/transaction.json"] = txData
	serverFiles["/transaction.json.sig"] = files["/transaction.json.sig"]
	// sign() stores the document under its local filename; map aliases used above.
	serverFiles["/system.json.sig"] = files["/system.json.sig"]
	serverFiles["/opr.json.sig"] = files["/opr.json.sig"]
	serverFiles["/transaction.json.sig"] = files["/transaction.json.sig"]
	client, err := New(Options{HTTP: server.Client(), TrustedKey: keyPath, TrustedFingerprint: fingerprint, Architecture: "x86_64", ExpectedChannel: "stable", Now: func() time.Time { return now.Add(time.Minute) }})
	if err != nil {
		t.Fatal(err)
	}
	return &signedFixture{server: server, client: client, manifestURL: server.URL + "/transaction.json", keyPath: keyPath, fingerprint: fingerprint, files: serverFiles}
}

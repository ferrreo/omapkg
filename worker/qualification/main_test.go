package qualification

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestQualificationRunsReviewedPlanAndSignsObservedBytes(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("fixture targets native x86_64 Linux")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "worker.key")
	outputPath := filepath.Join(directory, "evidence.json")
	planPath := filepath.Join(directory, "plan.json")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	stateBytes := []byte(`[{"name":"demo","version":"1","architecture":"x86_64"}]`)
	observed := map[string]interface{}{"files": []interface{}{map[string]interface{}{"name": "state", "kind": "package-state", "sha256": digestBytes(stateBytes), "size": len(stateBytes), "value": []interface{}{map[string]interface{}{"name": "demo", "version": "1", "architecture": "x86_64"}}}}, "states": map[string]interface{}{"state": []interface{}{map[string]interface{}{"name": "demo", "version": "1", "architecture": "x86_64"}}}}
	plan := map[string]interface{}{
		"schemaVersion": 1, "cohortId": "cohort-1", "revision": 1, "operation": "install", "architecture": "x86_64",
		"candidateSha256": repeat("a"), "inputSha256": repeat("b"), "artifactSha256": repeat("c"),
		"environmentSha256": "", "profile": map[string]interface{}{"id": "x86-uefi", "sha256": repeat("d")},
		"coverage":                  map[string]interface{}{"kind": "member", "pkgbase": "demo", "rootSha256": nil, "releaseId": nil, "members": []interface{}{"demo"}, "sha256": ""},
		"commands":                  []interface{}{map[string]interface{}{"name": "write", "executable": "/bin/sh", "arguments": []interface{}{"-c", "printf '%s' '[{\"name\":\"demo\",\"version\":\"1\",\"architecture\":\"x86_64\"}]' > state"}}},
		"observations":              []interface{}{map[string]interface{}{"name": "state", "path": "state", "kind": "package-state"}},
		"expectedObservationSha256": digestJSON(observed), "expected": map[string]interface{}{"environment": map[string]interface{}{"profileId": "x86-uefi", "operation": "install"}},
	}
	plan["coverage"].(map[string]interface{})["sha256"] = digestJSON(map[string]interface{}{"kind": "member", "pkgbase": "demo", "rootSha256": nil, "releaseId": nil, "members": []interface{}{"demo"}, "artifactSha256": plan["artifactSha256"]})
	machine := map[string]interface{}{"architecture": "x86_64", "goarch": "amd64", "goos": "linux", "runtime": runtime.Version()}
	plan["environmentSha256"] = digestJSON(map[string]interface{}{"machine": machine, "details": plan["expected"].(map[string]interface{})["environment"]})
	envelope := map[string]interface{}{"planId": "plan-1", "testPlanSha256": digestJSON(plan), "plan": plan}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planPath, envelopeBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"--plan", planPath, "--key-file", keyPath, "--worker-id", "worker-1", "--work-dir", directory, "--output", outputPath}); err != nil {
		t.Fatal(err)
	}
	var report evidence
	encoded, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &report); err != nil {
		t.Fatal(err)
	}
	if report.Result.ExitCode != 0 || report.ObservedSHA256 != digestJSON(observed) || report.Signature == "" || report.Environment.SHA256 != plan["environmentSha256"].(string) {
		t.Fatalf("unexpected qualification report: %+v", report)
	}
	publicKey := private.Public().(ed25519.PublicKey)
	payload := canonicalJSON(payloadWithoutSignature(report))
	signature, err := base64.StdEncoding.DecodeString(report.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		t.Fatal("qualification signature did not verify")
	}
}

func TestQualificationRejectsPlanDigestMismatch(t *testing.T) {
	directory := t.TempDir()
	planPath := filepath.Join(directory, "plan.json")
	keyPath := filepath.Join(directory, "worker.key")
	outputPath := filepath.Join(directory, "evidence.json")
	plan := map[string]interface{}{"schemaVersion": 1, "cohortId": "cohort-1", "revision": 1, "operation": "install", "architecture": "x86_64"}
	envelope := map[string]interface{}{"planId": "plan-1", "testPlanSha256": repeat("a"), "plan": plan}
	bytes, _ := json.Marshal(envelope)
	if err := os.WriteFile(planPath, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"--plan", planPath, "--key-file", keyPath, "--worker-id", "worker-1", "--output", outputPath}); err == nil {
		t.Fatal("accepted a mismatched reviewed plan digest")
	}
}

func repeat(char string) string { return strings.Repeat(char, 64) }

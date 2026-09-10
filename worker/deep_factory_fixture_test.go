package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type deepFactoryFixtureEnvelope struct {
	Job          Job    `json:"job"`
	WorkerID     string `json:"workerId"`
	WorkerSecret string `json:"workerPrivateKey"`
	SourcePath   string `json:"sourcePath"`
	ArtifactPath string `json:"artifactPath"`
	EvidencePath string `json:"evidencePath"`
	ResultPath   string `json:"resultPath"`
}

// TestDeepFactoryNativeFixture runs the real Runner and provenance renderer
// only when the caller supplies a local digest-pinned builder/runtime pair.
// The CLI owns the disposable source/result paths and never enrolls a worker.
func TestDeepFactoryNativeFixture(t *testing.T) {
	image := os.Getenv("OPR_DEEP_BUILDER_IMAGE")
	runtimeImage := os.Getenv("OPR_DEEP_RUNTIME_IMAGE")
	resultPath := os.Getenv("OPR_DEEP_RESULT")
	jobPath := os.Getenv("OPR_DEEP_JOB_FILE")
	if image == "" || runtimeImage == "" || resultPath == "" || jobPath == "" {
		t.Skip("OPR_DEEP_BUILDER_IMAGE, OPR_DEEP_RUNTIME_IMAGE, OPR_DEEP_RESULT and OPR_DEEP_JOB_FILE are required")
	}
	imageAt := strings.LastIndex(image, "@sha256:")
	if imageAt < 0 {
		t.Fatal("OPR_DEEP_BUILDER_IMAGE must be digest pinned")
	}
	imageDigest := image[imageAt+1:]
	if !digestPattern.MatchString(imageDigest) {
		t.Fatal("OPR_DEEP_BUILDER_IMAGE digest is invalid")
	}
	runtimeAt := strings.LastIndex(runtimeImage, "@sha256:")
	if runtimeAt < 0 || !digestPattern.MatchString(runtimeImage[runtimeAt+1:]) {
		t.Fatal("OPR_DEEP_RUNTIME_IMAGE must be digest pinned")
	}
	var envelope deepFactoryFixtureEnvelope
	bytes, err := os.ReadFile(jobPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bytes, &envelope); err != nil {
		t.Fatal(err)
	}
	job := envelope.Job
	if envelope.WorkerID == "" || envelope.WorkerSecret == "" || envelope.SourcePath == "" || envelope.ArtifactPath == "" || envelope.EvidencePath == "" || envelope.ResultPath == "" {
		t.Fatal("deep factory fixture envelope is incomplete")
	}
	if resultPath != envelope.ResultPath {
		t.Fatalf("result path differs from issued envelope: %s", resultPath)
	}
	if job.ImageDigest != imageDigest || job.ImageRef != image || job.FactoryRunID == "" || job.FactoryAttempt < 1 || job.OutputContract == nil {
		t.Fatal("issued worker job does not bind pinned factory inputs")
	}
	if len(job.Sources) != 1 || !sha256Pattern.MatchString(job.Sources[0].SHA256) {
		t.Fatal("issued worker job has invalid source evidence")
	}
	if _, err := os.Stat(envelope.SourcePath); err != nil {
		t.Fatal(err)
	}
	root := os.Getenv("OPR_DEEP_SOURCE_ROOT")
	if root == "" {
		root = filepath.Dir(envelope.SourcePath)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	runtime := os.Getenv("OPR_DEEP_RUNTIME")
	if runtime == "" {
		runtime = "podman"
	}
	runner := Runner{Runtime: runtime, Image: image, ImageDigest: imageDigest, RuntimeImage: runtimeImage, StateDir: root, BuildTimeout: 20 * time.Minute}
	started := time.Now().UTC()
	result, err := runner.Execute(context.Background(), job, []fetchedSource{{Source: job.Sources[0], Path: envelope.SourcePath}})
	finished := time.Now().UTC()
	if err != nil {
		if result.Cleanup != nil {
			result.Cleanup()
		}
		t.Fatalf("deep native factory build failed: %v\n%s", err, result.Log)
	}
	provenance, err := provenanceForOutputs(job, envelope.WorkerID, result, started.Format(time.RFC3339), finished.Format(time.RFC3339))
	if err != nil {
		if result.Cleanup != nil {
			result.Cleanup()
		}
		t.Fatal(err)
	}
	privateBytes, err := base64.StdEncoding.DecodeString(envelope.WorkerSecret)
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize {
		t.Fatal("issued worker private key is invalid")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateBytes), []byte(provenance))
	artifact := result.Outputs[0]
	info, err := os.Stat(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	artifactBytes, err := os.Open(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := os.Create(envelope.ArtifactPath)
	if err != nil {
		artifactBytes.Close()
		t.Fatal(err)
	}
	if _, err := io.Copy(destination, artifactBytes); err != nil {
		artifactBytes.Close()
		destination.Close()
		t.Fatal(err)
	}
	if err := artifactBytes.Close(); err != nil {
		destination.Close()
		t.Fatal(err)
	}
	if err := destination.Close(); err != nil {
		t.Fatal(err)
	}
	evidenceDirectory := artifact.Path + ".abi"
	evidenceEntries, err := os.ReadDir(evidenceDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidenceEntries) == 0 {
		t.Fatal("native fixture produced no ABI evidence")
	}
	if err := os.MkdirAll(envelope.EvidencePath, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, entry := range evidenceEntries {
		if !entry.Type().IsRegular() || filepath.Ext(entry.Name()) != ".json" {
			t.Fatalf("unexpected ABI evidence entry %s", entry.Name())
		}
		input, err := os.Open(filepath.Join(evidenceDirectory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		output, err := os.Create(filepath.Join(envelope.EvidencePath, entry.Name()))
		if err != nil {
			input.Close()
			t.Fatal(err)
		}
		if _, err := io.Copy(output, input); err != nil {
			input.Close()
			output.Close()
			t.Fatal(err)
		}
		if err := input.Close(); err != nil {
			output.Close()
			t.Fatal(err)
		}
		if err := output.Close(); err != nil {
			t.Fatal(err)
		}
	}
	value := map[string]any{
		"recipe": job.Recipe, "sourceName": job.Sources[0].Name, "sourceSha256": job.Sources[0].SHA256, "provenance": provenance,
		"provenanceSignature": base64.StdEncoding.EncodeToString(signature), "workerId": envelope.WorkerID,
		"artifactFilename": artifact.Filename, "artifactSha256": artifact.ArtifactSHA256, "artifactSize": info.Size(),
		"installedSize": artifact.PackageMetadata.InstalledSize, "abiEvidencePath": envelope.EvidencePath, "leaseToken": job.LeaseToken, "runId": job.FactoryRunID, "attempt": job.FactoryAttempt, "inputSha256": job.FactoryInputSHA256,
	}
	resultBytes, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(resultPath, resultBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if result.Cleanup != nil {
		result.Cleanup()
	}
}

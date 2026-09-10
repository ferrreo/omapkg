package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func ociDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func ociJSON(data string) ([]byte, string) {
	var value any
	if err := json.Unmarshal([]byte(data), &value); err != nil {
		panic(err)
	}
	canonical, _ := json.Marshal(value)
	return canonical, ociDigest(canonical)
}

func ociTar(t *testing.T) ([]byte, string) {
	var body bytes.Buffer
	writer := tar.NewWriter(&body)
	content := []byte("factory OCI fixture\n")
	contextDockerfile := "FROM scratch\nCOPY wrong.txt /payload.txt\n"
	if err := writer.WriteHeader(&tar.Header{Name: "Dockerfile", Mode: 0o644, Size: int64(len(contextDockerfile))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(contextDockerfile)); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "payload.txt", Mode: 0o644, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	data := body.Bytes()
	return data, ociDigest(data)
}

type ociArchiveDescriptor struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
}

type ociArchiveIndex struct {
	Manifests []ociArchiveDescriptor `json:"manifests"`
}

type ociArchiveManifest struct {
	Layers []ociArchiveDescriptor `json:"layers"`
}

type factoryImageBridgeFixture struct {
	Completion      factoryImageCompletion `json:"completion"`
	Candidate       factoryImageCandidate  `json:"candidate"`
	JobID           string                 `json:"jobId"`
	RunID           string                 `json:"runId"`
	Attempt         int                    `json:"attempt"`
	LeaseToken      string                 `json:"leaseToken"`
	InputSHA256     string                 `json:"inputSha256"`
	WorkerID        string                 `json:"workerId"`
	WorkerPublicKey string                 `json:"workerPublicKey"`
	ArtifactKey     string                 `json:"artifactKey"`
	ArtifactSHA256  string                 `json:"artifactSha256"`
	ArtifactSize    int64                  `json:"artifactSize"`
	ArtifactFile    string                 `json:"artifactFile"`
}

func writeFactoryImageBridgeFixture(path string, fixture factoryImageBridgeFixture, archive []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	archivePath := filepath.Join(directory, fixture.ArtifactFile)
	if err := os.WriteFile(archivePath, archive, 0o600); err != nil {
		return err
	}
	data, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func readOCIArchive(archive []byte) (map[string][]byte, error) {
	entries := make(map[string][]byte)
	reader := tar.NewReader(bytes.NewReader(archive))
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		name := strings.TrimPrefix(header.Name, "./")
		if name == "" || strings.Contains(name, "../") || strings.HasPrefix(name, "/") {
			return nil, fmt.Errorf("unsafe OCI archive entry %q", header.Name)
		}
		if _, exists := entries[name]; exists {
			return nil, fmt.Errorf("duplicate OCI archive entry %q", name)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		entries[name] = body
	}
}

func ociBlobPath(digest string) (string, error) {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 || parts[0] != "sha256" || !sha256HexPattern.MatchString(parts[1]) {
		return "", fmt.Errorf("invalid OCI digest %q", digest)
	}
	return "blobs/sha256/" + parts[1], nil
}

var sha256HexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func verifyOCIArchive(archive []byte, expectedPayload []byte) (string, error) {
	entries, err := readOCIArchive(archive)
	if err != nil {
		return "", err
	}
	var index ociArchiveIndex
	if err := json.Unmarshal(entries["index.json"], &index); err != nil {
		return "", fmt.Errorf("read OCI index: %w", err)
	}
	if len(index.Manifests) != 1 {
		return "", fmt.Errorf("OCI archive has %d manifests", len(index.Manifests))
	}
	manifestDescriptor := index.Manifests[0]
	manifestPath, err := ociBlobPath(manifestDescriptor.Digest)
	if err != nil {
		return "", err
	}
	manifestBytes, ok := entries[manifestPath]
	if !ok {
		return "", fmt.Errorf("OCI manifest blob %s is missing", manifestDescriptor.Digest)
	}
	if got := "sha256:" + ociDigest(manifestBytes); got != manifestDescriptor.Digest {
		return "", fmt.Errorf("OCI manifest digest is %s, expected %s", got, manifestDescriptor.Digest)
	}
	var manifest ociArchiveManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", fmt.Errorf("read OCI manifest: %w", err)
	}
	foundPayload := false
	for _, descriptor := range manifest.Layers {
		layerPath, err := ociBlobPath(descriptor.Digest)
		if err != nil {
			return "", err
		}
		layer, ok := entries[layerPath]
		if !ok {
			return "", fmt.Errorf("OCI layer blob %s is missing", descriptor.Digest)
		}
		if got := "sha256:" + ociDigest(layer); got != descriptor.Digest {
			return "", fmt.Errorf("OCI layer digest is %s, expected %s", got, descriptor.Digest)
		}
		var layerReader io.ReadCloser = io.NopCloser(bytes.NewReader(layer))
		if strings.Contains(descriptor.MediaType, "+gzip") {
			gzipReader, err := gzip.NewReader(bytes.NewReader(layer))
			if err != nil {
				return "", fmt.Errorf("read OCI gzip layer: %w", err)
			}
			layerReader = gzipReader
		}
		layerTar := tar.NewReader(layerReader)
		for {
			header, err := layerTar.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				_ = layerReader.Close()
				return "", fmt.Errorf("read OCI layer tar: %w", err)
			}
			if strings.TrimPrefix(header.Name, "./") != "payload.txt" {
				continue
			}
			payload, err := io.ReadAll(layerTar)
			if err != nil {
				_ = layerReader.Close()
				return "", err
			}
			if !bytes.Equal(payload, expectedPayload) {
				_ = layerReader.Close()
				return "", fmt.Errorf("OCI payload differs")
			}
			foundPayload = true
		}
		_ = layerReader.Close()
	}
	if !foundPayload {
		return "", errors.New("OCI payload.txt is missing")
	}
	return manifestDescriptor.Digest, nil
}

func TestFactoryImageOCIRealRootlessExecution(t *testing.T) {
	if os.Getenv("OPR_FACTORY_IMAGE_OCI_E2E") != "1" {
		t.Skip("set OPR_FACTORY_IMAGE_OCI_E2E=1 with a local pinned buildah tool image")
	}
	image := os.Getenv("OPR_FACTORY_IMAGE_OCI_IMAGE")
	if image == "" {
		t.Fatal("OPR_FACTORY_IMAGE_OCI_IMAGE is required")
	}
	imageAt := strings.LastIndex(image, "@")
	if imageAt < 1 {
		t.Fatal("OPR_FACTORY_IMAGE_OCI_IMAGE must be digest-pinned")
	}
	imageDigest := image[imageAt+1:]
	if !strings.HasPrefix(imageDigest, "sha256:") {
		imageDigest = "sha256:" + imageDigest
		image = image[:imageAt+1] + imageDigest
	}
	fixturePath := os.Getenv("OPR_FACTORY_IMAGE_E2E_FIXTURE")
	if os.Getenv("OPR_FACTORY_IMAGE_OCI_AB") == "1" {
		firstFixture, secondFixture := "", ""
		if fixturePath != "" {
			firstFixture, secondFixture = fixturePath+".a", fixturePath+".b"
		}
		first := runFactoryImageOCIOnce(t, image, firstFixture)
		time.Sleep(2 * time.Second)
		second := runFactoryImageOCIOnce(t, image, secondFixture)
		if !bytes.Equal(first, second) {
			t.Fatalf("OCI A/B output differs: first=%s second=%s", ociDigest(first), ociDigest(second))
		}
		t.Logf("OCI A/B output identical: bytes=%d sha256=%s", len(first), ociDigest(first))
		return
	}
	runFactoryImageOCIOnce(t, image, fixturePath)
}

func runFactoryImageOCIOnce(t *testing.T, image, fixturePath string) []byte {
	t.Helper()
	builder := filepath.Join("..", "scripts", "build-oci-image.sh")
	builderBytes, err := os.ReadFile(builder)
	if err != nil {
		t.Fatal(err)
	}
	imageDigest := image[strings.LastIndex(image, "@")+1:]
	profile, profileSHA := ociJSON(`{"schemaVersion":1,"format":"oci","architecture":"x86_64","sourceDateEpoch":1700000000}`)
	proof, proofSHA := ociJSON(`{"schemaVersion":1,"kind":"factory-image-construction-proof","status":"reviewed","runPolicySha256":"` + strings.Repeat("c", 64) + `","candidateId":"oci-e2e","architecture":"x86_64","profileSha256":"` + profileSHA + `","inputLockSha256":"` + strings.Repeat("b", 64) + `"}`)
	lock, lockSHA := ociJSON(`{"schemaVersion":1,"authority":"factory-candidate-v1","candidate":{"executionScope":"private","id":"oci-e2e","ownedUniverseSha256":"` + strings.Repeat("a", 64) + `","inputLockSha256":"` + strings.Repeat("b", 64) + `","nativePlanSha256":"` + proofSHA + `"},"architecture":"x86_64"}`)
	contextBytes, _ := ociTar(t)
	keyBytes := []byte("public package verification key fixture")
	root := t.TempDir()
	objects := map[string][]byte{
		"profile.json": profile, "construction-proof.json": proof, "candidate-lock.json": lock, "context.tar": contextBytes, "Dockerfile": []byte("FROM scratch\nCOPY payload.txt /payload.txt\n"), "authority.asc": keyBytes, "build-oci-image.sh": builderBytes,
	}
	refs := map[string]factoryImageObject{}
	for name, data := range objects {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		refs[name] = factoryImageObject{Key: name, SHA256: ociDigest(data), Size: int64(len(data)), File: name}
	}
	profileRef := refs["profile.json"]
	profileRef.SHA256 = profileSHA
	profileRef.Size = int64(len(profile))
	refs["profile.json"] = profileRef
	proofRef := refs["construction-proof.json"]
	proofRef.SHA256 = proofSHA
	proofRef.Size = int64(len(proof))
	refs["construction-proof.json"] = proofRef
	lockRef := refs["candidate-lock.json"]
	lockRef.SHA256 = lockSHA
	lockRef.Size = int64(len(lock))
	refs["candidate-lock.json"] = lockRef
	builderRef := refs["build-oci-image.sh"]
	builderRef.SHA256 = ociDigest(builderBytes)
	builderRef.Size = int64(len(builderBytes))
	refs["build-oci-image.sh"] = builderRef
	contextRef := refs["context.tar"]
	dockerfileRef := refs["Dockerfile"]
	policySHA := strings.Repeat("c", 64)
	candidate := factoryImageCandidate{ID: "oci-e2e", Architecture: "x86_64", Kind: "oci", ProfileID: "oci-fixture", ConstructionPolicySHA256: policySHA, Profile: profileRef, CandidateLock: lockRef, NativePlan: proofRef, TrustedAuthorityKey: refs["authority.asc"], Builder: builderRef, Context: &contextRef, Dockerfile: &dockerfileRef, ImageRef: "localhost/opr-factory-e2e:latest", TrustedAuthorityFingerprint: strings.Repeat("f", 40), SourceDateEpoch: 1700000000, OutputFilename: "image.oci"}
	job := &factoryImageJob{ID: "oci-e2e-job", RunID: "oci-e2e-run", Attempt: 1, LeaseToken: "lease", LeaseExpiry: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339), Candidate: candidate, InputSHA256: strings.Repeat("d", 64)}
	var uploaded []byte
	var completion factoryImageCompletion
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.Contains(request.URL.Path, "/inputs/") {
			name := request.URL.Path[strings.LastIndex(request.URL.Path, "/")+1:]
			inputFile := map[string]string{"profile": "profile.json", "candidate-lock": "candidate-lock.json", "native-plan": "construction-proof.json", "trusted-authority-key": "authority.asc", "builder": "build-oci-image.sh", "context": "context.tar", "dockerfile": "Dockerfile"}[name]
			data := objects[inputFile]
			writer.Header().Set("Content-Length", fmt.Sprint(len(data)))
			_, _ = writer.Write(data)
			return
		}
		if strings.HasSuffix(request.URL.Path, "/uploads") && request.Method == http.MethodPost {
			body, _ := io.ReadAll(request.Body)
			var input struct {
				Size   int64  `json:"size"`
				SHA256 string `json:"sha256"`
			}
			_ = json.Unmarshal(body, &input)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"uploadId":"upload","partSize":8388608,"maxSize":68719476736,"filename":"image.oci","size":` + fmt.Sprint(input.Size) + `,"sha256":"` + input.SHA256 + `","parts":[]}`))
			return
		}
		if strings.Contains(request.URL.Path, "/uploads/upload/") && request.Method == http.MethodPut {
			uploaded, _ = io.ReadAll(request.Body)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"partNumber":1,"sha256":"` + ociDigest(uploaded) + `","size":` + fmt.Sprint(len(uploaded)) + `,"etag":"part"}`))
			return
		}
		if strings.HasSuffix(request.URL.Path, "/uploads/upload/complete") {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write([]byte(`{"key":"private/oci-e2e/image.oci","sha256":"` + ociDigest(uploaded) + `","size":` + fmt.Sprint(len(uploaded)) + `,"filename":"image.oci"}`))
			return
		}
		if strings.HasSuffix(request.URL.Path, "/complete") {
			body, _ := io.ReadAll(request.Body)
			_ = json.Unmarshal(body, &completion)
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"status":"succeeded"}`))
			return
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	privateKey, _ := generateKey()
	client := &Client{Origin: mustURL(t, server.URL), WorkerID: "oci-e2e-worker", PrivateKey: privateKey, HTTP: server.Client()}
	cfg := Config{Origin: server.URL, WorkerID: client.WorkerID, Runtime: "podman", Image: image, ImageDigest: imageDigest, StateDir: root, FactoryImage: true, FactoryImageBuilderPath: builder, FactoryImageBuilderSHA256: ociDigest(builderBytes), Architecture: "x86_64", PrivateKey: encodePrivateKey(privateKey)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := runFactoryImageJob(ctx, client, cfg, job); err != nil {
		t.Fatal(err)
	}
	if len(uploaded) == 0 || completion.Status != "succeeded" {
		t.Fatalf("OCI output/evidence missing: bytes=%d completion=%+v", len(uploaded), completion)
	}
	signature, err := base64.StdEncoding.DecodeString(completion.EvidenceSignature)
	if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), []byte(completion.Evidence), signature) {
		t.Fatalf("worker evidence signature did not verify: err=%v", err)
	}
	var evidence factoryImageEvidence
	if err := json.Unmarshal([]byte(completion.Evidence), &evidence); err != nil {
		t.Fatalf("decode worker evidence: %v", err)
	}
	if evidence.ImageRef == nil {
		t.Fatal("OCI evidence omitted actual image reference")
	}
	if evidence.Artifact.SHA256 != ociDigest(uploaded) || evidence.Artifact.Size != int64(len(uploaded)) {
		t.Fatalf("worker artifact evidence does not bind uploaded bytes: %+v", evidence.Artifact)
	}
	manifestDigest, err := verifyOCIArchive(uploaded, []byte("factory OCI fixture\n"))
	if err != nil {
		t.Fatalf("verify OCI archive: %v", err)
	}
	imageAt := strings.LastIndex(*evidence.ImageRef, "@")
	if imageAt < 0 || manifestDigest != (*evidence.ImageRef)[imageAt+1:] {
		t.Fatalf("worker image reference %q does not match archive manifest %s", *evidence.ImageRef, manifestDigest)
	}
	if fixturePath != "" {
		publicKey := privateKey.Public().(ed25519.PublicKey)
		fixture := factoryImageBridgeFixture{
			Completion: completion, Candidate: candidate, JobID: job.ID, RunID: job.RunID, Attempt: job.Attempt,
			LeaseToken: job.LeaseToken, InputSHA256: job.InputSHA256, WorkerID: client.WorkerID,
			WorkerPublicKey: base64.StdEncoding.EncodeToString(publicKey), ArtifactKey: evidence.Artifact.Key,
			ArtifactSHA256: evidence.Artifact.SHA256, ArtifactSize: evidence.Artifact.Size, ArtifactFile: "factory-image.oci",
		}
		if err := writeFactoryImageBridgeFixture(fixturePath, fixture, uploaded); err != nil {
			t.Fatalf("write TS bridge fixture: %v", err)
		}
		t.Logf("TS bridge fixture: %s", fixturePath)
	}
	t.Logf("OCI archive bytes=%d sha256=%s manifest=%s imageRef=%s evidenceSignature=verified", len(uploaded), ociDigest(uploaded), manifestDigest, *evidence.ImageRef)
	return uploaded
}

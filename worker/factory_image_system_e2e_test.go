package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestFactoryImageSystemNativeExecution runs the complete system-image worker
// path against the same rootful tool image used by the filesystem fixture. It
// uses the configured native container runtime and production builder mounts.
func TestFactoryImageSystemNativeExecution(t *testing.T) {
	if os.Getenv("OPR_IMAGE_REPRO_SYSTEM_WORKER") != "1" {
		t.Skip("set OPR_IMAGE_REPRO_SYSTEM_WORKER=1 with a native filesystem fixture")
	}
	repoRoot := requiredSystemWorkerEnv(t, "OPR_IMAGE_REPRO_REPO_ROOT")
	profilePath := requiredSystemWorkerEnv(t, "OPR_IMAGE_REPRO_PROFILE")
	lockPath := requiredSystemWorkerEnv(t, "SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK")
	lockSignaturePath := requiredSystemWorkerEnv(t, "SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK_SIGNATURE")
	planPath := requiredSystemWorkerEnv(t, "SYSTEM_IMAGE_REPRO_NATIVE_PLAN")
	planSignaturePath := requiredSystemWorkerEnv(t, "SYSTEM_IMAGE_REPRO_NATIVE_PLAN_SIGNATURE")
	keyPath := requiredSystemWorkerEnv(t, "SYSTEM_IMAGE_REPRO_KEY")
	contextPath := requiredSystemWorkerEnv(t, "SYSTEM_IMAGE_REPRO_CONTEXT")
	fingerprint := requiredSystemWorkerEnv(t, "SYSTEM_IMAGE_REPRO_FINGERPRINT")
	builderPath := filepath.Join(repoRoot, "scripts", "build-system-image.sh")

	var profile struct {
		ID           string `json:"id"`
		Architecture string `json:"architecture"`
	}
	readSystemWorkerJSON(t, profilePath, &profile)
	var plan struct {
		RunPolicySHA256 string `json:"runPolicySha256"`
	}
	readSystemWorkerJSON(t, planPath, &plan)
	if profile.ID == "" || (profile.Architecture != "x86_64" && profile.Architecture != "aarch64") || len(plan.RunPolicySHA256) != 64 {
		t.Fatalf("system worker fixture profile/proof is incomplete: profile=%+v plan=%+v", profile, plan)
	}

	profileRef := systemWorkerRef(t, profilePath)
	lockRef := systemWorkerRef(t, lockPath)
	lockSignatureRef := systemWorkerRef(t, lockSignaturePath)
	planRef := systemWorkerRef(t, planPath)
	planSignatureRef := systemWorkerRef(t, planSignaturePath)
	keyRef := systemWorkerRef(t, keyPath)
	contextRef := systemWorkerRef(t, contextPath)
	builderRef := systemWorkerRef(t, builderPath)
	candidate := factoryImageCandidate{
		ID: "fixture-candidate", Architecture: profile.Architecture, Kind: "system", ProfileID: profile.ID,
		ConstructionPolicySHA256: plan.RunPolicySHA256, Profile: profileRef, CandidateLock: lockRef,
		CandidateLockSignature: &lockSignatureRef, NativePlan: planRef, NativePlanSignature: &planSignatureRef,
		TrustedAuthorityKey: keyRef, Builder: builderRef, Context: &contextRef,
		TrustedAuthorityFingerprint: strings.ToLower(fingerprint), SourceDateEpoch: 1700000000,
		OutputFilename: "system-worker.raw",
	}
	privateKey, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	job := &factoryImageJob{
		ID: "system-worker-job", RunID: "system-worker-run", Attempt: 1, LeaseToken: "system-worker-lease",
		LeaseExpiry: time.Now().Add(30 * time.Minute).UTC().Format(time.RFC3339), Candidate: candidate,
		InputSHA256: strings.Repeat("d", 64),
	}
	runtime := os.Getenv("SYSTEM_IMAGE_REPRO_CONTAINER_RUNTIME")
	if runtime == "" {
		runtime = "docker"
	}
	image := requiredSystemWorkerEnv(t, "SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE")
	imageAt := strings.LastIndex(image, "@")
	if imageAt <= 0 || !strings.HasPrefix(image[imageAt+1:], "sha256:") {
		t.Fatalf("SYSTEM_IMAGE_REPRO_BOOT_BUILDER_IMAGE must be digest-pinned: %q", image)
	}
	imageDigest := image[imageAt+1:]
	server, state := newSystemWorkerServer(t, map[string]string{
		"profile": profilePath, "candidate-lock": lockPath, "candidate-lock-signature": lockSignaturePath,
		"native-plan": planPath, "native-plan-signature": planSignaturePath, "trusted-authority-key": keyPath,
		"context": contextPath,
	}, candidate.OutputFilename)
	defer server.Close()
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{Origin: origin, WorkerID: "system-worker", PrivateKey: privateKey, HTTP: server.Client()}
	cfg := Config{
		Origin: server.URL, WorkerID: client.WorkerID, Runtime: runtime, Image: image,
		ImageDigest: imageDigest, StateDir: t.TempDir(), FactoryImage: true, FactoryImageBuilderPath: builderPath,
		FactoryImageBuilderSHA256: builderRef.SHA256, Architecture: profile.Architecture, PrivateKey: encodePrivateKey(privateKey),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	if err := runFactoryImageJob(ctx, client, cfg, job); err != nil {
		t.Fatal(err)
	}
	if state.completion.Status != "succeeded" {
		t.Fatalf("system worker completion status = %q", state.completion.Status)
	}
	if state.uploadedSize <= 0 || state.uploadedSize != state.expectedSize || state.uploadedSHA == "" || state.parts == 0 {
		t.Fatalf("system worker upload incomplete: size=%d expected=%d sha=%q parts=%d", state.uploadedSize, state.expectedSize, state.uploadedSHA, state.parts)
	}
	if state.completion.EvidenceSignature == "" {
		t.Fatal("system worker completion omitted evidence signature")
	}
	signature, err := base64.StdEncoding.DecodeString(state.completion.EvidenceSignature)
	if err != nil || !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), []byte(state.completion.Evidence), signature) {
		t.Fatalf("system worker evidence signature did not verify: %v", err)
	}
	var evidence factoryImageEvidence
	if err := json.Unmarshal([]byte(state.completion.Evidence), &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.ImageKind != "system" || evidence.ImageRef != nil || evidence.Artifact.SHA256 != state.uploadedSHA || evidence.Artifact.Size != state.uploadedSize {
		t.Fatalf("system worker evidence does not bind uploaded output: %+v", evidence)
	}
}

type systemWorkerServerState struct {
	completion   factoryImageCompletion
	uploadedSHA  string
	uploadedSize int64
	expectedSize int64
	parts        int
}

func newSystemWorkerServer(t *testing.T, objects map[string]string, filename string) (*httptest.Server, *systemWorkerServerState) {
	t.Helper()
	state := &systemWorkerServerState{}
	var uploadHash = sha256.New()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := request.URL.Path
		if strings.Contains(path, "/inputs/") {
			name := path[strings.LastIndex(path, "/")+1:]
			objectPath, ok := objects[name]
			if !ok {
				http.Error(writer, "missing input", http.StatusNotFound)
				return
			}
			body, err := os.Open(objectPath)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusNotFound)
				return
			}
			defer body.Close()
			if info, statErr := body.Stat(); statErr == nil {
				writer.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
			}
			_, _ = io.Copy(writer, body)
			return
		}
		if strings.HasSuffix(path, "/heartbeat") {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"leaseExpiresAt":"2099-01-01T00:00:00Z","cancel":false}`)
			return
		}
		if strings.HasSuffix(path, "/uploads") && request.Method == http.MethodPost {
			var input struct {
				Size   int64  `json:"size"`
				SHA256 string `json:"sha256"`
			}
			body, _ := io.ReadAll(request.Body)
			_ = json.Unmarshal(body, &input)
			state.expectedSize = input.Size
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(writer, `{"uploadId":"upload","partSize":8388608,"maxSize":68719476736,"filename":%q,"size":%d,"sha256":%q,"parts":[]}`, filename, input.Size, input.SHA256)
			return
		}
		if strings.Contains(path, "/uploads/upload/") && request.Method == http.MethodPut {
			partHash := sha256.New()
			size, _ := io.Copy(io.MultiWriter(partHash, uploadHash), request.Body)
			state.uploadedSize += size
			state.parts++
			writer.Header().Set("Content-Type", "application/json")
			part := path[strings.LastIndex(path, "/")+1:]
			part = strings.Split(part, "?")[0]
			_, _ = fmt.Fprintf(writer, `{"partNumber":%s,"sha256":%q,"size":%d,"etag":"part-%s"}`, part, hex.EncodeToString(partHash.Sum(nil)), size, part)
			return
		}
		if strings.HasSuffix(path, "/uploads/upload/complete") {
			state.uploadedSHA = hex.EncodeToString(uploadHash.Sum(nil))
			writer.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(writer, `{"key":"private/system-worker/image.raw","sha256":%q,"size":%d,"filename":%q}`, state.uploadedSHA, state.uploadedSize, filename)
			return
		}
		if strings.HasSuffix(path, "/complete") && request.Method == http.MethodPost {
			body, _ := io.ReadAll(request.Body)
			_ = json.Unmarshal(body, &state.completion)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"status":"succeeded"}`)
			return
		}
		http.NotFound(writer, request)
	}))
	return server, state
}

func requiredSystemWorkerEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("incomplete: %s is required", name)
	}
	return value
}

func readSystemWorkerJSON(t *testing.T, path string, value any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, value); err != nil {
		t.Fatal(err)
	}
}

func systemWorkerRef(t *testing.T, path string) factoryImageObject {
	t.Helper()
	digest, size, err := hashFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return factoryImageObject{Key: path, SHA256: digest, Size: size, File: filepath.Base(path)}
}

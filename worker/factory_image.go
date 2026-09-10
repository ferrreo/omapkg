package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type factoryImageObject struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	File   string `json:"filename"`
}

type factoryImageCandidate struct {
	ID                          string              `json:"id"`
	Architecture                string              `json:"architecture"`
	Kind                        string              `json:"kind"`
	ProfileID                   string              `json:"profileId"`
	NativePlanID                string              `json:"nativePlanId"`
	Profile                     factoryImageObject  `json:"profile"`
	CandidateLock               factoryImageObject  `json:"candidateLock"`
	CandidateLockSignature      factoryImageObject  `json:"candidateLockSignature"`
	NativePlan                  factoryImageObject  `json:"nativePlan"`
	NativePlanSignature         factoryImageObject  `json:"nativePlanSignature"`
	TrustedAuthorityKey         factoryImageObject  `json:"trustedAuthorityKey"`
	Builder                     factoryImageObject  `json:"builder"`
	Context                     *factoryImageObject `json:"context,omitempty"`
	Dockerfile                  *factoryImageObject `json:"dockerfile,omitempty"`
	TrustedAuthorityFingerprint string              `json:"trustedAuthorityFingerprint"`
	SourceDateEpoch             int64               `json:"sourceDateEpoch"`
	OutputFilename              string              `json:"outputFilename"`
	ImageRef                    string              `json:"imageRef,omitempty"`
}

type factoryImageJob struct {
	ID          string                `json:"id"`
	RunID       string                `json:"runId"`
	Attempt     int                   `json:"attempt"`
	LeaseToken  string                `json:"leaseToken"`
	LeaseExpiry string                `json:"leaseExpiresAt"`
	Candidate   factoryImageCandidate `json:"candidate"`
	InputSHA256 string                `json:"inputSha256"`
}

type factoryImageClaimResponse struct {
	Job *factoryImageJob `json:"job"`
}

type factoryImageCompletion struct {
	LeaseToken        string `json:"leaseToken"`
	Status            string `json:"status"`
	Error             string `json:"error,omitempty"`
	Evidence          string `json:"evidence,omitempty"`
	EvidenceSignature string `json:"evidenceSignature,omitempty"`
}

type factoryImageEvidence struct {
	SchemaVersion    int                  `json:"schemaVersion"`
	Kind             string               `json:"kind"`
	JobID            string               `json:"jobId"`
	RunID            string               `json:"runId"`
	Attempt          int                  `json:"attempt"`
	CandidateID      string               `json:"candidateId"`
	Architecture     string               `json:"architecture"`
	ImageKind        string               `json:"imageKind"`
	ImageRef         *string              `json:"imageRef"`
	InputSHA256      string               `json:"inputSha256"`
	ProfileSHA256    string               `json:"profileSha256"`
	NativePlanSHA256 string               `json:"nativePlanSha256"`
	Artifact         factoryImageArtifact `json:"artifact"`
	BuilderSHA256    string               `json:"builderSha256"`
	Observed         json.RawMessage      `json:"observed"`
}

type factoryImageArtifact struct {
	Key      string `json:"key"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	Filename string `json:"filename"`
}

func (c *Client) claimFactoryImage(ctx context.Context) (*factoryImageJob, error) {
	var result factoryImageClaimResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/worker/factory-images/claim", c.Metadata, &result); err != nil {
		return nil, err
	}
	return result.Job, nil
}

func (c *Client) factoryImageInput(ctx context.Context, jobID, leaseToken, name, destination string, expected factoryImageObject) error {
	if !idPattern.MatchString(jobID) || leaseToken == "" || name == "" {
		return errors.New("invalid private image input identity")
	}
	resp, err := c.signedRequest(ctx, http.MethodGet, "/api/worker/factory-images/"+urlPath(jobID)+"/inputs/"+urlPath(name)+"?leaseToken="+urlQuery(leaseToken), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readHTTPError(resp)
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(resp.Body, expected.Size+1))
	if err != nil {
		return err
	}
	if size != expected.Size || hexBytes(hash.Sum(nil)) != expected.SHA256 {
		return errors.New("private image input bytes do not match reviewed digest")
	}
	return file.Sync()
}

func (c *Client) heartbeatFactoryImage(ctx context.Context, job *factoryImageJob) (HeartbeatResponse, error) {
	var result HeartbeatResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/worker/factory-images/"+urlPath(job.ID)+"/heartbeat", map[string]any{"leaseToken": job.LeaseToken, "version": c.Metadata.Version, "runtime": c.Metadata.Runtime, "capabilities": c.Metadata.Capabilities}, &result)
	return result, err
}

func (c *Client) completeFactoryImage(ctx context.Context, job *factoryImageJob, completion factoryImageCompletion) error {
	return c.doJSON(ctx, http.MethodPost, "/api/worker/factory-images/"+urlPath(job.ID)+"/complete", completion, nil)
}

func (c *Client) uploadFactoryImage(ctx context.Context, job *factoryImageJob, file *os.File, size int64, digest string) (factoryImageArtifact, error) {
	var start uploadStartResponse
	requestPath := "/api/worker/factory-images/" + urlPath(job.ID) + "/uploads"
	if err := c.doJSON(ctx, http.MethodPost, requestPath, uploadStartRequest{LeaseToken: job.LeaseToken, Filename: job.Candidate.OutputFilename, Size: size, SHA256: digest}, &start); err != nil {
		return factoryImageArtifact{}, err
	}
	if start.Completed != nil {
		return factoryImageArtifact{Key: start.Completed.Key, SHA256: start.Completed.SHA256, Size: start.Completed.Size, Filename: start.Completed.Filename}, nil
	}
	if start.UploadID == "" || start.PartSize <= 0 || start.PartSize > maxUploadPartSize || start.Size != size || start.SHA256 != digest {
		return factoryImageArtifact{}, errors.New("invalid private image upload session")
	}
	parts := make(map[int]UploadPart, len(start.Parts))
	for _, part := range start.Parts {
		parts[part.PartNumber] = part
	}
	total := int((size + start.PartSize - 1) / start.PartSize)
	for index := 0; index < total; index++ {
		partNumber := index + 1
		offset := int64(index) * start.PartSize
		partSize := start.PartSize
		if remaining := size - offset; remaining < partSize {
			partSize = remaining
		}
		partHash, err := hashFileRange(file, offset, partSize)
		if err != nil {
			return factoryImageArtifact{}, err
		}
		if previous, ok := parts[partNumber]; ok {
			if previous.SHA256 != partHash || previous.Size != partSize {
				return factoryImageArtifact{}, errors.New("private image upload part conflicts")
			}
			continue
		}
		var response uploadPartResponse
		partPath := requestPath + "/" + urlPath(start.UploadID) + "/" + fmt.Sprint(partNumber) + "?leaseToken=" + urlQuery(job.LeaseToken)
		if err := c.uploadPart(ctx, partPath, file, offset, partSize, partHash, &response); err != nil {
			return factoryImageArtifact{}, err
		}
		if response.PartNumber != partNumber || response.SHA256 != partHash || response.Size != partSize {
			return factoryImageArtifact{}, errors.New("private image upload part response differs")
		}
	}
	var result ArtifactResponse
	if err := c.doJSON(ctx, http.MethodPost, requestPath+"/"+urlPath(start.UploadID)+"/complete", HeartbeatRequest{LeaseToken: job.LeaseToken}, &result); err != nil {
		return factoryImageArtifact{}, err
	}
	if result.SHA256 != digest || result.Size != size || result.Filename != job.Candidate.OutputFilename {
		return factoryImageArtifact{}, errors.New("private image upload result differs")
	}
	return factoryImageArtifact{Key: result.Key, SHA256: result.SHA256, Size: result.Size, Filename: result.Filename}, nil
}

func runFactoryImageJob(parent context.Context, client *Client, cfg Config, job *factoryImageJob) error {
	if job == nil || job.ID == "" || job.LeaseToken == "" || job.Candidate.Architecture != cfg.Architecture {
		return errors.New("private image job does not match worker")
	}
	lease, err := time.Parse(time.RFC3339, job.LeaseExpiry)
	if err != nil || !lease.After(time.Now()) {
		return errors.New("private image lease is expired")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	status := &heartbeatStatus{}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				response, heartbeatErr := client.heartbeatFactoryImage(ctx, job)
				if heartbeatErr != nil {
					fmt.Fprintln(os.Stderr, "image heartbeat:", heartbeatErr)
					continue
				}
				if response.Cancel {
					status.cancelled.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	root, err := os.MkdirTemp(cfg.StateDir, "factory-image-"+job.ID+"-")
	if err != nil {
		return completeFactoryImageFailure(parent, client, job, err)
	}
	defer os.RemoveAll(root)
	_ = os.Chmod(root, 0o700)
	inputs := map[string]factoryImageObject{"profile": job.Candidate.Profile, "candidate-lock": job.Candidate.CandidateLock, "candidate-lock-signature": job.Candidate.CandidateLockSignature, "native-plan": job.Candidate.NativePlan, "native-plan-signature": job.Candidate.NativePlanSignature, "trusted-authority-key": job.Candidate.TrustedAuthorityKey}
	if job.Candidate.Context != nil {
		inputs["context"] = *job.Candidate.Context
	}
	if job.Candidate.Dockerfile != nil {
		inputs["dockerfile"] = *job.Candidate.Dockerfile
	}
	paths := make(map[string]string, len(inputs))
	for name, ref := range inputs {
		path := filepath.Join(root, ref.File)
		if err := client.factoryImageInput(ctx, job.ID, job.LeaseToken, name, path, ref); err != nil {
			return completeFactoryImageFailure(parent, client, job, err)
		}
		paths[name] = path
	}
	if err := verifyFactoryImageSignedInputs(job, paths, cfg); err != nil {
		return completeFactoryImageFailure(parent, client, job, err)
	}
	outputDir := filepath.Join(root, "output")
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return completeFactoryImageFailure(parent, client, job, err)
	}
	output := filepath.Join(outputDir, job.Candidate.OutputFilename)
	provenance := filepath.Join(outputDir, "provenance.json")
	command, cleanup, err := factoryImageBuilderCommand(ctx, cfg, job, root, outputDir)
	if err != nil {
		return completeFactoryImageFailure(parent, client, job, err)
	}
	defer cleanup()
	var outputLog boundedBuffer
	outputLog.limit = maxBuildLogBytes
	command.Stdout = &outputLog
	command.Stderr = &outputLog
	if err := command.Run(); err != nil || status.cancelled.Load() {
		if status.cancelled.Load() {
			err = errors.New("private image build cancelled by coordinator")
		}
		return completeFactoryImageFailure(parent, client, job, fmt.Errorf("private image build: %v\n%s", err, outputLog.String()))
	}
	digest, size, err := hashFile(output)
	if err != nil {
		return completeFactoryImageFailure(parent, client, job, err)
	}
	file, err := os.Open(output)
	if err != nil {
		return completeFactoryImageFailure(parent, client, job, err)
	}
	artifact, uploadErr := client.uploadFactoryImage(ctx, job, file, size, digest)
	_ = file.Close()
	if uploadErr != nil {
		return completeFactoryImageFailure(parent, client, job, uploadErr)
	}
	observed, err := os.ReadFile(provenance)
	if job.Candidate.Kind == "oci" && os.IsNotExist(err) {
		observed = []byte(fmt.Sprintf(`{"builder":"buildah","outputSha256":%q}`, digest))
		err = nil
	}
	if err != nil {
		return completeFactoryImageFailure(parent, client, job, err)
	}
	imageRef := (*string)(nil)
	if job.Candidate.ImageRef != "" {
		value := job.Candidate.ImageRef
		imageRef = &value
	}
	evidence := factoryImageEvidence{SchemaVersion: 1, Kind: "factory-image-result", JobID: job.ID, RunID: job.RunID, Attempt: job.Attempt, CandidateID: job.Candidate.ID, Architecture: job.Candidate.Architecture, ImageKind: job.Candidate.Kind, ImageRef: imageRef, InputSHA256: job.InputSHA256, ProfileSHA256: job.Candidate.Profile.SHA256, NativePlanSHA256: job.Candidate.NativePlan.SHA256, Artifact: artifact, BuilderSHA256: job.Candidate.Builder.SHA256, Observed: json.RawMessage(bytes.TrimSpace(observed))}
	evidenceBytes, err := json.Marshal(evidence)
	if err != nil {
		return completeFactoryImageFailure(parent, client, job, err)
	}
	key, err := decodePrivateKey(cfg.PrivateKey)
	if err != nil {
		return completeFactoryImageFailure(parent, client, job, err)
	}
	if err := client.completeFactoryImage(parent, job, factoryImageCompletion{LeaseToken: job.LeaseToken, Status: "succeeded", Evidence: string(evidenceBytes), EvidenceSignature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, evidenceBytes))}); err != nil {
		return err
	}
	return nil
}

func factoryImageBuilderCommand(ctx context.Context, cfg Config, job *factoryImageJob, inputDir, outputDir string) (*exec.Cmd, func(), error) {
	if cfg.Image == "" || cfg.ImageDigest == "" {
		return nil, func() {}, errors.New("private image builder requires a pinned worker image")
	}
	if !factoryImageSupported(cfg) {
		return nil, func() {}, errors.New("private image worker prerequisites are unavailable")
	}
	name := "opr-image-" + strings.ReplaceAll(job.ID, "_", "-")
	args := []string{"run", "--rm", "--name", name, "--pull=never", "--network=none", "--read-only"}
	if job.Candidate.Kind == "system" {
		// The mounted-filesystem assembler needs loop/mount access inside its container.
		args = append(args, "--privileged")
	}
	args = append(args, "--tmpfs", "/tmp:rw,nosuid,nodev", "--tmpfs", "/run:rw,nosuid,nodev", "-v", inputDir+":/opr/input:ro", "-v", outputDir+":/opr/output:rw", "-v", cfg.FactoryImageBuilderPath+":/opr/builder/image-builder:ro", cfg.Image, "/bin/bash", "/opr/builder/image-builder",
		"--candidate-lock", "/opr/input/"+job.Candidate.CandidateLock.File, "--candidate-lock-signature", "/opr/input/"+job.Candidate.CandidateLockSignature.File, "--candidate-id", job.Candidate.ID,
		"--native-plan", "/opr/input/"+job.Candidate.NativePlan.File, "--native-plan-signature", "/opr/input/"+job.Candidate.NativePlanSignature.File, "--key", "/opr/input/"+job.Candidate.TrustedAuthorityKey.File,
		"--fingerprint", job.Candidate.TrustedAuthorityFingerprint, "--profile", "/opr/input/"+job.Candidate.Profile.File, "--output", "/opr/output/"+job.Candidate.OutputFilename, "--provenance", "/opr/output/provenance.json", "--work-dir", "/opr/output/work")
	if job.Candidate.Kind == "oci" {
		if job.Candidate.Context == nil || job.Candidate.Dockerfile == nil {
			return nil, func() {}, errors.New("OCI image job is missing reviewed context inputs")
		}
		args = append(args, "--context", "/opr/input/"+job.Candidate.Context.File, "--dockerfile", "/opr/input/"+job.Candidate.Dockerfile.File)
	}
	command := exec.CommandContext(ctx, cfg.Runtime, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=/tmp", "LANG=C", "LC_ALL=C", "TZ=UTC", "SOURCE_DATE_EPOCH=" + fmt.Sprint(job.Candidate.SourceDateEpoch), "OMAPKG_IMAGE_CLEAN_ENV=1"}
	cleanup := func() {
		cleanup := exec.CommandContext(context.Background(), cfg.Runtime, "rm", "-f", name)
		_ = cleanup.Run()
	}
	return command, cleanup, nil
}

func verifyFactoryImageSignedInputs(job *factoryImageJob, paths map[string]string, cfg Config) error {
	builderDigest, _, err := hashFile(cfg.FactoryImageBuilderPath)
	if err != nil || builderDigest != job.Candidate.Builder.SHA256 || builderDigest != cfg.FactoryImageBuilderSHA256 {
		return errors.New("operator image builder digest differs from reviewed candidate")
	}
	lock, err := canonicalJSONFile(paths["candidate-lock"])
	if err != nil {
		return fmt.Errorf("read candidate lock: %w", err)
	}
	plan, err := canonicalJSONFile(paths["native-plan"])
	if err != nil {
		return fmt.Errorf("read native plan: %w", err)
	}
	profile, err := canonicalJSONFile(paths["profile"])
	if err != nil {
		return fmt.Errorf("read image profile: %w", err)
	}
	if digest := hashBytes(lock); digest != job.Candidate.CandidateLock.SHA256 {
		return errors.New("candidate lock digest differs from reviewed input")
	}
	if digest := hashBytes(plan); digest != job.Candidate.NativePlan.SHA256 {
		return errors.New("native plan digest differs from reviewed input")
	}
	if digest := hashBytes(profile); digest != job.Candidate.Profile.SHA256 {
		return errors.New("image profile digest differs from reviewed input")
	}
	if stringField(lock, "authority") != "factory-candidate-v1" || stringField(lock, "candidate.executionScope") != "private" || stringField(lock, "candidate.id") != job.Candidate.ID || stringField(lock, "architecture") != job.Candidate.Architecture {
		return errors.New("candidate lock does not bind the private image candidate")
	}
	requiredOperation := "boot"
	if job.Candidate.Kind == "oci" {
		requiredOperation = "install"
	}
	if stringField(lock, "candidate.nativePlanSha256") != job.Candidate.NativePlan.SHA256 || stringField(plan, "kind") != "factory-image-native-plan" || stringField(plan, "status") != "reviewed" || stringField(plan, "operation") != requiredOperation || stringField(plan, "nativePlanId") != job.Candidate.NativePlanID || stringField(plan, "candidateId") != job.Candidate.ID || stringField(plan, "architecture") != job.Candidate.Architecture || stringField(plan, "qualificationPlanSha256") == "" || stringField(plan, "profileSha256") != job.Candidate.Profile.SHA256 {
		return errors.New("native plan does not bind the private image candidate")
	}
	if stringField(profile, "architecture") != job.Candidate.Architecture {
		return errors.New("image profile architecture differs from worker target")
	}
	if err := verifyFactoryImageSignature(paths["candidate-lock"], paths["candidate-lock-signature"], paths["trusted-authority-key"], job.Candidate.TrustedAuthorityFingerprint); err != nil {
		return fmt.Errorf("candidate lock signature: %w", err)
	}
	if err := verifyFactoryImageSignature(paths["native-plan"], paths["native-plan-signature"], paths["trusted-authority-key"], job.Candidate.TrustedAuthorityFingerprint); err != nil {
		return fmt.Errorf("native plan signature: %w", err)
	}
	return nil
}

func canonicalJSONFile(filename string) ([]byte, error) {
	body, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func stringField(body []byte, path string) string {
	var value any
	if json.Unmarshal(body, &value) != nil {
		return ""
	}
	for _, part := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return ""
		}
		value = object[part]
	}
	result, _ := value.(string)
	return result
}

func verifyFactoryImageSignature(payload, signature, publicKey, fingerprint string) error {
	home, err := os.MkdirTemp("", "opr-image-gpg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(home)
	if err := os.Chmod(home, 0o700); err != nil {
		return err
	}
	if output, err := exec.Command("gpg", "--batch", "--no-tty", "--homedir", home, "--import", publicKey).CombinedOutput(); err != nil {
		return fmt.Errorf("import authority key: %w: %s", err, strings.TrimSpace(string(output)))
	}
	output, err := exec.Command("gpg", "--batch", "--no-tty", "--status-fd=1", "--homedir", home, "--verify", signature, payload).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "[GNUPG:] VALIDSIG "+strings.ToUpper(fingerprint)) {
		return errors.New("authority signature is invalid")
	}
	return nil
}

func completeFactoryImageFailure(ctx context.Context, client *Client, job *factoryImageJob, cause error) error {
	message := compactError(cause)
	if err := client.completeFactoryImage(ctx, job, factoryImageCompletion{LeaseToken: job.LeaseToken, Status: "failed", Error: message}); err != nil {
		return fmt.Errorf("%s; completion: %w", message, err)
	}
	return cause
}

func urlPath(value string) string { return strings.NewReplacer("/", "%2F", " ", "%20").Replace(value) }
func urlQuery(value string) string {
	return strings.NewReplacer("%", "%25", " ", "%20", "/", "%2F", ":", "%3A").Replace(value)
}
func hexBytes(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = digits[item>>4]
		result[index*2+1] = digits[item&15]
	}
	return string(result)
}

// Command qualification runs one reviewed native test plan and emits a
// worker-signed observation. It deliberately has no success flag: pass is
// possible only after every planned command ran and observed bytes match the
// plan's expected observation digest.
package qualification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

type plan struct {
	SchemaVersion             int                    `json:"schemaVersion"`
	CohortID                  string                 `json:"cohortId"`
	Revision                  int                    `json:"revision"`
	Operation                 string                 `json:"operation"`
	Architecture              string                 `json:"architecture"`
	CandidateSHA256           string                 `json:"candidateSha256"`
	InputSHA256               string                 `json:"inputSha256"`
	ArtifactSHA256            string                 `json:"artifactSha256"`
	EnvironmentSHA256         string                 `json:"environmentSha256"`
	Profile                   profile                `json:"profile"`
	Coverage                  coverage               `json:"coverage"`
	Commands                  []command              `json:"commands"`
	Observations              []observation          `json:"observations"`
	ExpectedObservationSHA256 string                 `json:"expectedObservationSha256"`
	Expected                  map[string]interface{} `json:"expected"`
}

type profile struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}
type coverage struct {
	Kind       string   `json:"kind"`
	Pkgbase    *string  `json:"pkgbase"`
	RootSHA256 *string  `json:"rootSha256"`
	ReleaseID  *string  `json:"releaseId"`
	Members    []string `json:"members"`
	SHA256     string   `json:"sha256"`
}
type command struct {
	Name             string   `json:"name"`
	Executable       string   `json:"executable"`
	Arguments        []string `json:"arguments"`
	WorkingDirectory string   `json:"workingDirectory,omitempty"`
	TimeoutSeconds   int      `json:"timeoutSeconds,omitempty"`
}
type observation struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Kind string `json:"kind"`
}
type commandResult struct {
	Name         string `json:"name"`
	ExitCode     int    `json:"exitCode"`
	Passed       bool   `json:"passed"`
	StdoutSHA256 string `json:"stdoutSha256"`
	StderrSHA256 string `json:"stderrSha256"`
}
type machine struct {
	Architecture string `json:"architecture"`
	Goarch       string `json:"goarch"`
	Goos         string `json:"goos"`
	Runtime      string `json:"runtime"`
}
type environment struct {
	SHA256  string                 `json:"sha256"`
	Machine machine                `json:"machine"`
	Details map[string]interface{} `json:"details"`
}
type result struct {
	StartedAt  string          `json:"startedAt"`
	FinishedAt string          `json:"finishedAt"`
	ExitCode   int             `json:"exitCode"`
	Commands   []commandResult `json:"commands"`
}
type observedFile struct {
	Name   string      `json:"name"`
	Kind   string      `json:"kind"`
	SHA256 string      `json:"sha256"`
	Size   int         `json:"size"`
	Value  interface{} `json:"value,omitempty"`
}
type observed struct {
	Files  []observedFile         `json:"files"`
	States map[string]interface{} `json:"states"`
}
type reproOutput struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
}
type reproAttempt struct {
	BuildID        string        `json:"buildId"`
	Attempt        int           `json:"attempt"`
	WorkerID       string        `json:"workerId"`
	ArtifactSHA256 string        `json:"artifactSha256"`
	Outputs        []reproOutput `json:"outputs"`
}
type reproReport struct {
	Status    string       `json:"status"`
	Primary   reproAttempt `json:"primary"`
	Secondary reproAttempt `json:"secondary"`
}
type evidence struct {
	SchemaVersion   int                    `json:"schemaVersion"`
	PlanID          string                 `json:"planId"`
	TestPlanSHA256  string                 `json:"testPlanSha256"`
	CohortID        string                 `json:"cohortId"`
	Revision        int                    `json:"revision"`
	Operation       string                 `json:"operation"`
	Architecture    string                 `json:"architecture"`
	Candidate       map[string]string      `json:"candidate"`
	Input           map[string]string      `json:"input"`
	Artifact        map[string]string      `json:"artifact"`
	Environment     environment            `json:"environment"`
	Profile         profile                `json:"profile"`
	Coverage        coverage               `json:"coverage"`
	Command         map[string]string      `json:"command"`
	Result          result                 `json:"result"`
	Observed        map[string]interface{} `json:"observed"`
	ObservedSHA256  string                 `json:"observedSha256"`
	Reproducibility *reproReport           `json:"reproducibility,omitempty"`
	WorkerID        string                 `json:"workerId"`
	WorkerPublicKey string                 `json:"workerPublicKey"`
	Signature       string                 `json:"signature"`
}

type envelope struct {
	PlanID         string `json:"planId"`
	TestPlanSHA256 string `json:"testPlanSha256"`
	Plan           plan   `json:"plan"`
}

type artifactReference struct {
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
	Path     string `json:"path"`
}

type planResponse struct {
	PlanID         string              `json:"planId"`
	TestPlanSHA256 string              `json:"testPlanSha256"`
	Plan           plan                `json:"plan"`
	Artifacts      []artifactReference `json:"artifacts"`
}

type workerConfig struct {
	Origin     string `json:"origin"`
	WorkerID   string `json:"workerId"`
	PrivateKey string `json:"privateKey"`
	StateDir   string `json:"stateDir"`
}

const (
	maxCommandOutput    = 1 << 20
	maxObservationBytes = 4 << 20
)

type boundedBuffer struct {
	bytes    []byte
	overflow bool
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if len(b.bytes)+len(value) > maxCommandOutput {
		b.overflow = true
		return 0, errors.New("qualification command output exceeds its limit")
	}
	b.bytes = append(b.bytes, value...)
	return len(value), nil
}

func Run(args []string) error {
	flags := flag.NewFlagSet("qualification", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	planPath := flags.String("plan", "", "reviewed qualification plan envelope")
	origin := flags.String("origin", "", "coordinator origin; fetches plan when --plan is omitted")
	planID := flags.String("plan-id", "", "reviewed plan id to fetch from coordinator")
	submit := flags.Bool("submit", false, "submit signed evidence to coordinator after writing it")
	keyPath := flags.String("key-file", "", "worker Ed25519 private key file (base64 or raw 64 bytes)")
	configPath := flags.String("config", "", "worker config; supplies origin, worker id, key, and state directory")
	workerID := flags.String("worker-id", "", "registered worker id")
	workDir := flags.String("work-dir", "", "private test working directory")
	outputPath := flags.String("output", "", "signed evidence output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	var config workerConfig
	if *configPath != "" {
		if info, statErr := os.Stat(*configPath); statErr != nil || info.Mode().Perm()&0o077 != 0 {
			return errors.New("worker config must be private")
		}
		bytes, err := os.ReadFile(*configPath)
		if err != nil {
			return fmt.Errorf("read worker config: %w", err)
		}
		if err := json.Unmarshal(bytes, &config); err != nil {
			return fmt.Errorf("decode worker config: %w", err)
		}
		if *origin == "" {
			*origin = config.Origin
		}
		if *workerID == "" {
			*workerID = config.WorkerID
		}
		if *workDir == "" {
			*workDir = config.StateDir
		}
	}
	if *keyPath == "" && config.PrivateKey == "" {
		return errors.New("key-file or config is required")
	}
	if (*planPath == "") == (*origin == "" || *planID == "") || *workerID == "" {
		return errors.New("provide either plan or origin plus plan-id, with key-file or config, worker-id, and output")
	}
	if *outputPath == "" {
		if *workDir == "" {
			return errors.New("output is required")
		}
		*outputPath = filepath.Join(*workDir, "qualification.json")
	}
	var key ed25519.PrivateKey
	var err error
	if *keyPath != "" {
		key, err = readPrivateKey(*keyPath)
	} else {
		key, err = decodePrivateKey([]byte(config.PrivateKey))
	}
	if err != nil {
		return err
	}
	var input envelope
	var artifacts []artifactReference
	if *planPath != "" {
		envelopeBytes, err := os.ReadFile(*planPath)
		if err != nil {
			return fmt.Errorf("read plan: %w", err)
		}
		if err := json.Unmarshal(envelopeBytes, &input); err != nil {
			return fmt.Errorf("decode plan: %w", err)
		}
	} else {
		fetched, err := fetchPlan(*origin, *planID, *workerID, key)
		if err != nil {
			return err
		}
		input = envelope{PlanID: fetched.PlanID, TestPlanSHA256: fetched.TestPlanSHA256, Plan: fetched.Plan}
		artifacts = fetched.Artifacts
	}
	if input.Plan.SchemaVersion != 1 || input.PlanID == "" || input.TestPlanSHA256 == "" {
		return errors.New("invalid plan envelope")
	}
	if digestJSON(input.Plan) != input.TestPlanSHA256 {
		return errors.New("reviewed test plan digest does not match plan bytes")
	}
	if err := validatePlan(input.Plan); err != nil {
		return err
	}
	workRoot := *workDir
	if workRoot != "" {
		if err := os.MkdirAll(workRoot, 0o700); err != nil {
			return err
		}
	} else {
		workRoot = os.TempDir()
	}
	*workDir, err = os.MkdirTemp(workRoot, "opr-qualification-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(*workDir)
	if info, err := os.Stat(*workDir); err != nil || !info.IsDir() {
		return errors.New("work directory is not a directory")
	}
	for _, artifact := range artifacts {
		if err := fetchArtifact(*origin, input.PlanID, artifact, *workerID, key, *workDir); err != nil {
			return err
		}
	}
	started := time.Now().UTC()
	results := make([]commandResult, 0, len(input.Plan.Commands))
	exitCode := 0
	for _, spec := range input.Plan.Commands {
		commandResult, err := runCommand(*workDir, spec)
		if err != nil && exitCode == 0 {
			exitCode = commandResult.ExitCode
			if exitCode == 0 {
				exitCode = 1
			}
		}
		results = append(results, commandResult)
	}
	observedValue, observationDigest, err := collectObservations(*workDir, input.Plan.Observations)
	if err != nil {
		if exitCode == 0 {
			return err
		}
		observedValue = observed{}
		observationDigest = digestJSON(map[string]interface{}{"files": []observedFile{}, "states": map[string]interface{}{}})
	}
	if exitCode == 0 && observationDigest != input.Plan.ExpectedObservationSHA256 {
		exitCode = 1
	}
	finished := time.Now().UTC()
	arch, goarch, err := nativeArchitecture(input.Plan.Architecture)
	if err != nil {
		return err
	}
	details := map[string]interface{}{"profileId": input.Plan.Profile.ID, "operation": input.Plan.Operation}
	if expected, ok := input.Plan.Expected["environment"].(map[string]interface{}); ok {
		details = expected
	}
	envValue := environment{Machine: machine{Architecture: arch, Goarch: goarch, Goos: runtime.GOOS, Runtime: runtime.Version()}, Details: details}
	envValue.SHA256 = digestJSON(map[string]interface{}{"machine": envValue.Machine, "details": envValue.Details})
	if envValue.SHA256 != input.Plan.EnvironmentSHA256 {
		return errors.New("native environment does not match reviewed environment digest")
	}
	observedMap := map[string]interface{}{"files": observedValue.Files, "states": observedValue.States}
	report := evidence{SchemaVersion: 1, PlanID: input.PlanID, TestPlanSHA256: input.TestPlanSHA256, CohortID: input.Plan.CohortID, Revision: input.Plan.Revision, Operation: input.Plan.Operation, Architecture: arch,
		Candidate: map[string]string{"sha256": input.Plan.CandidateSHA256}, Input: map[string]string{"sha256": input.Plan.InputSHA256}, Artifact: map[string]string{"sha256": input.Plan.ArtifactSHA256}, Environment: envValue, Profile: input.Plan.Profile, Coverage: input.Plan.Coverage,
		Command: map[string]string{"sha256": digestJSON(input.Plan.Commands)}, Result: result{StartedAt: started.Format(time.RFC3339Nano), FinishedAt: finished.Format(time.RFC3339Nano), ExitCode: exitCode, Commands: results}, Observed: observedMap, ObservedSHA256: observationDigest, WorkerID: *workerID, WorkerPublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	if input.Plan.Operation == "reproducibility" {
		report.Reproducibility = buildReproReport(input.Plan, observedValue, *workerID)
	}
	if input.Plan.Operation == "reproducibility" {
		if report.Reproducibility.Status == "verified-reproducible" && exitCode != 0 {
			report.Reproducibility.Status = "not-checked"
		}
	}
	payload := report
	payload.Signature = ""
	payloadBytes := canonicalJSON(payloadWithoutSignature(payload))
	report.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payloadBytes))
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outputPath, encoded, 0o600); err != nil {
		return err
	}
	if *submit {
		if *origin == "" {
			return errors.New("--submit requires --origin")
		}
		if err := submitEvidence(*origin, encoded, *workerID, key); err != nil {
			return err
		}
	}
	if exitCode != 0 {
		return fmt.Errorf("qualification commands or observations failed")
	}
	return nil
}

func validatePlan(value plan) error {
	if value.Architecture != "x86_64" && value.Architecture != "aarch64" {
		return errors.New("plan architecture is invalid")
	}
	if value.Operation != "install" && value.Operation != "upgrade" && value.Operation != "recovery" && value.Operation != "boot" && value.Operation != "reproducibility" {
		return errors.New("plan operation is invalid")
	}
	for _, digestValue := range []string{value.CandidateSHA256, value.InputSHA256, value.ArtifactSHA256, value.EnvironmentSHA256, value.Profile.SHA256, value.ExpectedObservationSHA256} {
		if !isDigest(digestValue) {
			return errors.New("plan contains an invalid digest")
		}
	}
	if value.Coverage.Kind != "member" && value.Coverage.Kind != "system" || value.Coverage.Kind == "member" && (value.Coverage.Pkgbase == nil || value.Coverage.RootSHA256 != nil || value.Coverage.ReleaseID != nil) || value.Coverage.Kind == "system" && (value.Coverage.Pkgbase != nil || value.Coverage.RootSHA256 == nil || value.Coverage.ReleaseID == nil || *value.Coverage.ReleaseID == "") || !isDigest(value.Coverage.SHA256) || len(value.Coverage.Members) == 0 || len(value.Coverage.Members) > 100000 {
		return errors.New("plan coverage is invalid")
	}
	if digestJSON(map[string]interface{}{"kind": value.Coverage.Kind, "pkgbase": value.Coverage.Pkgbase, "rootSha256": value.Coverage.RootSHA256, "releaseId": value.Coverage.ReleaseID, "members": value.Coverage.Members, "artifactSha256": value.ArtifactSHA256}) != value.Coverage.SHA256 {
		return errors.New("plan coverage digest does not match plan bytes")
	}
	if len(value.Commands) == 0 || len(value.Commands) > 32 || len(value.Observations) == 0 || len(value.Observations) > 32 {
		return errors.New("plan command or observation budget exceeded")
	}
	seen := map[string]bool{}
	for _, command := range value.Commands {
		if command.Name == "" || len(command.Name) > 128 || seen[command.Name] || !strings.HasPrefix(command.Executable, "/") || len(command.Executable) > 256 || len(command.Arguments) > 64 || command.TimeoutSeconds < 0 || command.TimeoutSeconds > 3600 || filepath.IsAbs(command.WorkingDirectory) || strings.Contains(command.WorkingDirectory, "..") {
			return errors.New("plan command is invalid")
		}
		for _, argument := range command.Arguments {
			if len(argument) > 4096 || strings.IndexByte(argument, 0) >= 0 {
				return errors.New("plan command argument is invalid")
			}
		}
		seen[command.Name] = true
	}
	seen = map[string]bool{}
	for _, observation := range value.Observations {
		if observation.Name == "" || len(observation.Name) > 128 || seen[observation.Name] || observation.Path == "" || len(observation.Path) > 512 || filepath.IsAbs(observation.Path) || strings.Contains(observation.Path, "..") || (observation.Kind != "package-state" && observation.Kind != "manifest" && observation.Kind != "boot-state" && observation.Kind != "recovery-state" && observation.Kind != "text") {
			return errors.New("plan observation is invalid")
		}
		seen[observation.Name] = true
	}
	return nil
}

func nativeArchitecture(expected string) (string, string, error) {
	goarch := runtime.GOARCH
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[goarch]
	if arch == "" || arch != expected || runtime.GOOS != "linux" {
		return "", "", errors.New("qualification command is not running on the reviewed native Linux architecture")
	}
	return arch, goarch, nil
}

func runCommand(workDir string, spec command) (commandResult, error) {
	limit := time.Duration(spec.TimeoutSeconds) * time.Second
	if limit <= 0 {
		limit = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.Command(spec.Executable, spec.Arguments...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cwd := workDir
	if spec.WorkingDirectory != "" {
		cwd = filepath.Join(workDir, spec.WorkingDirectory)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		return commandResult{Name: spec.Name, ExitCode: 1}, err
	}
	resolvedCWD, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return commandResult{Name: spec.Name, ExitCode: 1}, err
	}
	relativeCWD, err := filepath.Rel(workDir, resolvedCWD)
	if err != nil || relativeCWD == ".." || strings.HasPrefix(relativeCWD, ".."+string(filepath.Separator)) {
		return commandResult{Name: spec.Name, ExitCode: 1}, errors.New("command working directory escapes the private work directory")
	}
	cwd = resolvedCWD
	cmd.Dir = cwd
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + workDir, "LANG=C", "LC_ALL=C", "TZ=UTC"}
	var stdout, stderr boundedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		err = <-done
	}
	exitCode := 0
	passed := err == nil && ctx.Err() == nil && !stdout.overflow && !stderr.overflow
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		}
		if ctx.Err() != nil {
			exitCode = 124
		}
	}
	if stdout.overflow || stderr.overflow {
		return commandResult{Name: spec.Name, ExitCode: 1, Passed: false, StdoutSHA256: digestBytes(stdout.bytes), StderrSHA256: digestBytes(stderr.bytes)}, errors.New("qualification command output exceeds its limit")
	}
	return commandResult{Name: spec.Name, ExitCode: exitCode, Passed: passed, StdoutSHA256: digestBytes(stdout.bytes), StderrSHA256: digestBytes(stderr.bytes)}, err
}

func collectObservations(workDir string, specs []observation) (observed, string, error) {
	files := make([]observedFile, 0, len(specs))
	states := map[string]interface{}{}
	for _, spec := range specs {
		path := filepath.Join(workDir, spec.Path)
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return observed{}, "", fmt.Errorf("resolve observation %s: %w", spec.Name, err)
		}
		relative, err := filepath.Rel(workDir, resolved)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return observed{}, "", errors.New("observation path escapes the private work directory")
		}
		file, err := os.Open(resolved)
		if err != nil {
			return observed{}, "", fmt.Errorf("read observation %s: %w", spec.Name, err)
		}
		bytes, err := io.ReadAll(io.LimitReader(file, maxObservationBytes+1))
		_ = file.Close()
		if err != nil {
			return observed{}, "", fmt.Errorf("read observation %s: %w", spec.Name, err)
		}
		if len(bytes) > maxObservationBytes {
			return observed{}, "", errors.New("qualification observation exceeds its limit")
		}
		item := observedFile{Name: spec.Name, Kind: spec.Kind, SHA256: digestBytes(bytes), Size: len(bytes)}
		if spec.Kind == "package-state" || spec.Kind == "boot-state" || spec.Kind == "recovery-state" {
			var value interface{}
			if err := json.Unmarshal(bytes, &value); err != nil {
				return observed{}, "", fmt.Errorf("decode observation %s: %w", spec.Name, err)
			}
			item.Value = value
			states[spec.Name] = value
		}
		files = append(files, item)
	}
	return observed{Files: files, States: states}, digestJSON(map[string]interface{}{"files": files, "states": states}), nil
}

func buildReproReport(value plan, observations observed, workerID string) *reproReport {
	primary := reproAttempt{BuildID: stringExpected(value.Expected, "primaryBuildId"), Attempt: intExpected(value.Expected, "primaryAttempt"), WorkerID: stringExpected(value.Expected, "primaryWorkerId"), ArtifactSHA256: stringExpected(value.Expected, "primaryArtifactSha256")}
	secondary := reproAttempt{BuildID: stringExpected(value.Expected, "secondaryBuildId"), Attempt: intExpected(value.Expected, "secondaryAttempt"), WorkerID: workerID}
	for _, file := range observations.Files {
		output := reproOutput{Filename: file.Name, SHA256: file.SHA256}
		secondary.Outputs = append(secondary.Outputs, output)
	}
	secondary.ArtifactSHA256 = digestJSON(secondary.Outputs)
	if expected, ok := value.Expected["primaryOutputs"].([]interface{}); ok {
		for _, item := range expected {
			if object, ok := item.(map[string]interface{}); ok {
				primary.Outputs = append(primary.Outputs, reproOutput{Filename: stringExpected(object, "filename"), SHA256: stringExpected(object, "sha256")})
			}
		}
	}
	status := "mismatch"
	if digestJSON(primary.Outputs) == digestJSON(secondary.Outputs) {
		status = "verified-reproducible"
	}
	if expected, ok := value.Expected["reproducibilityStatus"].(string); ok && expected == "not-checked" {
		status = expected
	}
	return &reproReport{Status: status, Primary: primary, Secondary: secondary}
}

func stringExpected(value map[string]interface{}, key string) string {
	if result, ok := value[key].(string); ok {
		return result
	}
	return ""
}
func intExpected(value map[string]interface{}, key string) int {
	if result, ok := value[key].(float64); ok {
		return int(result)
	}
	return 0
}

func fetchPlan(origin, planID, workerID string, key ed25519.PrivateKey) (planResponse, error) {
	path := "/api/worker/qualification?planId=" + url.QueryEscape(planID)
	response, err := signedHTTP(origin, http.MethodGet, path, nil, workerID, key)
	if err != nil {
		return planResponse{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return planResponse{}, httpStatusError(response)
	}
	bytes, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return planResponse{}, err
	}
	var result planResponse
	if err := json.Unmarshal(bytes, &result); err != nil {
		return planResponse{}, fmt.Errorf("decode coordinator plan: %w", err)
	}
	if result.PlanID != planID || result.TestPlanSHA256 == "" {
		return planResponse{}, errors.New("coordinator returned a different qualification plan")
	}
	return result, nil
}

func fetchArtifact(origin, planID string, artifact artifactReference, workerID string, key ed25519.PrivateKey, workDir string) error {
	if artifact.Filename == "" || filepath.Base(artifact.Filename) != artifact.Filename || !strings.HasSuffix(artifact.Filename, ".pkg.tar.zst") || !isDigest(artifact.SHA256) || artifact.Size <= 0 || artifact.Path == "" || !strings.HasPrefix(artifact.Path, "/api/worker/qualification/artifacts/") {
		return errors.New("coordinator returned an invalid qualification artifact")
	}
	response, err := signedHTTP(origin, http.MethodGet, artifact.Path, nil, workerID, key)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return httpStatusError(response)
	}
	bytes, err := io.ReadAll(io.LimitReader(response.Body, int64(artifact.Size)+1))
	if err != nil {
		return err
	}
	if len(bytes) != artifact.Size || digestBytes(bytes) != artifact.SHA256 {
		return errors.New("qualification artifact checksum does not match the reviewed output")
	}
	return os.WriteFile(filepath.Join(workDir, artifact.Filename), bytes, 0o600)
}

func submitEvidence(origin string, body []byte, workerID string, key ed25519.PrivateKey) error {
	response, err := signedHTTP(origin, http.MethodPost, "/api/worker/qualification", body, workerID, key)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return httpStatusError(response)
	}
	return nil
}

func signedHTTP(origin, method, requestPath string, body []byte, workerID string, key ed25519.PrivateKey) (*http.Response, error) {
	base, err := url.Parse(origin)
	if err != nil || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Scheme != "https" && !isLoopback(base.Hostname())) {
		return nil, errors.New("coordinator origin must be HTTPS or loopback HTTP")
	}
	u, err := url.Parse(requestPath)
	if err != nil || !strings.HasPrefix(u.Path, "/") || u.Host != "" {
		return nil, errors.New("qualification request path is invalid")
	}
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceBytes)
	bodyHash := digestBytes(body)
	signature := ed25519.Sign(key, []byte(strings.ToUpper(method)+"\n"+u.EscapedPath()+func() string {
		if u.RawQuery != "" {
			return "?" + u.RawQuery
		}
		return ""
	}()+"\n"+timestamp+"\n"+nonce+"\n"+bodyHash))
	target := *base
	target.Path = strings.TrimRight(base.Path, "/") + u.Path
	target.RawQuery = u.RawQuery
	request, err := http.NewRequest(method, target.String(), strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	if body == nil {
		request.Body = http.NoBody
	}
	request.Header.Set("X-OPR-Worker", workerID)
	request.Header.Set("X-OPR-Timestamp", timestamp)
	request.Header.Set("X-OPR-Nonce", nonce)
	request.Header.Set("X-OPR-Signature", base64.StdEncoding.EncodeToString(signature))
	request.Header.Set("Content-Type", "application/json")
	return (&http.Client{Timeout: 60 * time.Second}).Do(request)
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

func httpStatusError(response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 16<<10))
	return fmt.Errorf("coordinator qualification request returned %s: %s", response.Status, strings.TrimSpace(string(body)))
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if info, statErr := os.Stat(path); statErr == nil && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("worker key file must be private")
	}
	return decodePrivateKey(bytes)
}

func decodePrivateKey(bytes []byte) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(string(bytes))
	if decoded, decodeErr := base64.StdEncoding.DecodeString(trimmed); decodeErr == nil && len(decoded) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(decoded), nil
	}
	if len(bytes) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(bytes), nil
	}
	return nil, errors.New("worker key must be a raw or base64 Ed25519 private key")
}
func isDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func digestBytes(value []byte) string     { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func digestJSON(value interface{}) string { return digestBytes(canonicalJSON(value)) }

func canonicalJSON(value interface{}) []byte {
	return canonicalValue(value)
}
func canonicalValue(value interface{}) []byte {
	switch value := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				b.WriteByte(',')
			}
			keyBytes, _ := json.Marshal(key)
			b.Write(keyBytes)
			b.WriteByte(':')
			b.Write(canonicalValue(value[key]))
		}
		b.WriteByte('}')
		return []byte(b.String())
	case []interface{}:
		var b strings.Builder
		b.WriteByte('[')
		for index, item := range value {
			if index > 0 {
				b.WriteByte(',')
			}
			b.Write(canonicalValue(item))
		}
		b.WriteByte(']')
		return []byte(b.String())
	case string, bool, nil, float64, json.Number:
		bytes, _ := json.Marshal(value)
		return bytes
	default:
		bytes, _ := json.Marshal(value)
		var decoded interface{}
		if json.Unmarshal(bytes, &decoded) == nil {
			return canonicalValue(decoded)
		}
		return bytes
	}
}

func payloadWithoutSignature(value evidence) map[string]interface{} {
	bytes, _ := json.Marshal(value)
	var payload map[string]interface{}
	_ = json.Unmarshal(bytes, &payload)
	delete(payload, "signature")
	return payload
}

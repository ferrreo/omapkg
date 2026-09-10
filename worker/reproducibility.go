package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	defaultReproducibilityGap  = 5 * time.Second
	maxReproducibilityOutputs  = 256
	maxReproducibilityLogBytes = 2 << 20
)

const (
	ReproducibilityContractVerified        = "reproducibility-contract-verified"
	ReproducibilityIndependentlyReproduced = "independently-reproduced"
	ReproducibilityMismatch                = "mismatch"
	ReproducibilityNotChecked              = "not-checked"
)

var ErrReproducibilityMismatch = errors.New("reproducibility mismatch")

// ReproducibilityBuild is returned by a real builder invocation. OutputPaths
// must point at files below Root from the request. EvidencePaths may include
// retained input/environment reports below Root.
type ReproducibilityBuild struct {
	OutputPaths   []string
	EvidencePaths []string
	Log           string
	Cleanup       func()
}

type ReproducibilityBuildRequest struct {
	Attempt string
	Root    string
}

type ReproducibilityBuilder func(context.Context, ReproducibilityBuildRequest) (ReproducibilityBuild, error)

type ReproducibilitySpec struct {
	Root              string
	Gap               time.Duration
	PreserveOnSuccess bool
	Build             ReproducibilityBuilder
}

type ReproducibilityOutput struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Path     string `json:"-"`
}

type ReproducibilityEvidence struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	Path     string `json:"-"`
}

type ReproducibilityAttempt struct {
	ID         string                    `json:"id"`
	Root       string                    `json:"root"`
	StartedAt  time.Time                 `json:"startedAt"`
	FinishedAt time.Time                 `json:"finishedAt"`
	Outputs    []ReproducibilityOutput   `json:"outputs"`
	Evidence   []ReproducibilityEvidence `json:"evidence"`
	Log        string                    `json:"log,omitempty"`
}

type ReproducibilityDifference struct {
	Filename        string `json:"filename"`
	Reason          string `json:"reason"`
	PrimarySize     int64  `json:"primarySize,omitempty"`
	SecondarySize   int64  `json:"secondarySize,omitempty"`
	PrimarySHA256   string `json:"primarySha256,omitempty"`
	SecondarySHA256 string `json:"secondarySha256,omitempty"`
	FirstByte       int64  `json:"firstByte"`
}

type ReproducibilityPair struct {
	SchemaVersion int                         `json:"schemaVersion"`
	Status        string                      `json:"status"`
	Gap           time.Duration               `json:"gap"`
	Primary       ReproducibilityAttempt      `json:"primary"`
	Secondary     ReproducibilityAttempt      `json:"secondary"`
	Differences   []ReproducibilityDifference `json:"differences,omitempty"`
	FailureRoot   string                      `json:"failureRoot,omitempty"`
}

// singleBuildObservation records checks performed during one normal build.
// It intentionally does not claim that another execution matched its bytes.
type singleBuildObservation struct {
	ArchivePathsInspected          bool
	ArchiveMetadataInspected       bool
	TimestampOwnershipOrderChecked bool
	UnexpectedOutputs              []string
	ProhibitedPaths                []string
}

func singleBuildContract(job Job, outputs []ReproducibilityOutput, observation *singleBuildObservation) map[string]any {
	inputLock := ""
	if job.InputLock != nil {
		inputLock = job.InputLock.SHA256
	}
	dependencyPlan := ""
	if job.DependencyPlan != nil {
		if encoded, err := canonicalReproJSON(job.DependencyPlan); err == nil {
			dependencyPlan = hashBytes(encoded)
		}
	}
	encodedOutputs, _ := canonicalReproJSON(reproducibilityOutputDigestValues(outputs))
	archiveInspected := observation != nil && observation.ArchivePathsInspected
	metadataInspected := observation != nil && observation.ArchiveMetadataInspected
	timestampOwnershipOrderChecked := observation != nil && observation.TimestampOwnershipOrderChecked
	unexpected := []string(nil)
	prohibited := []string(nil)
	if observation != nil {
		unexpected = append(unexpected, observation.UnexpectedOutputs...)
		prohibited = append(prohibited, observation.ProhibitedPaths...)
	}
	contract := map[string]any{
		"schemaVersion": 1,
		"status":        ReproducibilityContractVerified,
		"mode":          "single-build",
		"target":        job.Architecture,
		"inputs": map[string]any{
			"recipeSha256":         job.RecipeSHA256,
			"sourceManifestSha256": hashBytes(mustEncodeJSON(job.Sources)),
			"inputLockSha256":      inputLock,
			"dependencyPlanSha256": dependencyPlan,
			"imageDigest":          job.ImageDigest,
			"sourceDateEpoch":      job.SourceDateEpoch,
		},
		"controls": map[string]any{
			"network":                        "disabled",
			"locale":                         "C",
			"timezone":                       "UTC",
			"umask":                          "022",
			"hostSecrets":                    "excluded",
			"writableCaches":                 "excluded",
			"nativeTarget":                   job.Architecture,
			"archivePathsChecked":            archiveInspected,
			"archiveMetadataChecked":         metadataInspected,
			"timestampOwnershipOrderChecked": timestampOwnershipOrderChecked,
		},
		"outputs": map[string]any{
			"setSha256":       hashBytes(encodedOutputs),
			"files":           outputs,
			"unexpected":      unexpected,
			"prohibitedPaths": prohibited,
		},
		"limitations": []string{
			"single execution does not establish independent byte reproduction",
			"static archive inspection cannot prove arbitrary upstream code is deterministic",
		},
	}
	if job.FactoryRunID != "" {
		contract["execution"] = map[string]any{"runId": job.FactoryRunID, "attempt": job.FactoryAttempt, "inputSha256": job.FactoryInputSHA256}
	}
	return contract
}

func reproducibilityOutputDigestValues(outputs []ReproducibilityOutput) []map[string]any {
	values := make([]map[string]any, 0, len(outputs))
	for _, output := range outputs {
		values = append(values, map[string]any{"filename": output.Filename, "sha256": output.SHA256, "size": output.Size})
	}
	return values
}

func mustEncodeJSON(value any) []byte {
	encoded, err := canonicalReproJSON(value)
	if err != nil {
		return []byte("null")
	}
	return encoded
}

func canonicalReproJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized any
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

func reproducibilityArtifactSize(path string) int64 {
	if path == "" {
		return 0
	}
	_, size, err := hashFile(path)
	if err != nil {
		return 0
	}
	return size
}

// RunReproducibilityPair invokes the real builder twice in fresh roots. It
// compares complete output bytes, including metadata, without extraction or
// normalization. A mismatch leaves both roots and their evidence in place.
func RunReproducibilityPair(ctx context.Context, spec ReproducibilitySpec) (ReproducibilityPair, error) {
	if spec.Build == nil {
		return ReproducibilityPair{}, errors.New("reproducibility builder is required")
	}
	gap := spec.Gap
	if gap <= 0 {
		gap = defaultReproducibilityGap
	}
	root := spec.Root
	autoRoot := false
	if root == "" {
		var err error
		root, err = os.MkdirTemp("", "opr-reproducibility-")
		if err != nil {
			return ReproducibilityPair{}, fmt.Errorf("create reproducibility root: %w", err)
		}
		autoRoot = true
	} else if err := os.MkdirAll(root, 0o700); err != nil {
		return ReproducibilityPair{}, fmt.Errorf("create reproducibility root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		if autoRoot {
			_ = os.RemoveAll(root)
		}
		return ReproducibilityPair{}, fmt.Errorf("protect reproducibility root: %w", err)
	}
	resolvedRoot, err := filepath.Abs(root)
	if err != nil {
		if autoRoot {
			_ = os.RemoveAll(root)
		}
		return ReproducibilityPair{}, fmt.Errorf("resolve reproducibility root: %w", err)
	}
	root = resolvedRoot
	primaryRoot, err := os.MkdirTemp(root, "primary-")
	if err != nil {
		if autoRoot {
			_ = os.RemoveAll(root)
		}
		return ReproducibilityPair{}, fmt.Errorf("create primary build root: %w", err)
	}
	secondaryRoot, err := os.MkdirTemp(root, "secondary-")
	if err != nil {
		if autoRoot {
			_ = os.RemoveAll(root)
		}
		return ReproducibilityPair{}, fmt.Errorf("create secondary build root: %w", err)
	}
	primary := ReproducibilityAttempt{ID: "primary", Root: primaryRoot}
	secondary := ReproducibilityAttempt{ID: "secondary", Root: secondaryRoot}

	started := time.Now()
	primary.StartedAt = started.UTC()
	buildA, buildErr := spec.Build(ctx, ReproducibilityBuildRequest{Attempt: primary.ID, Root: primaryRoot})
	finished := time.Now()
	primary.FinishedAt = finished.UTC()
	primary.Log = boundedReproducibilityLog(buildA.Log)
	if buildErr != nil {
		primary.Log = boundedReproducibilityLog(joinReproducibilityError(primary.Log, buildErr))
		_ = writeReproducibilityAttempt(primary)
		result := ReproducibilityPair{SchemaVersion: 1, Status: ReproducibilityNotChecked, Primary: primary, Secondary: secondary, FailureRoot: root}
		_ = writeReproducibilityFailure(root, result)
		return result, fmt.Errorf("primary reproducibility build: %w", buildErr)
	}
	primary.Outputs, primary.Evidence, err = inspectReproducibilityBuild(primaryRoot, buildA)
	if err != nil {
		primary.Log = boundedReproducibilityLog(joinReproducibilityError(primary.Log, err))
		_ = writeReproducibilityAttempt(primary)
		result := ReproducibilityPair{SchemaVersion: 1, Status: ReproducibilityNotChecked, Primary: primary, Secondary: secondary, FailureRoot: root}
		_ = writeReproducibilityFailure(root, result)
		return result, fmt.Errorf("inspect primary reproducibility build: %w", err)
	}
	if err := writeReproducibilityAttempt(primary); err != nil {
		return ReproducibilityPair{}, err
	}

	if err := waitReproducibilityGap(ctx, finished, gap); err != nil {
		result := ReproducibilityPair{SchemaVersion: 1, Status: ReproducibilityNotChecked, Primary: primary, Secondary: secondary, FailureRoot: root}
		_ = writeReproducibilityFailure(root, result)
		return result, err
	}
	secondaryStarted := time.Now()
	secondary.StartedAt = secondaryStarted.UTC()
	buildB, buildErr := spec.Build(ctx, ReproducibilityBuildRequest{Attempt: secondary.ID, Root: secondaryRoot})
	secondaryFinished := time.Now()
	secondary.FinishedAt = secondaryFinished.UTC()
	secondary.Log = boundedReproducibilityLog(buildB.Log)
	result := ReproducibilityPair{SchemaVersion: 1, Primary: primary, Secondary: secondary, Gap: secondaryStarted.Sub(finished)}
	if buildErr != nil {
		secondary.Log = boundedReproducibilityLog(joinReproducibilityError(secondary.Log, buildErr))
		result.Status = ReproducibilityNotChecked
		result.Secondary = secondary
		result.FailureRoot = root
		_ = writeReproducibilityAttempt(secondary)
		_ = writeReproducibilityFailure(root, result)
		return result, fmt.Errorf("secondary reproducibility build: %w", buildErr)
	}
	secondary.Outputs, secondary.Evidence, err = inspectReproducibilityBuild(secondaryRoot, buildB)
	if err != nil {
		secondary.Log = boundedReproducibilityLog(joinReproducibilityError(secondary.Log, err))
		result.Status = ReproducibilityNotChecked
		result.Secondary = secondary
		result.FailureRoot = root
		_ = writeReproducibilityAttempt(secondary)
		_ = writeReproducibilityFailure(root, result)
		return result, fmt.Errorf("inspect secondary reproducibility build: %w", err)
	}
	result.Primary, result.Secondary = primary, secondary
	result.Differences, err = CompareReproducibilityOutputs(primary.Outputs, secondary.Outputs)
	if err != nil {
		result.Status = ReproducibilityNotChecked
		result.FailureRoot = root
		_ = writeReproducibilityAttempt(secondary)
		_ = writeReproducibilityFailure(root, result)
		return result, err
	}
	if len(result.Differences) > 0 {
		result.Status = ReproducibilityMismatch
		result.FailureRoot = root
		_ = writeReproducibilityAttempt(secondary)
		_ = writeReproducibilityFailure(root, result)
		return result, fmt.Errorf("%w: %s", ErrReproducibilityMismatch, result.Differences[0].Filename)
	}
	result.Status = ReproducibilityIndependentlyReproduced
	if err := writeReproducibilityAttempt(secondary); err != nil {
		return ReproducibilityPair{}, err
	}
	if !spec.PreserveOnSuccess {
		if buildA.Cleanup != nil {
			buildA.Cleanup()
		}
		if buildB.Cleanup != nil {
			buildB.Cleanup()
		}
		if autoRoot {
			_ = os.RemoveAll(root)
		}
	}
	return result, nil
}

// CompareReproducibilityOutputs checks complete output sets and final bytes.
// Metadata, archive headers, and payload bytes are compared as one file.
func CompareReproducibilityOutputs(primary, secondary []ReproducibilityOutput) ([]ReproducibilityDifference, error) {
	left := make(map[string]ReproducibilityOutput, len(primary))
	right := make(map[string]ReproducibilityOutput, len(secondary))
	for _, output := range primary {
		if _, ok := left[output.Filename]; ok {
			return nil, fmt.Errorf("duplicate primary output %q", output.Filename)
		}
		left[output.Filename] = output
	}
	for _, output := range secondary {
		if _, ok := right[output.Filename]; ok {
			return nil, fmt.Errorf("duplicate secondary output %q", output.Filename)
		}
		right[output.Filename] = output
	}
	names := make([]string, 0, len(left)+len(right))
	seen := map[string]bool{}
	for name := range left {
		seen[name] = true
		names = append(names, name)
	}
	for name := range right {
		if !seen[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	differences := []ReproducibilityDifference{}
	for _, name := range names {
		first, firstOK := left[name]
		second, secondOK := right[name]
		if !firstOK {
			differences = append(differences, ReproducibilityDifference{Filename: name, Reason: "missing-primary-output", SecondarySize: second.Size, SecondarySHA256: second.SHA256})
			continue
		}
		if !secondOK {
			differences = append(differences, ReproducibilityDifference{Filename: name, Reason: "missing-secondary-output", PrimarySize: first.Size, PrimarySHA256: first.SHA256})
			continue
		}
		difference := ReproducibilityDifference{Filename: name, PrimarySize: first.Size, SecondarySize: second.Size, PrimarySHA256: first.SHA256, SecondarySHA256: second.SHA256}
		if first.Size != second.Size {
			difference.Reason = "size-mismatch"
			differences = append(differences, difference)
			continue
		}
		offset, different, err := firstDifferentByte(first.Path, second.Path)
		if err != nil {
			return nil, fmt.Errorf("compare %s: %w", name, err)
		}
		if different {
			difference.Reason = "byte-mismatch"
			difference.FirstByte = offset
			differences = append(differences, difference)
		} else if first.SHA256 != second.SHA256 {
			difference.Reason = "sha256-mismatch"
			differences = append(differences, difference)
		}
	}
	return differences, nil
}

func inspectReproducibilityBuild(root string, build ReproducibilityBuild) ([]ReproducibilityOutput, []ReproducibilityEvidence, error) {
	if len(build.OutputPaths) == 0 || len(build.OutputPaths) > maxReproducibilityOutputs {
		return nil, nil, errors.New("reproducibility build must produce one to 256 outputs")
	}
	outputs := make([]ReproducibilityOutput, 0, len(build.OutputPaths))
	seen := map[string]bool{}
	for _, path := range build.OutputPaths {
		output, err := inspectReproducibilityFile(root, path)
		if err != nil {
			return nil, nil, fmt.Errorf("output %s: %w", filepath.Base(path), err)
		}
		if seen[output.Filename] {
			return nil, nil, fmt.Errorf("duplicate output %s", output.Filename)
		}
		seen[output.Filename] = true
		outputs = append(outputs, output)
	}
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].Filename < outputs[j].Filename })
	evidence := make([]ReproducibilityEvidence, 0, len(build.EvidencePaths))
	for _, path := range build.EvidencePaths {
		item, err := inspectReproducibilityFile(root, path)
		if err != nil {
			return nil, nil, fmt.Errorf("evidence %s: %w", filepath.Base(path), err)
		}
		evidence = append(evidence, ReproducibilityEvidence{Filename: item.Filename, Size: item.Size, SHA256: item.SHA256, Path: item.Path})
	}
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Filename < evidence[j].Filename })
	return outputs, evidence, nil
}

func inspectReproducibilityFile(root, path string) (ReproducibilityOutput, error) {
	if path == "" {
		return ReproducibilityOutput{}, errors.New("path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ReproducibilityOutput{}, err
	}
	relative, err := filepath.Rel(root, abs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == "." {
		return ReproducibilityOutput{}, errors.New("path escapes build root")
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return ReproducibilityOutput{}, err
	}
	if !info.Mode().IsRegular() {
		return ReproducibilityOutput{}, errors.New("path is not a regular file")
	}
	digest, size, err := hashFile(abs)
	if err != nil {
		return ReproducibilityOutput{}, err
	}
	return ReproducibilityOutput{Filename: filepath.Base(abs), Path: abs, Size: size, SHA256: digest}, nil
}

func waitReproducibilityGap(ctx context.Context, finished time.Time, gap time.Duration) error {
	remaining := gap - time.Since(finished)
	if remaining <= 0 {
		return nil
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("wait reproducibility gap: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

func firstDifferentByte(primary, secondary string) (int64, bool, error) {
	left, err := os.Open(primary)
	if err != nil {
		return 0, false, err
	}
	defer left.Close()
	right, err := os.Open(secondary)
	if err != nil {
		return 0, false, err
	}
	defer right.Close()
	const chunkSize = 1 << 20
	leftChunk, rightChunk := make([]byte, chunkSize), make([]byte, chunkSize)
	var offset int64
	for {
		leftN, leftErr := io.ReadFull(left, leftChunk)
		rightN, rightErr := io.ReadFull(right, rightChunk)
		limit := leftN
		if rightN < limit {
			limit = rightN
		}
		for index := 0; index < limit; index++ {
			if leftChunk[index] != rightChunk[index] {
				return offset + int64(index), true, nil
			}
		}
		if leftN != rightN {
			return offset + int64(limit), true, nil
		}
		offset += int64(limit)
		if leftErr != nil || rightErr != nil {
			if errors.Is(leftErr, io.EOF) || errors.Is(leftErr, io.ErrUnexpectedEOF) || errors.Is(rightErr, io.EOF) || errors.Is(rightErr, io.ErrUnexpectedEOF) {
				return offset, false, nil
			}
			if leftErr != nil {
				return 0, false, leftErr
			}
			return 0, false, rightErr
		}
	}
}

func writeReproducibilityAttempt(attempt ReproducibilityAttempt) error {
	bytes, err := json.Marshal(attempt)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(attempt.Root, "reproducibility-attempt.json"), bytes, 0o600); err != nil {
		return err
	}
	if attempt.Log != "" {
		return os.WriteFile(filepath.Join(attempt.Root, "reproducibility-log.txt"), []byte(attempt.Log), 0o600)
	}
	return nil
}

func writeReproducibilityFailure(root string, result ReproducibilityPair) error {
	bytes, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "reproducibility-diff.json"), bytes, 0o600)
}

func boundedReproducibilityLog(value string) string {
	if len(value) <= maxReproducibilityLogBytes {
		return value
	}
	return value[:maxReproducibilityLogBytes] + "\n[reproducibility log truncated]\n"
}

func joinReproducibilityError(log string, err error) string {
	if log == "" {
		return err.Error()
	}
	return log + "\n" + err.Error()
}

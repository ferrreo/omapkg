package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestImageReproducibilityAcceptance is driven by
// system-images/reproducibility/run.sh. It intentionally does nothing during
// the ordinary worker suite; the harness performs prerequisite checks and
// sets OPR_IMAGE_REPRO_ACCEPTANCE=1 before invoking this real-build test.
func TestImageReproducibilityAcceptance(t *testing.T) {
	if os.Getenv("OPR_IMAGE_REPRO_ACCEPTANCE") != "1" {
		return
	}
	repoRoot := os.Getenv("OPR_IMAGE_REPRO_REPO_ROOT")
	kind := os.Getenv("OPR_IMAGE_REPRO_KIND")
	profile := os.Getenv("OPR_IMAGE_REPRO_PROFILE")
	outputRoot := os.Getenv("OPR_IMAGE_REPRO_OUTPUT")
	if repoRoot == "" || outputRoot == "" || profile == "" {
		t.Fatal("incomplete: OPR_IMAGE_REPRO_REPO_ROOT, OPR_IMAGE_REPRO_PROFILE and OPR_IMAGE_REPRO_OUTPUT are required")
	}
	gap := 5 * time.Second
	if value := os.Getenv("OPR_IMAGE_REPRO_GAP"); value != "" {
		seconds, err := strconv.Atoi(value)
		if err != nil || seconds < 1 {
			t.Fatalf("invalid OPR_IMAGE_REPRO_GAP %q", value)
		}
		gap = time.Duration(seconds) * time.Second
	}
	if kind == "oci" {
		runOCIImageReproducibility(t, repoRoot, profile, filepath.Join(outputRoot, "oci"), gap)
		return
	}
	if kind == "boot" {
		runBootImageReproducibility(t, repoRoot, profile, filepath.Join(outputRoot, "boot"), gap)
		return
	}
	t.Fatalf("incomplete: unsupported image reproducibility kind %q", kind)
}

type imageAttemptMetadata struct {
	SchemaVersion    int               `json:"schemaVersion"`
	Kind             string            `json:"kind"`
	Attempt          string            `json:"attempt"`
	Fixture          string            `json:"fixture"`
	Status           string            `json:"status"`
	StartedAtUnixNs  string            `json:"startedAtUnixNs"`
	FinishedAtUnixNs string            `json:"finishedAtUnixNs"`
	Architecture     string            `json:"architecture"`
	ProfileSHA256    string            `json:"profileSha256"`
	SourceDateEpoch  int64             `json:"sourceDateEpoch,omitempty"`
	ContextSHA256    string            `json:"contextSha256"`
	Builder          map[string]string `json:"builder"`
	OutputTreeSHA256 string            `json:"outputTreeSha256"`
	InputIdentity    string            `json:"inputIdentitySha256,omitempty"`
}

func runOCIImageReproducibility(t *testing.T, repoRoot, profile, outputRoot string, gap time.Duration) {
	t.Helper()
	profileBytes, err := os.ReadFile(profile)
	if err != nil {
		t.Fatalf("incomplete: read OCI profile: %v", err)
	}
	var profileValue struct {
		Architecture    string `json:"architecture"`
		Format          string `json:"format"`
		Network         string `json:"network"`
		SourceDateEpoch int64  `json:"sourceDateEpoch"`
		Builder         string `json:"builder"`
		BuilderVersion  string `json:"builderVersion"`
		DockerfileSHA   string `json:"dockerfileSha256"`
		PayloadSHA      string `json:"payloadSha256"`
	}
	if err := json.Unmarshal(profileBytes, &profileValue); err != nil || profileValue.Architecture != "x86_64" || profileValue.Format != "oci" || profileValue.Network != "none" || profileValue.Builder != "buildah" || profileValue.BuilderVersion == "" || len(profileValue.DockerfileSHA) != 64 || len(profileValue.PayloadSHA) != 64 || profileValue.SourceDateEpoch <= 0 {
		t.Fatalf("incomplete: OCI profile is not the pinned x86_64 fixture")
	}
	if runtime := os.Getenv("OPR_IMAGE_REPRO_BUILDER"); runtime != "" && runtime != "buildah" {
		t.Fatalf("incomplete: OCI acceptance pins buildah, got %q", runtime)
	}
	if _, err := exec.LookPath("buildah"); err != nil {
		t.Fatalf("incomplete: buildah is required: %v", err)
	}
	if _, err := exec.LookPath("jq"); err != nil {
		t.Fatalf("incomplete: jq is required: %v", err)
	}
	if os.Getenv("OPR_IMAGE_REPRO_OUTER_NETWORK_NONE") == "1" {
		if err := assertLoopbackOnlyNetwork(); err != nil {
			t.Fatalf("incomplete: outer network isolation is not loopback-only: %v", err)
		}
	}
	version := buildahVersion()
	versionFields := strings.Fields(version)
	versionMatches := false
	for index := 0; index+1 < len(versionFields); index++ {
		if versionFields[index] == "Version:" && versionFields[index+1] == profileValue.BuilderVersion {
			versionMatches = true
			break
		}
	}
	if !versionMatches {
		t.Fatalf("incomplete: pinned Buildah %q is unavailable; found %q", profileValue.BuilderVersion, strings.TrimSpace(version))
	}
	if digest := hashPath(filepath.Join(repoRoot, "system-images", "reproducibility", "oci", "Dockerfile")); digest != profileValue.DockerfileSHA {
		t.Fatalf("incomplete: pinned OCI Dockerfile digest changed: %s", digest)
	}
	if digest := hashPath(filepath.Join(repoRoot, "system-images", "reproducibility", "oci", "payload.txt")); digest != profileValue.PayloadSHA {
		t.Fatalf("incomplete: pinned OCI payload digest changed: %s", digest)
	}
	if err := os.MkdirAll(outputRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	deterministic := runReproducibilityPair(t, filepath.Join(outputRoot, "deterministic"), gap, ociBuilder(repoRoot, profile, profileValue.SourceDateEpoch, false))
	if deterministic.result.Status != ReproducibilityIndependentlyReproduced || deterministic.result.Gap < gap {
		writeImageMismatchArtifacts(deterministic)
		t.Fatalf("deterministic OCI fixture did not reproduce: status=%s gap=%s err=%v differences=%+v log=%s", deterministic.result.Status, deterministic.result.Gap, deterministic.err, deterministic.result.Differences, deterministic.result.Primary.Log)
	}

	nondeterministic := runReproducibilityPair(t, filepath.Join(outputRoot, "nondeterministic"), gap, ociBuilder(repoRoot, profile, profileValue.SourceDateEpoch, true))
	if !errors.Is(nondeterministic.err, ErrReproducibilityMismatch) || nondeterministic.result.Status != ReproducibilityMismatch || nondeterministic.result.Gap < gap {
		writeImageMismatchArtifacts(nondeterministic)
		t.Fatalf("nondeterministic OCI fixture was not detected: status=%s err=%v", nondeterministic.result.Status, nondeterministic.err)
	}
	writeImageMismatchArtifacts(nondeterministic)
}

func assertLoopbackOnlyNetwork() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		return fmt.Errorf("interface %s exists outside loopback", iface.Name)
	}
	return nil
}

type pairRun struct {
	result ReproducibilityPair
	err    error
}

func runReproducibilityPair(t *testing.T, root string, gap time.Duration, build ReproducibilityBuilder) pairRun {
	t.Helper()
	result, err := RunReproducibilityPair(context.Background(), ReproducibilitySpec{Root: root, Gap: gap, PreserveOnSuccess: true, Build: build})
	return pairRun{result: result, err: err}
}

func ociBuilder(repoRoot, profile string, sourceDateEpoch int64, nondeterministic bool) ReproducibilityBuilder {
	return func(ctx context.Context, request ReproducibilityBuildRequest) (ReproducibilityBuild, error) {
		builder, err := exec.LookPath("buildah")
		if err != nil {
			return ReproducibilityBuild{}, fmt.Errorf("find buildah: %w", err)
		}
		fixtureRoot := filepath.Join(repoRoot, "system-images", "reproducibility", "oci")
		contextRoot := filepath.Join(request.Root, "context")
		storageRoot := filepath.Join(request.Root, "buildah-storage")
		runRoot := filepath.Join(request.Root, "buildah-runroot")
		layoutRoot := filepath.Join(request.Root, "payload")
		for _, path := range []string{contextRoot, storageRoot, runRoot} {
			if err := os.MkdirAll(path, 0o700); err != nil {
				return ReproducibilityBuild{}, err
			}
		}
		dockerfile := filepath.Join(fixtureRoot, "Dockerfile")
		if nondeterministic {
			dockerfile = filepath.Join(fixtureRoot, "nondeterministic", "Dockerfile")
		}
		dockerfileBytes, err := os.ReadFile(dockerfile)
		if err != nil {
			return ReproducibilityBuild{}, err
		}
		if err := os.WriteFile(filepath.Join(contextRoot, "Dockerfile"), dockerfileBytes, 0o644); err != nil {
			return ReproducibilityBuild{}, err
		}
		if nondeterministic {
			if err := os.WriteFile(filepath.Join(contextRoot, "nonce.txt"), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)+"\n"), 0o644); err != nil {
				return ReproducibilityBuild{}, err
			}
		} else {
			payload, err := os.ReadFile(filepath.Join(fixtureRoot, "payload.txt"))
			if err != nil {
				return ReproducibilityBuild{}, err
			}
			if err := os.WriteFile(filepath.Join(contextRoot, "payload.txt"), payload, 0o644); err != nil {
				return ReproducibilityBuild{}, err
			}
		}
		contextDigest, err := digestContext(contextRoot)
		if err != nil {
			return ReproducibilityBuild{}, err
		}
		profileDigest, _, err := hashFile(profile)
		if err != nil {
			return ReproducibilityBuild{}, err
		}
		start := time.Now().UTC()
		tag := "localhost/omapkg-repro-" + request.Attempt + "-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ":fixture"
		global := []string{"--root", storageRoot, "--runroot", runRoot, "--storage-driver=vfs"}
		networkMode := "none"
		if os.Getenv("OPR_IMAGE_REPRO_OUTER_NETWORK_NONE") == "1" {
			networkMode = "host"
		}
		buildArgs := append(append([]string{}, global...), "bud", "--format", "oci", "--network", networkMode, "--no-cache", "--pull=never", "--timestamp", strconv.FormatInt(sourceDateEpoch, 10), "--arch", "amd64", "--os", "linux", "--file", filepath.Join(contextRoot, "Dockerfile"), "--tag", tag, contextRoot)
		buildOutput, buildErr := runImageCommand(ctx, builder, buildArgs, request.Root)
		if buildErr == nil {
			pushArgs := append(append([]string{}, global...), "push", "--quiet", tag, "oci:"+layoutRoot+":latest")
			pushOutput, pushErr := runImageCommand(ctx, builder, pushArgs, request.Root)
			buildOutput += "\n" + pushOutput
			buildErr = pushErr
		}
		finish := time.Now().UTC()
		if buildErr != nil {
			return ReproducibilityBuild{Log: buildOutput}, buildErr
		}
		outputs, err := regularFiles(layoutRoot)
		if err != nil {
			return ReproducibilityBuild{Log: buildOutput}, err
		}
		treePath := filepath.Join(request.Root, "output-tree.tsv")
		if err := writeOutputTree(request.Root, outputs, treePath); err != nil {
			return ReproducibilityBuild{Log: buildOutput}, err
		}
		metadataPath := filepath.Join(request.Root, "image-builder-metadata.json")
		metadata := imageAttemptMetadata{SchemaVersion: 1, Kind: "oci-image-reproducibility-attempt", Attempt: request.Attempt, Fixture: map[bool]string{true: "nondeterministic", false: "deterministic"}[nondeterministic], Status: "built", StartedAtUnixNs: strconv.FormatInt(start.UnixNano(), 10), FinishedAtUnixNs: strconv.FormatInt(finish.UnixNano(), 10), Architecture: "x86_64", ProfileSHA256: profileDigest, SourceDateEpoch: sourceDateEpoch, ContextSHA256: contextDigest, Builder: map[string]string{"path": builder, "sha256": hashPath(builder), "version": strings.TrimSpace(buildahVersion())}, OutputTreeSHA256: hashPath(treePath)}
		if err := writeJSON(metadataPath, metadata); err != nil {
			return ReproducibilityBuild{Log: buildOutput}, err
		}
		return ReproducibilityBuild{OutputPaths: outputs, EvidencePaths: []string{treePath, metadataPath}, Log: buildOutput}, nil
	}
}

func runImageCommand(ctx context.Context, command string, args []string, tempRoot string) (string, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	isolation := "oci"
	if os.Getenv("OPR_IMAGE_REPRO_OUTER_NETWORK_NONE") == "1" {
		isolation = "chroot"
	}
	cmd.Env = append(os.Environ(), "BUILDAH_ISOLATION="+isolation, "BUILDAH_LAYERS=false", "TMPDIR="+filepath.Join(tempRoot, "tmp"))
	if err := os.MkdirAll(filepath.Join(tempRoot, "tmp"), 0o700); err != nil {
		return "", err
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func buildahVersion() string {
	output, err := exec.Command("buildah", "version").CombinedOutput()
	if err != nil {
		return "unavailable: " + err.Error()
	}
	return string(output)
}

func digestContext(root string) (string, error) {
	paths, err := regularFiles(root)
	if err != nil {
		return "", err
	}
	return digestPaths(root, paths)
}

func regularFiles(root string) ([]string, error) {
	paths := []string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is not a reproducibility file: %s", path)
		}
		if entry.Type().IsRegular() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	return paths, nil
}

func digestPaths(root string, paths []string) (string, error) {
	lines := []string{}
	for _, path := range paths {
		digest, size, err := hashFile(path)
		if err != nil {
			return "", err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("%s\t%d\t%s", filepath.ToSlash(relative), size, digest))
	}
	sort.Strings(lines)
	return hashBytes([]byte(strings.Join(lines, "\n") + "\n")), nil
}

func writeOutputTree(root string, paths []string, destination string) error {
	lines := []string{}
	for _, path := range paths {
		digest, size, err := hashFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s\t%d\t%s", filepath.ToSlash(relative), size, digest))
	}
	sort.Strings(lines)
	return os.WriteFile(destination, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

func writeJSON(path string, value any) error {
	bytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(bytes, '\n'), 0o600)
}

func hashPath(path string) string {
	digest, _, err := hashFile(path)
	if err != nil {
		return ""
	}
	return digest
}

func writeImageMismatchArtifacts(pair pairRun) {
	if pair.result.FailureRoot == "" || len(pair.result.Differences) == 0 {
		return
	}
	primaryTree := filepath.Join(pair.result.Primary.Root, "output-tree.tsv")
	secondaryTree := filepath.Join(pair.result.Secondary.Root, "output-tree.tsv")
	left, leftErr := os.ReadFile(primaryTree)
	right, rightErr := os.ReadFile(secondaryTree)
	if leftErr == nil && rightErr == nil {
		diffOutput, diffErr := exec.Command("diff", "-u", primaryTree, secondaryTree).CombinedOutput()
		if diffErr != nil && len(diffOutput) == 0 {
			diffOutput = append([]byte("--- primary output metadata\n+++ secondary output metadata\n"), append(left, right...)...)
		}
		_ = os.WriteFile(filepath.Join(pair.result.FailureRoot, "metadata.diff"), diffOutput, 0o600)
	}
	payload := []string{}
	for _, difference := range pair.result.Differences {
		payload = append(payload, fmt.Sprintf("%s\t%s\tfirstByte=%d\tprimarySha256=%s\tsecondarySha256=%s", difference.Filename, difference.Reason, difference.FirstByte, difference.PrimarySHA256, difference.SecondarySHA256))
	}
	_ = os.WriteFile(filepath.Join(pair.result.FailureRoot, "payload.diff"), []byte(strings.Join(payload, "\n")+"\n"), 0o600)
}

func runBootImageReproducibility(t *testing.T, repoRoot, profile, outputRoot string, gap time.Duration) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("incomplete: boot/filesystem image build requires root for loop devices and filesystems")
	}
	if os.Getenv("SYSTEM_IMAGE_REPRO_KEY") == "" || os.Getenv("SYSTEM_IMAGE_REPRO_FINGERPRINT") == "" {
		t.Fatal("incomplete: SYSTEM_IMAGE_REPRO_KEY and SYSTEM_IMAGE_REPRO_FINGERPRINT are required")
	}
	if os.Getenv("SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK") == "" && os.Getenv("SYSTEM_IMAGE_REPRO_MANIFEST") == "" {
		t.Fatal("incomplete: private candidate lock or immutable manifest is required")
	}
	if err := os.MkdirAll(outputRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	result := runReproducibilityPair(t, outputRoot, gap, bootImageBuilder(repoRoot, profile))
	if result.err != nil || result.result.Status != ReproducibilityIndependentlyReproduced {
		writeImageMismatchArtifacts(result)
		t.Fatalf("boot/filesystem image did not reproduce: status=%s err=%v differences=%+v", result.result.Status, result.err, result.result.Differences)
	}
}

func bootImageBuilder(repoRoot, profile string) ReproducibilityBuilder {
	return func(ctx context.Context, request ReproducibilityBuildRequest) (ReproducibilityBuild, error) {
		output := filepath.Join(request.Root, "image.raw")
		provenance := filepath.Join(request.Root, "provenance.json")
		work := filepath.Join(request.Root, "image-work")
		args := []string{"--profile", profile, "--output", output, "--provenance", provenance, "--work-dir", work}
		if lock := os.Getenv("SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK"); lock != "" {
			args = append(args, "--candidate-lock", lock, "--candidate-lock-signature", os.Getenv("SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK_SIGNATURE"), "--candidate-id", os.Getenv("SYSTEM_IMAGE_REPRO_CANDIDATE_ID"), "--native-plan", os.Getenv("SYSTEM_IMAGE_REPRO_NATIVE_PLAN"), "--native-plan-signature", os.Getenv("SYSTEM_IMAGE_REPRO_NATIVE_PLAN_SIGNATURE"))
		} else {
			args = append(args, "--manifest", os.Getenv("SYSTEM_IMAGE_REPRO_MANIFEST"))
			if signature := os.Getenv("SYSTEM_IMAGE_REPRO_SIGNATURE"); signature != "" {
				args = append(args, "--signature", signature)
			}
			if lock := os.Getenv("SYSTEM_IMAGE_REPRO_RELEASE_LOCK"); lock != "" {
				args = append(args, "--release-lock", lock)
			}
		}
		args = append(args, "--key", os.Getenv("SYSTEM_IMAGE_REPRO_KEY"), "--fingerprint", os.Getenv("SYSTEM_IMAGE_REPRO_FINGERPRINT"))
		if client := os.Getenv("SYSTEM_IMAGE_REPRO_CLIENT"); client != "" {
			args = append(args, "--client", client)
		}
		if os.Getenv("SYSTEM_IMAGE_REPRO_ALLOW_HTTP") == "1" {
			args = append(args, "--allow-http")
		}
		builder := filepath.Join(repoRoot, "scripts", "build-system-image.sh")
		start := time.Now().UTC()
		outputBytes, err := exec.CommandContext(ctx, builder, args...).CombinedOutput()
		finish := time.Now().UTC()
		if err != nil {
			return ReproducibilityBuild{Log: string(outputBytes)}, err
		}
		outputs := []string{output, provenance}
		tree := filepath.Join(request.Root, "output-tree.tsv")
		if err := writeOutputTree(request.Root, outputs, tree); err != nil {
			return ReproducibilityBuild{Log: string(outputBytes)}, err
		}
		profileDigest := hashPath(profile)
		inputIdentity := os.Getenv("SYSTEM_IMAGE_REPRO_MANIFEST")
		if lock := os.Getenv("SYSTEM_IMAGE_REPRO_CANDIDATE_LOCK"); lock != "" {
			inputIdentity = hashPath(lock)
		} else if lock := os.Getenv("SYSTEM_IMAGE_REPRO_RELEASE_LOCK"); lock != "" {
			inputIdentity = hashPath(lock)
		} else {
			inputIdentity = hashBytes([]byte("manifest:" + inputIdentity))
		}
		builderIdentity := map[string]string{"path": builder, "scriptSha256": hashPath(builder)}
		if plan := os.Getenv("SYSTEM_IMAGE_REPRO_NATIVE_PLAN"); plan != "" {
			builderIdentity["nativePlanSha256"] = hashPath(plan)
		}
		metadata := imageAttemptMetadata{SchemaVersion: 1, Kind: "boot-filesystem-image-reproducibility-attempt", Attempt: request.Attempt, Status: "built", StartedAtUnixNs: strconv.FormatInt(start.UnixNano(), 10), FinishedAtUnixNs: strconv.FormatInt(finish.UnixNano(), 10), Architecture: "x86_64", ProfileSHA256: profileDigest, Builder: builderIdentity, OutputTreeSHA256: hashPath(tree), InputIdentity: inputIdentity}
		metadataPath := filepath.Join(request.Root, "image-builder-metadata.json")
		if err := writeJSON(metadataPath, metadata); err != nil {
			return ReproducibilityBuild{Log: string(outputBytes)}, err
		}
		return ReproducibilityBuild{OutputPaths: outputs, EvidencePaths: []string{tree, metadataPath}, Log: string(outputBytes)}, nil
	}
}

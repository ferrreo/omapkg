package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

//go:embed runtime-analysis.py
var runtimeAnalysisScript string

type analysisFinding struct {
	Code       string  `json:"code"`
	Level      string  `json:"level"`
	Detail     string  `json:"detail"`
	Dependency *string `json:"dependency"`
	SHA256     string  `json:"sha256"`
}

type runtimeAnalysis struct {
	SchemaVersion          int                `json:"schemaVersion"`
	Tool                   string             `json:"tool"`
	ToolVersion            string             `json:"toolVersion"`
	ELF                    []json.RawMessage  `json:"elf"`
	NativeCode             *[]string          `json:"nativeCode,omitempty"`
	PayloadSHA256          string             `json:"payloadSha256,omitempty"`
	Findings               []analysisFinding  `json:"findings"`
	RuntimeClosureComplete bool               `json:"runtimeClosureComplete"`
	Unknowns               []string           `json:"unknowns"`
	Exceptions             []runtimeException `json:"exceptions,omitempty"`
}

type runtimeException struct {
	FindingSHA256 string `json:"findingSha256"`
	Reason        string `json:"reason"`
}

type dependencyBlocker struct {
	Relation      string `json:"relation,omitempty"`
	Phase         string `json:"phase"`
	Resolution    string `json:"resolution"`
	Detail        string `json:"detail"`
	FindingSHA256 string `json:"findingSha256,omitempty"`
}

type dependencyResolutionError struct {
	Blockers []dependencyBlocker
	Cause    error
}

func (e *dependencyResolutionError) Error() string { return e.Cause.Error() }
func (e *dependencyResolutionError) Unwrap() error { return e.Cause }

func missingPackageError(log string, dependencies []string, cause error) error {
	var blockers []dependencyBlocker
	for _, dependency := range dependencies {
		if strings.Contains(log, "error: target not found: "+dependency+"\n") {
			blockers = append(blockers, dependencyBlocker{Relation: dependency, Phase: "build", Resolution: "dependency", Detail: "Approved repositories could not resolve " + dependency})
		}
		if len(blockers) == 16 {
			break
		}
	}
	if len(blockers) == 0 {
		return cause
	}
	return &dependencyResolutionError{Blockers: blockers, Cause: cause}
}

type environmentEvidence struct {
	BaseImage     string   `json:"baseImage"`
	PreparedImage string   `json:"preparedImage"`
	Packages      []string `json:"packages"`
}

func (r *Runner) inspectEnvironment(ctx context.Context, name, base, image string) (environmentEvidence, error) {
	imageID, err := r.run(ctx, "image", "inspect", "--format", "{{.Id}}", image)
	if err != nil {
		return environmentEvidence{}, err
	}
	imageID = strings.TrimSpace(imageID)
	if sha256Pattern.MatchString(imageID) {
		imageID = "sha256:" + imageID
	}
	if !digestPattern.MatchString(imageID) {
		return environmentEvidence{}, errors.New("prepared image identity is invalid")
	}
	args := r.baseContainerArgsForImage(containerName(name, "inventory"), "none", "", nil, nil, "65534:65534", image)
	args = append(args, "/usr/bin/pacman", "--config", "/dev/null", "-Q")
	output, err := r.runContainer(ctx, containerName(name, "inventory"), args...)
	if err != nil {
		return environmentEvidence{}, err
	}
	packages := strings.Split(strings.TrimSpace(output), "\n")
	if len(packages) == 0 || len(packages) > 4096 {
		return environmentEvidence{}, errors.New("installed package inventory exceeds limit")
	}
	for _, entry := range packages {
		fields := strings.Fields(entry)
		if len(fields) != 2 || !depNamePattern.MatchString(fields[0]) || !validArchVersion(fields[1]) {
			return environmentEvidence{}, errors.New("installed package inventory is invalid")
		}
	}
	return environmentEvidence{BaseImage: base, PreparedImage: imageID, Packages: packages}, nil
}

func (r *Runner) analyzePackage(ctx context.Context, artifact, name, imageRef string, exceptions []runtimeException) (*runtimeAnalysis, error) {
	directory, err := os.MkdirTemp(r.StateDir, "analysis-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	script := filepath.Join(directory, "analysis.py")
	if err := os.WriteFile(script, []byte(runtimeAnalysisScript), 0o644); err != nil {
		return nil, err
	}
	args := r.baseContainerArgsForImage(containerName(name, "analysis"), "none", "", []mount{
		{Source: script, Target: "/opr-analysis.py", ReadOnly: true},
		{Source: artifact, Target: "/opr-package.pkg.tar.zst", ReadOnly: true},
	}, map[string]string{"PYTHONHASHSEED": "0", "PYTHONPATH": "", "PYTHONHOME": ""}, "65534:65534", imageRef)
	args = append(args, "/usr/bin/python", "-s", "-P", "/opr-analysis.py", "/opr-package.pkg.tar.zst")
	output, err := r.runContainer(ctx, containerName(name, "analysis"), args...)
	if err != nil {
		return nil, fmt.Errorf("package analysis failed: %w: %s", err, output)
	}
	var analysis runtimeAnalysis
	if len(output) > 256*1024 || json.Unmarshal([]byte(output), &analysis) != nil || analysis.SchemaVersion != 1 || analysis.Tool != "namcap" || analysis.RuntimeClosureComplete {
		return nil, errors.New("package analysis returned invalid evidence")
	}
	analysis.Exceptions = exceptions
	for _, finding := range analysis.Findings {
		ambiguous := finding.Code == "library-no-package-associated" || finding.Code == "dependency-detected-but-optional" || finding.Code == "dependency-implicitly-satisfied-optional"
		if finding.Level != "error" && !ambiguous {
			continue
		}
		exempt := false
		if ambiguous && finding.Level != "error" {
			for _, exception := range exceptions {
				if exception.FindingSHA256 == finding.SHA256 {
					exempt = true
				}
			}
		}
		if !exempt {
			blocker := dependencyBlocker{Phase: "runtime", Resolution: "recipe", Detail: finding.Detail, FindingSHA256: finding.SHA256}
			if ambiguous && finding.Level != "error" {
				blocker.Resolution = "exception"
			}
			if finding.Dependency != nil && validArchDependency(*finding.Dependency) {
				blocker.Relation = *finding.Dependency
			}
			return &analysis, &dependencyResolutionError{Blockers: []dependencyBlocker{blocker}, Cause: fmt.Errorf("runtime dependency analysis requires review: %s [%s]", finding.Detail, finding.SHA256)}
		}
	}
	return &analysis, nil
}

func runtimeDependencyPlan(plan *DependencyPlan) (*DependencyPlan, error) {
	if plan == nil {
		return nil, nil
	}
	if plan.RuntimeReleaseIDs == nil {
		return nil, errors.New("dependency plan lacks runtime scope; re-lease the job")
	}
	result := *plan
	result.Packages = nil
	for _, item := range plan.Packages {
		if slices.Contains(*plan.RuntimeReleaseIDs, item.ReleaseID) {
			result.Packages = append(result.Packages, item)
		}
	}
	if len(result.Packages) == 0 {
		return nil, nil
	}
	return &result, nil
}

func copyRuntimeDependencies(ctx context.Context, plan *DependencyPlan, source, destination string) error {
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return err
	}
	if err := copyFile(ctx, filepath.Join(source, "public-key"), filepath.Join(destination, "public-key")); err != nil {
		return err
	}
	var manifest strings.Builder
	for _, item := range plan.Packages {
		for _, name := range []string{item.Filename, item.Filename + ".sig"} {
			if err := copyFile(ctx, filepath.Join(source, name), filepath.Join(destination, name)); err != nil {
				return err
			}
		}
		fmt.Fprintf(&manifest, "%s\t%s\t%s\t%s\n", item.Name, item.Version, item.Architecture, item.Filename)
	}
	return os.WriteFile(filepath.Join(destination, "plan.tsv"), []byte(manifest.String()), 0o644)
}

func (r *Runner) checkShell(ctx context.Context, job Job, name, image string) (string, error) {
	directory, err := os.MkdirTemp(r.StateDir, "shellcheck-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	files := []struct{ name, shell, contents string }{
		{"PKGBUILD", "bash", job.Recipe},
		{"smoke.sh", "sh", "set -eu\n" + strings.Join(job.SmokeCommands, "\n") + "\n"},
	}
	if job.PublicRecipe != "" {
		files = append(files, struct{ name, shell, contents string }{"public.PKGBUILD", "bash", job.PublicRecipe})
	}
	var mounts []mount
	var script strings.Builder
	script.WriteString("set -eu\n")
	for _, file := range files {
		filename := filepath.Join(directory, file.name)
		if err := os.WriteFile(filename, []byte(file.contents), 0o644); err != nil {
			return "", err
		}
		target := "/opr-" + file.name
		mounts = append(mounts, mount{Source: filename, Target: target, ReadOnly: true})
		fmt.Fprintf(&script, "/bin/%s -n %s\n/usr/bin/shellcheck --norc --shell=%s --severity=error %s\n", file.shell, target, file.shell, target)
	}
	args := r.baseContainerArgsForImage(containerName(name, "shellcheck"), "none", "", mounts, nil, "65534:65534", image)
	args = append(args, "/bin/sh", "-ceu", script.String())
	return r.runContainer(ctx, containerName(name, "shellcheck"), args...)
}

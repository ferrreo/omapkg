package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const maxBuildOutputs = 256

var outputReleasePattern = regexp.MustCompile(`^[1-9][0-9]{0,3}(\.[1-9][0-9]{0,3})?$`)

type expectedOutput struct {
	Name         string `json:"name"`
	FullVersion  string `json:"fullVersion"`
	Architecture string `json:"architecture"`
}
type outputContract struct {
	SchemaVersion int `json:"schemaVersion"`
	Cohort        struct {
		ID             string `json:"id"`
		Revision       int64  `json:"revision"`
		ManifestSHA256 string `json:"manifestSha256"`
	} `json:"cohort"`
	Outputs       []expectedOutput `json:"outputs"`
	RuntimeGroups [][]string       `json:"runtimeGroups"`
}
type buildOutput struct {
	PackageBase     string          `json:"pkgbase"`
	Path            string          `json:"-"`
	Filename        string          `json:"filename"`
	ArtifactSHA256  string          `json:"artifactSha256"`
	PackageMetadata packageMetadata `json:"packageMetadata"`
}

type outputAnalysis struct {
	Name            string           `json:"name"`
	RuntimeAnalysis *runtimeAnalysis `json:"runtimeAnalysis"`
}
type outputRuntimeTest struct {
	Outputs     []string            `json:"outputs"`
	Environment environmentEvidence `json:"environment"`
	Analyses    []outputAnalysis    `json:"analyses"`
	SmokePassed bool                `json:"smokePassed"`
}

func outputFilename(item expectedOutput) string {
	return item.Name + "-" + item.FullVersion + "-" + item.Architecture + ".pkg.tar.zst"
}

func validateOutputContract(job Job) error {
	contract := job.OutputContract
	if contract == nil {
		return nil
	}
	if contract.SchemaVersion != 2 || job.Surface != "binary" || job.Attempt < 1 || !idPattern.MatchString(contract.Cohort.ID) ||
		contract.Cohort.Revision < 1 || !sha256Pattern.MatchString(contract.Cohort.ManifestSHA256) || len(contract.Outputs) < 1 || len(contract.Outputs) > maxBuildOutputs {
		return errors.New("invalid multi-output build contract")
	}
	seen := map[string]bool{}
	for _, output := range contract.Outputs {
		version := output.FullVersion
		if index := strings.IndexByte(version, ':'); index >= 0 {
			version = version[index+1:]
		}
		index := strings.LastIndexByte(version, '-')
		if !depNamePattern.MatchString(output.Name) || seen[output.Name] || !validArchVersion(output.FullVersion) || index < 1 ||
			!pkgverPattern.MatchString(version[:index]) || !outputReleasePattern.MatchString(version[index+1:]) ||
			(output.Architecture != job.Architecture && output.Architecture != "any") || validateArtifactFilename(outputFilename(output)) != nil {
			return errors.New("invalid expected package output")
		}
		seen[output.Name] = true
	}
	if len(contract.RuntimeGroups) < 1 || len(contract.RuntimeGroups) > maxBuildOutputs {
		return errors.New("invalid native installation groups")
	}
	covered, groups := map[string]bool{}, map[string]bool{}
	for _, group := range contract.RuntimeGroups {
		if len(group) < 1 || len(group) > maxBuildOutputs {
			return errors.New("invalid installation group size")
		}
		members := map[string]bool{}
		for _, name := range group {
			if !seen[name] || members[name] {
				return errors.New("installation group has an unknown or repeated output")
			}
			members[name] = true
			covered[name] = true
		}
		ordered := append([]string{}, group...)
		sort.Strings(ordered)
		key := strings.Join(ordered, " ")
		if groups[key] {
			return errors.New("duplicate installation group")
		}
		groups[key] = true
	}
	if len(covered) != len(seen) {
		return errors.New("installation groups omit expected outputs")
	}
	return nil
}

func (r *Runner) collectOutputs(ctx context.Context, outputDir, jobName, image, pkgbase string, contract *outputContract) ([]buildOutput, error) {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, err
	}
	expected := map[string]expectedOutput{}
	for _, output := range contract.Outputs {
		expected[outputFilename(output)] = output
	}
	outputs := []buildOutput{}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pkg.tar.zst") {
			continue
		}
		identity, ok := expected[entry.Name()]
		if !ok || !entry.Type().IsRegular() {
			return nil, fmt.Errorf("unexpected or nonregular package output %s", entry.Name())
		}
		artifact := filepath.Join(outputDir, entry.Name())
		args := r.baseContainerArgsForImage(containerName(jobName+identity.Name, "metadata"), "none", "", []mount{{Source: artifact, Target: "/package.pkg.tar.zst", ReadOnly: true}}, nil, "65534:65534", image)
		args = append(args, "/usr/bin/bsdtar", "-xOf", "/package.pkg.tar.zst", ".PKGINFO")
		text, err := r.runContainer(ctx, containerName(jobName+identity.Name, "metadata"), args...)
		if err != nil || len(text) > 1<<20 {
			return nil, errors.New("cannot read bounded package metadata from artifact")
		}
		metadata, err := parsePackageMetadata([]byte(text))
		if err != nil {
			return nil, err
		}
		if metadata.PackageBase != pkgbase || metadata.Name != identity.Name || metadata.FullVersion != identity.FullVersion || metadata.Architecture != identity.Architecture {
			return nil, fmt.Errorf("output %s differs from reviewed package identity", entry.Name())
		}
		digest, _, err := hashFile(artifact)
		if err != nil {
			return nil, err
		}
		outputs = append(outputs, buildOutput{PackageBase: metadata.PackageBase, Path: artifact, Filename: entry.Name(), ArtifactSHA256: digest, PackageMetadata: metadata})
	}
	if len(outputs) != len(expected) {
		return nil, errors.New("build did not produce every expected output")
	}
	sort.Slice(outputs, func(i, j int) bool { return outputs[i].Filename < outputs[j].Filename })
	return outputs, nil
}

func provenanceForOutputs(job Job, workerID string, result BuildResult, started, finished string) (string, error) {
	if err := validateOutputContract(job); err != nil {
		return "", err
	}
	if job.OutputContract == nil || len(result.Outputs) != len(job.OutputContract.Outputs) {
		return "", errors.New("incomplete output provenance")
	}
	report := map[string]any{
		"schemaVersion": 2, "attempt": job.Attempt, "outputContract": job.OutputContract, "buildId": job.ID, "revisionId": job.RevisionID,
		"workerId": workerID, "recipeSha256": job.RecipeSHA256, "architecture": job.Architecture, "imageDigest": job.ImageDigest,
		"sourceDateEpoch": job.SourceDateEpoch, "sources": append([]Source{}, job.Sources...), "network": "disabled", "startedAt": started, "finishedAt": finished,
		"buildEnvironment": result.BuildEnvironment, "runtimeTests": result.RuntimeTests, "outputs": result.Outputs,
	}
	if job.DependencyPlan != nil {
		report["dependencyPlan"] = job.DependencyPlan
	}
	if job.InputLock != nil {
		if result.InputEvidence == nil || result.InputEvidence.Lock != *job.InputLock {
			return "", errors.New("frozen input evidence is missing")
		}
		report["frozenInputs"] = result.InputEvidence
	}
	if job.PreservedRecipe != nil {
		if result.PreservedRecipe == nil || *result.PreservedRecipe != *job.PreservedRecipe {
			return "", errors.New("preserved recipe source evidence is missing")
		}
		report["preservedRecipe"] = result.PreservedRecipe
	}
	data, err := encodeJSON(report)
	if len(data) > 512*1024 {
		return "", errors.New("multi-output evidence exceeds 512 KiB")
	}
	return string(data), err
}

func withoutOutputDependencies(dependencies []string, outputs []buildOutput) []string {
	names := map[string]bool{}
	name := func(relation string) string {
		if index := strings.IndexAny(relation, "<>="); index >= 0 {
			return relation[:index]
		}
		return relation
	}
	for _, output := range outputs {
		names[output.PackageMetadata.Name] = true
		for _, relation := range output.PackageMetadata.Provides {
			names[name(relation)] = true
		}
	}
	result := []string{}
	for _, relation := range dependencies {
		if !names[name(relation)] {
			result = append(result, relation)
		}
	}
	// pacman validates versions and providers in the complete local transaction.
	return uniqueStrings(result)
}

func (r *Runner) finishOutputs(ctx context.Context, job Job, jobDir, outputDir, jobName, buildImage, dependencyDir string, buildEnvironment environmentEvidence, frozen *materializedInputs) (BuildResult, error) {
	result := BuildResult{BuildEnvironment: &buildEnvironment}
	outputs, err := r.collectOutputs(ctx, outputDir, jobName, buildImage, job.PackageName, job.OutputContract)
	if err != nil {
		return result, err
	}
	result.Outputs = outputs
	for _, output := range outputs {
		result.InstalledSize += output.PackageMetadata.InstalledSize
		if result.InstalledSize > 1<<53-1 {
			return result, errors.New("output installed size exceeds JSON safe range")
		}
	}
	plan, err := runtimeDependencyPlan(job.DependencyPlan)
	if err != nil {
		return result, err
	}
	runtimeDir := ""
	if plan != nil {
		runtimeDir = filepath.Join(jobDir, "runtime-dependencies")
		if err := copyRuntimeDependencies(ctx, plan, dependencyDir, runtimeDir); err != nil {
			return result, err
		}
	}
	for index, group := range job.OutputContract.RuntimeGroups {
		selected := []buildOutput{}
		for _, output := range outputs {
			if slices.Contains(group, output.PackageMetadata.Name) {
				selected = append(selected, output)
			}
		}
		test, log, err := r.testOutputGroup(ctx, job, selected, group, fmt.Sprintf("%s-group-%d", jobName, index), buildImage, runtimeDir, plan, frozen, fmt.Sprintf("runtime-%d", index))
		result.Log += log
		if err != nil {
			return result, err
		}
		result.RuntimeTests = append(result.RuntimeTests, test)
	}
	result.SmokePassed = true
	return result, nil
}

func (r *Runner) testOutputGroup(ctx context.Context, job Job, outputs []buildOutput, group []string, name, buildImage, runtimeDir string, plan *DependencyPlan, frozen *materializedInputs, environmentName string) (outputRuntimeTest, string, error) {
	test := outputRuntimeTest{Outputs: group}
	artifacts, dependencies := []string{}, []string{}
	for _, output := range outputs {
		artifacts = append(artifacts, output.Path)
		dependencies = append(dependencies, output.PackageMetadata.Depends...)
	}
	analysisImage, err := r.installOutputs(ctx, artifacts, name+"-analysis", buildImage)
	log := analysisImage.log
	if err != nil {
		return test, log, fmt.Errorf("install analysis group %v: %w", group, err)
	}
	defer analysisImage.cleanup()
	for _, output := range outputs {
		analysis, err := r.analyzePackage(ctx, output.Path, name+output.PackageMetadata.Name, analysisImage.ref, job.RuntimeExceptions, output.Path+".abi")
		if err != nil {
			return test, log, err
		}
		if analysis.NativeCode == nil || !sha256Pattern.MatchString(analysis.PayloadSHA256) || analysis.ABIInventory == nil || !validInputObject(*analysis.ABIInventory, maxABIDocument) {
			return test, log, errors.New("native code inspection is missing")
		}
		if output.PackageMetadata.Architecture == "any" && len(*analysis.NativeCode) > 0 {
			return test, log, errors.New("architecture-independent output contains native code")
		}
		test.Analyses = append(test.Analyses, outputAnalysis{Name: output.PackageMetadata.Name, RuntimeAnalysis: analysis})
	}
	var prepared preparedImage
	baseImage := r.RuntimeImage
	if frozen != nil {
		prepared, err = r.prepareFrozenEnvironment(ctx, name, frozen, environmentName)
		baseImage = frozen.Manifest.HelperImage
	} else {
		prepared, err = r.prepareDependenciesWithPlan(ctx, name+"-runtime", r.RuntimeImage, withoutOutputDependencies(dependencies, outputs), plan, runtimeDir)
	}
	log += prepared.log
	if err != nil {
		return test, log, err
	}
	if prepared.cleanup != nil {
		defer prepared.cleanup()
	}
	test.Environment, err = r.inspectEnvironment(ctx, name+"-runtime", baseImage, prepared.ref)
	if err != nil {
		return test, log, err
	}
	if frozen != nil {
		if err := frozen.verifyEnvironment(environmentName, test.Environment); err != nil {
			return test, log, err
		}
	}
	installed, err := r.installOutputs(ctx, artifacts, name+"-runtime", prepared.ref)
	log += installed.log
	if err != nil {
		return test, log, fmt.Errorf("install output transaction %v: %w", group, err)
	}
	defer installed.cleanup()
	smokeLog, err := r.smokeInstalled(ctx, name, installed.ref, job.SmokeCommands)
	log += smokeLog
	if err != nil {
		return test, log, err
	}
	test.SmokePassed = true
	return test, log, nil
}

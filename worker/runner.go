package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBuildTimeout     = 2 * time.Hour
	maxBuildLogBytes        = 2 << 20
	maxPackageRelations     = 256
	maxPackageRelationBytes = 256
)

type Runner struct {
	Runtime      string
	Image        string
	ImageDigest  string
	Origin       string
	StateDir     string
	BuildTimeout time.Duration
}

type BuildResult struct {
	ArtifactPath    string
	InstalledSize   int64
	PackageMetadata packageMetadata
	Log             string
	SmokePassed     bool
	Cleanup         func()
}

func (r *Runner) createJobDirectory(jobID string) (string, error) {
	if !idPattern.MatchString(jobID) {
		return "", errors.New("invalid job ID")
	}
	if err := os.MkdirAll(r.StateDir, 0o700); err != nil {
		return "", fmt.Errorf("create worker state directory: %w", err)
	}
	dir, err := os.MkdirTemp(r.StateDir, "job-"+jobID+"-")
	if err != nil {
		return "", fmt.Errorf("create job directory: %w", err)
	}
	for _, name := range []string{"work", "output"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("create job %s directory: %w", name, err)
		}
	}
	return dir, nil
}

func writeRecipe(workdir, recipe string) error {
	filename := filepath.Join(workdir, "PKGBUILD")
	// The build runs as a nonroot UID. The job directory remains private (0700),
	// so reviewed recipe bytes are readable only by this worker and its container.
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, recipe); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

type preparedImage struct {
	ref     string
	log     string
	cleanup func()
}

func (r *Runner) prepareDependencies(ctx context.Context, jobName, imageRef string, dependencies []string) (preparedImage, error) {
	return r.prepareDependenciesWithPlan(ctx, jobName, imageRef, dependencies, nil, "")
}

func (r *Runner) prepareDependenciesWithPlan(ctx context.Context, jobName, imageRef string, dependencies []string, plan *DependencyPlan, dependencyDir string) (preparedImage, error) {
	if len(dependencies) == 0 && plan == nil {
		return preparedImage{ref: imageRef}, nil
	}
	container := containerName(jobName, "prep")
	imageTag := "opr-prepared-" + strings.TrimPrefix(container, "opr-") + ":1"
	r.removeContainer(container)
	r.removeImage(imageTag)
	mounts := []mount(nil)
	prepEnv := map[string]string(nil)
	if plan != nil {
		if dependencyDir == "" {
			return preparedImage{}, errors.New("dependency plan files are required")
		}
		mounts = []mount{{Source: dependencyDir, Target: "/opr/dependencies", ReadOnly: true}}
		prepEnv = map[string]string{"OPR_DEP_KEY_FINGERPRINT": strings.ToUpper(plan.PublicKeyFingerprint)}
	}
	args := r.mutableContainerArgsForImage(container, "bridge", "", mounts, prepEnv, "", imageRef)
	args = withoutArgument(args, "--rm")
	args = insertBeforeImage(args, "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER")
	prepScript, err := dependencyPrepScript(dependencies, plan)
	if err != nil {
		return preparedImage{}, err
	}
	args = append(args, "/bin/bash", "-ceu", prepScript)
	createArgs := append([]string{"create"}, withoutFirstArgument(args, "run")...)
	log, err := r.run(ctx, createArgs...)
	cleanup := func() {
		r.removeContainer(container)
		r.removeImage(imageTag)
	}
	if err != nil {
		cleanup()
		return preparedImage{log: log}, fmt.Errorf("install Arch dependencies: %w", err)
	}
	prepLog, err := r.startAndCollect(ctx, container)
	log += prepLog
	if err != nil {
		cleanup()
		return preparedImage{log: log}, fmt.Errorf("install Arch dependencies: %w", err)
	}
	if _, err := r.run(ctx, "commit", container, imageTag); err != nil {
		cleanup()
		return preparedImage{log: log}, fmt.Errorf("commit prepared Arch image: %w", err)
	}
	imageID, err := r.run(ctx, "image", "inspect", "--format", "{{.Id}}", imageTag)
	if err != nil {
		cleanup()
		return preparedImage{log: log}, fmt.Errorf("inspect prepared Arch image: %w", err)
	}
	log += "prepared image " + strings.TrimSpace(imageID) + "\n"
	r.removeContainer(container)
	return preparedImage{ref: imageTag, log: log, cleanup: func() { r.removeImage(imageTag) }}, nil
}

func withoutArgument(args []string, unwanted string) []string {
	result := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != unwanted {
			result = append(result, arg)
		}
	}
	return result
}

func (r *Runner) removeContainer(name string) {
	if !containerNamePattern.MatchString(name) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = r.run(ctx, "rm", "-f", name)
}

func (r *Runner) startAndCollect(ctx context.Context, name string) (string, error) {
	if _, err := r.run(ctx, "start", name); err != nil {
		return "", err
	}
	waitOutput, err := r.run(ctx, "wait", name)
	if err != nil {
		return "", err
	}
	logs, logsErr := r.run(ctx, "logs", name)
	if logsErr != nil {
		return logs, logsErr
	}
	exitCode, err := strconv.Atoi(strings.TrimSpace(waitOutput))
	if err != nil {
		return logs, fmt.Errorf("container returned invalid exit status %q", strings.TrimSpace(waitOutput))
	}
	if exitCode != 0 {
		return logs, fmt.Errorf("container exited with status %d", exitCode)
	}
	return logs, nil
}

func (r *Runner) removeImage(imageRef string) {
	if imageRef == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = r.run(ctx, "rmi", imageRef)
}

func (r *Runner) cleanupJobDirectory(jobDir, imageRef string) {
	if jobDir == "" || imageRef == "" {
		return
	}
	name := containerName(filepath.Base(jobDir), "cleanup")
	args := r.baseContainerArgsForImage(name, "none", "/opr/job", []mount{{Source: jobDir, Target: "/opr/job"}}, nil, "", imageRef)
	args = insertBeforeImage(args, "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER")
	args = append(args, "/usr/bin/chmod", "-R", "a+rwX", "/opr/job")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, _ = r.runContainer(ctx, name, args...)
}

func (r *Runner) build(ctx context.Context, workdir, output, jobName string, sourceDateEpoch int64, imageRef string) (string, error) {
	env := map[string]string{
		"SOURCE_DATE_EPOCH": fmt.Sprintf("%d", sourceDateEpoch),
		"PKGDEST":           "/opr/output",
		"SRCDEST":           "/opr/work",
		"LOGDEST":           "/opr/output",
		"BUILDDIR":          "/opr/work/build",
	}
	args := r.baseContainerArgsForImage(containerName(jobName, "build"), "none", "/opr/work", []mount{
		{Source: workdir, Target: "/opr/work"},
		{Source: output, Target: "/opr/output"},
	}, env, workerContainerUser(), imageRef)
	if runtimeKind(r.Runtime) == "podman" {
		// keep-id makes files produced by the numeric build user owned by the
		// worker account on rootless Podman hosts, so cleanup cannot be fenced
		// by an unmapped subuid.
		args = insertBeforeImage(args, "--userns=keep-id")
	}
	args = append(args, "/bin/sh", "-ceu", "mkdir -m 700 /opr/work/.opr-tmp\ntrap 'rm -rf /opr/work/.opr-tmp' EXIT\nexport TMPDIR=/opr/work/.opr-tmp\ncp /etc/makepkg.conf /opr/work/makepkg.conf\nprintf '\\nOPTIONS=(\"${OPTIONS[@]/#debug/!debug}\")\\nPKGEXT=.pkg.tar.zst\\n' >> /opr/work/makepkg.conf\nexport MAKEPKG_CONF=/opr/work/makepkg.conf\nmakepkg --noconfirm --nodeps --check --log\nfound=0\nfor package in /opr/output/*.pkg.tar.zst; do\n  bsdtar -tf \"$package\" | grep -qx '.BUILDINFO'\n  bsdtar -xOf \"$package\" .PKGINFO > /opr/output/.PKGINFO\n  found=1\ndone\ntest \"$found\" -eq 1")
	log, err := r.runContainer(ctx, containerName(jobName, "build"), args...)
	if err != nil {
		return log, fmt.Errorf("offline Arch build: %w", err)
	}
	return log, nil
}

func workerContainerUser() string {
	uid := os.Getuid()
	gid := os.Getgid()
	if uid < 1 || gid < 1 {
		return "65534:65534"
	}
	return fmt.Sprintf("%d:%d", uid, gid)
}

func (r *Runner) smoke(ctx context.Context, artifact, jobName, imageRef string, commands []string) (string, error) {
	if len(commands) == 0 {
		return "", nil
	}
	installContainer := containerName(jobName, "smoke-install")
	installImage := "opr-smoke-" + strings.TrimPrefix(installContainer, "opr-") + ":1"
	r.removeContainer(installContainer)
	r.removeImage(installImage)
	create := r.mutableContainerArgsForImage(installContainer, "none", "", nil, nil, "", imageRef)
	create = withoutArgument(create, "--rm")
	create = insertBeforeImage(create, "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER")
	create = append(create, "/bin/sh", "-ceu", smokeInstallScript())
	createArgs := append([]string{"create"}, withoutFirstArgument(create, "run")...)
	log, err := r.run(ctx, createArgs...)
	cleanup := func() {
		r.removeContainer(installContainer)
		r.removeImage(installImage)
	}
	if err != nil {
		cleanup()
		return log, fmt.Errorf("create smoke install container: %w", err)
	}
	copyArgs := []string{"cp"}
	if runtimeKind(r.Runtime) == "docker" {
		copyArgs = append(copyArgs, "-a")
	}
	copyArgs = append(copyArgs, artifact, installContainer+":/package.pkg.tar.zst")
	cpLog, err := r.run(ctx, copyArgs...)
	log += cpLog
	if err != nil {
		cleanup()
		return log, fmt.Errorf("copy package into smoke container: %w", err)
	}
	installLog, err := r.startAndCollect(ctx, installContainer)
	log += installLog
	if err != nil {
		cleanup()
		return log, fmt.Errorf("install package for smoke test: %w", err)
	}
	if _, err := r.run(ctx, "commit", installContainer, installImage); err != nil {
		cleanup()
		return log, fmt.Errorf("commit smoke image: %w", err)
	}
	if imageID, inspectErr := r.run(ctx, "image", "inspect", "--format", "{{.Id}}", installImage); inspectErr == nil {
		log += "smoke image " + strings.TrimSpace(imageID) + "\n"
	}
	r.removeContainer(installContainer)
	defer r.removeImage(installImage)
	var script strings.Builder
	script.WriteString("set -eu\n")
	for _, command := range commands {
		script.WriteString(command)
		script.WriteByte('\n')
	}
	args := r.baseContainerArgsForImage(containerName(jobName, "smoke"), "none", "", nil, nil, "65534:65534", installImage)
	args = append(args, "/bin/sh", "-ceu", script.String())
	smokeLog, smokeErr := r.runContainer(ctx, containerName(jobName, "smoke"), args...)
	return log + smokeLog, smokeErr
}

func smokeInstallScript() string {
	return `set -eu
config=/tmp/opr-smoke-pacman.conf
cp /etc/pacman.conf "$config"
sed -i '/^[#[:space:]]*NoExtract[[:space:]]*=/d' "$config"
pacman --config "$config" -U --noconfirm /package.pkg.tar.zst
rm -f "$config"`
}

func withoutFirstArgument(args []string, unwanted string) []string {
	if len(args) > 0 && args[0] == unwanted {
		return args[1:]
	}
	return args
}

func insertBeforeImage(args []string, options ...string) []string {
	if len(args) == 0 {
		return args
	}
	result := make([]string, 0, len(args)+len(options))
	result = append(result, args[:len(args)-1]...)
	result = append(result, options...)
	result = append(result, args[len(args)-1])
	return result
}

func (r *Runner) Execute(ctx context.Context, job Job, fetched []fetchedSource) (BuildResult, error) {
	return r.execute(ctx, job, fetched, nil)
}

func (r *Runner) ExecuteWithClient(ctx context.Context, job Job, fetched []fetchedSource, client *Client) (BuildResult, error) {
	if client == nil {
		return r.execute(ctx, job, fetched, nil)
	}
	return r.execute(ctx, job, fetched, client.registryCredentials)
}

func (r *Runner) execute(ctx context.Context, job Job, fetched []fetchedSource, getCredentials registryCredentialGetter) (BuildResult, error) {
	legacy := Config{Origin: r.Origin, Architecture: job.Architecture, Image: r.Image, ImageDigest: r.ImageDigest}
	if err := validateJob(job, legacy); err != nil {
		// Execute is called after full validation; this guards direct callers from
		// accidentally running an incomplete job.
		return BuildResult{}, err
	}
	imageRef, err := imageReferenceForJob(job, legacy)
	if err != nil {
		return BuildResult{}, err
	}
	if len(fetched) != len(job.Sources) {
		return BuildResult{}, errors.New("fetched source count does not match job")
	}
	jobDir, err := r.createJobDirectory(job.ID)
	if err != nil {
		return BuildResult{}, err
	}
	keepDirectory := false
	defer func() {
		if !keepDirectory {
			r.cleanupJobDirectory(jobDir, imageRef)
			_ = os.RemoveAll(jobDir)
		}
	}()
	workdir := filepath.Join(jobDir, "work")
	output := filepath.Join(jobDir, "output")
	dependencyDir := ""
	if job.DependencyPlan != nil {
		dependencyDir = filepath.Join(jobDir, "dependencies")
		if err := materializeDependencyPlan(ctx, job.DependencyPlan, job, r.Origin, dependencyDir); err != nil {
			return BuildResult{}, err
		}
	}
	if err := writeRecipe(workdir, job.Recipe); err != nil {
		return BuildResult{}, fmt.Errorf("write recipe: %w", err)
	}
	for index, source := range fetched {
		if !namePattern.MatchString(filepath.Base(source.Path)) || filepath.Base(source.Path) != source.Name {
			return BuildResult{}, errors.New("source path has unsafe basename")
		}
		reviewed := job.Sources[index]
		if source.Name != reviewed.Name || source.URL != reviewed.URL || source.SHA256 != reviewed.SHA256 {
			return BuildResult{}, errors.New("fetched source does not match reviewed source")
		}
		info, err := os.Lstat(source.Path)
		if err != nil || !info.Mode().IsRegular() {
			return BuildResult{}, errors.New("fetched source is not a regular file")
		}
		if digest, _, err := hashFile(source.Path); err != nil || digest != source.SHA256 {
			return BuildResult{}, errors.New("fetched source checksum does not match reviewed source")
		}
		if err := copyFile(source.Path, filepath.Join(workdir, source.Name)); err != nil {
			return BuildResult{}, fmt.Errorf("stage source %s: %w", source.Name, err)
		}
	}
	if err := r.ensureImageReference(ctx, imageRef, job.ImageDigest, getCredentials, job.ID, job.LeaseToken); err != nil {
		return BuildResult{}, err
	}
	jobName := "opr-" + job.ID
	dependencies := append(append(append([]string{}, job.Dependencies...), job.RuntimeDependencies...), job.MakeDependencies...)
	prepared, err := r.prepareDependenciesWithPlan(ctx, jobName, imageRef, uniqueStrings(dependencies), job.DependencyPlan, dependencyDir)
	if err != nil {
		return BuildResult{Log: prepared.log}, err
	}
	if prepared.cleanup != nil {
		defer prepared.cleanup()
	}
	if dependencyDir != "" {
		if err := os.RemoveAll(dependencyDir); err != nil {
			return BuildResult{Log: prepared.log}, fmt.Errorf("remove dependency plan files: %w", err)
		}
		dependencyDir = ""
	}
	log := prepared.log
	for _, directory := range []string{workdir, output} {
		if err := os.Chmod(directory, 0o777); err != nil {
			return BuildResult{Log: log}, fmt.Errorf("prepare build directory: %w", err)
		}
	}
	defer func() {
		_ = os.Chmod(workdir, 0o700)
		_ = os.Chmod(output, 0o700)
	}()
	buildLog, err := r.build(ctx, workdir, output, jobName, job.SourceDateEpoch, prepared.ref)
	log += buildLog
	if err != nil {
		return BuildResult{Log: log}, err
	}
	artifact, err := findArtifact(output, job.PackageName)
	if err != nil {
		return BuildResult{Log: log}, err
	}
	metadata, err := readPackageMetadata(output, artifact, job)
	if err != nil {
		return BuildResult{ArtifactPath: artifact, Log: log}, err
	}
	_ = os.Remove(filepath.Join(output, ".PKGINFO"))
	smokeLog, smokeErr := r.smoke(ctx, artifact, jobName, prepared.ref, job.SmokeCommands)
	if smokeLog != "" {
		log += smokeLog
	}
	if smokeErr != nil {
		return BuildResult{ArtifactPath: artifact, InstalledSize: metadata.InstalledSize, PackageMetadata: metadata, Log: log, SmokePassed: false}, smokeErr
	}
	keepDirectory = true
	return BuildResult{ArtifactPath: artifact, InstalledSize: metadata.InstalledSize, PackageMetadata: metadata, Log: log, SmokePassed: true, Cleanup: func() {
		r.cleanupJobDirectory(jobDir, imageRef)
		_ = os.RemoveAll(jobDir)
	}}, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		return err
	}
	return output.Close()
}

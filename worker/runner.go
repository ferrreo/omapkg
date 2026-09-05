package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	defaultBuildTimeout     = 2 * time.Hour
	maxBuildLogBytes        = 2 << 20
	maxPackageRelations     = 256
	maxPackageRelationBytes = 256
)

var containerNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type Runner struct {
	Runtime      string
	Image        string
	ImageDigest  string
	Origin       string
	StateDir     string
	BuildTimeout time.Duration
}

type mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type BuildResult struct {
	ArtifactPath    string
	InstalledSize   int64
	PackageMetadata packageMetadata
	Log             string
	SmokePassed     bool
	Cleanup         func()
}

type boundedBuffer struct {
	data      strings.Builder
	limit     int
	truncated bool
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - b.data.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = b.data.Write(data[:remaining])
		b.truncated = true
		return len(data), nil
	}
	_, _ = b.data.Write(data)
	return len(data), nil
}

func (b *boundedBuffer) String() string {
	if b.truncated {
		return b.data.String() + "\n[output truncated by worker]\n"
	}
	return b.data.String()
}

func newRunner(cfg Config) (*Runner, error) {
	if cfg.Runtime != "podman" && cfg.Runtime != "docker" {
		return nil, errors.New("containerRuntime must be podman or docker")
	}
	if _, err := exec.LookPath(cfg.Runtime); err != nil {
		return nil, fmt.Errorf("find %s: %w", cfg.Runtime, err)
	}
	return &Runner{
		Runtime:      cfg.Runtime,
		Image:        cfg.Image,
		ImageDigest:  cfg.ImageDigest,
		Origin:       cfg.Origin,
		StateDir:     cfg.StateDir,
		BuildTimeout: defaultBuildTimeout,
	}, nil
}

func (r *Runner) command(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, r.Runtime, args...)
	cmd.Env = runtimeEnvironment()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
	return cmd
}

func runtimeEnvironment() []string {
	result := []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TERM=dumb"}
	for _, name := range []string{"HOME", "XDG_RUNTIME_DIR", "TMPDIR", "DOCKER_HOST", "CONTAINER_HOST"} {
		if value := os.Getenv(name); value != "" {
			if strings.ContainsAny(value, "\x00\r\n") {
				continue
			}
			result = append(result, name+"="+value)
		}
	}
	return result
}

func (r *Runner) run(ctx context.Context, args ...string) (string, error) {
	var output boundedBuffer
	output.limit = maxBuildLogBytes
	cmd := r.command(ctx, args...)
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err != nil {
		return output.String(), fmt.Errorf("container command failed: %w", err)
	}
	return output.String(), nil
}

func (r *Runner) runWithStdin(ctx context.Context, stdin io.Reader, args ...string) (string, error) {
	var output boundedBuffer
	output.limit = maxBuildLogBytes
	cmd := r.command(ctx, args...)
	cmd.Stdin = stdin
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if err != nil {
		return output.String(), fmt.Errorf("container command failed: %w", err)
	}
	return output.String(), nil
}

func (r *Runner) runContainer(ctx context.Context, name string, args ...string) (string, error) {
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cleanup := r.command(cleanupContext, "rm", "-f", name)
		_ = cleanup.Run()
	}()
	return r.run(ctx, args...)
}

type registryCredentialGetter func(context.Context, string, string) (RegistryCredentials, error)

func (r *Runner) ensureImageReference(ctx context.Context, imageRef, imageDigest string, getCredentials registryCredentialGetter, jobID, leaseToken string) error {
	if err := validateImageReference(imageRef, imageDigest); err != nil {
		return err
	}
	format := "{{.Digest}}"
	if runtimeKind(r.Runtime) == "docker" {
		format = "{{json .RepoDigests}}"
	}
	output, err := r.run(ctx, "image", "inspect", "--format", format, imageRef)
	if err != nil {
		var pullErr error
		if imageRegistryHost(imageRef) == "registry.cloudflare.com" {
			if getCredentials == nil {
				pullErr = errors.New("private registry credentials are required")
			} else {
				credentials, credentialErr := getCredentials(ctx, jobID, leaseToken)
				if credentialErr != nil {
					pullErr = fmt.Errorf("request private registry credentials: %w", credentialErr)
				} else {
					pullErr = r.pullPrivateImage(ctx, imageRef, credentials)
				}
			}
		} else {
			_, pullErr = r.run(ctx, "pull", imageRef)
		}
		if pullErr != nil {
			return fmt.Errorf("inspect pinned image: %w; pull: %v", err, pullErr)
		}
		output, err = r.run(ctx, "image", "inspect", "--format", format, imageRef)
	}
	if err != nil {
		return fmt.Errorf("inspect pinned image: %w", err)
	}
	foundDigest := imageDigestInInspect(output, imageDigest, r.Runtime)
	if !foundDigest {
		return fmt.Errorf("builder image digest mismatch: expected %s, got %q", imageDigest, strings.TrimSpace(output))
	}
	return nil
}

func imageRegistryHost(imageRef string) string {
	name := imageRef
	if at := strings.LastIndexByte(name, '@'); at >= 0 {
		name = name[:at]
	}
	if slash := strings.IndexByte(name, '/'); slash >= 0 {
		host := name[:slash]
		if strings.ContainsAny(host, ".:") || strings.EqualFold(host, "localhost") {
			return strings.ToLower(host)
		}
	}
	return "docker.io"
}

func runtimeKind(runtime string) string {
	switch filepath.Base(runtime) {
	case "podman":
		return "podman"
	case "docker":
		return "docker"
	default:
		return runtime
	}
}

func (r *Runner) pullPrivateImage(ctx context.Context, imageRef string, credentials RegistryCredentials) error {
	if strings.ToLower(credentials.Registry) != "registry.cloudflare.com" || imageRegistryHost(imageRef) != "registry.cloudflare.com" {
		return errors.New("private registry credential host does not match image")
	}
	authDir, err := os.MkdirTemp("", "opr-registry-auth-")
	if err != nil {
		return fmt.Errorf("create registry auth directory: %w", err)
	}
	defer os.RemoveAll(authDir)
	if err := os.Chmod(authDir, 0o700); err != nil {
		return fmt.Errorf("protect registry auth directory: %w", err)
	}
	password := strings.NewReader(credentials.Password + "\n")
	var pullArgs []string
	var authFile string
	if runtimeKind(r.Runtime) == "podman" {
		authFile = filepath.Join(authDir, "auth.json")
		if _, err := r.runWithStdin(ctx, password, "login", "--authfile", authFile, "--username", credentials.Username, "--password-stdin", credentials.Registry); err != nil {
			return errors.New("private registry login failed")
		}
		pullArgs = []string{"pull", "--authfile", authFile, imageRef}
	} else {
		if _, err := r.runWithStdin(ctx, password, "--config", authDir, "login", "--username", credentials.Username, "--password-stdin", credentials.Registry); err != nil {
			return errors.New("private registry login failed")
		}
		authFile = filepath.Join(authDir, "config.json")
		pullArgs = []string{"--config", authDir, "pull", imageRef}
	}
	if err := validateAuthFile(authFile); err != nil {
		return err
	}
	if _, err := r.run(ctx, pullArgs...); err != nil {
		return errors.New("private registry pull failed")
	}
	return nil
}

func validateAuthFile(filename string) error {
	info, err := os.Lstat(filename)
	if err != nil {
		return errors.New("private registry auth file was not created")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("private registry auth file is not private")
	}
	return nil
}

func imageDigestInInspect(output, imageDigest, runtime string) bool {
	if runtime == "docker" {
		var references []string
		if json.Unmarshal([]byte(output), &references) != nil {
			return false
		}
		for _, reference := range references {
			if strings.HasSuffix(reference, "@"+imageDigest) {
				return true
			}
		}
		return false
	}
	for _, field := range strings.Fields(output) {
		if field == imageDigest || strings.HasSuffix(field, "@"+imageDigest) {
			return true
		}
	}
	return false
}

func (r *Runner) baseContainerArgs(name, network, workdir string, mounts []mount, env map[string]string, user string) []string {
	return r.baseContainerArgsForImage(name, network, workdir, mounts, env, user, r.Image)
}

func (r *Runner) baseContainerArgsForImage(name, network, workdir string, mounts []mount, env map[string]string, user, imageRef string) []string {
	return r.containerArgsForImage(name, network, workdir, mounts, env, user, imageRef, true)
}

func (r *Runner) mutableContainerArgsForImage(name, network, workdir string, mounts []mount, env map[string]string, user, imageRef string) []string {
	return r.containerArgsForImage(name, network, workdir, mounts, env, user, imageRef, false)
}

func (r *Runner) containerArgsForImage(name, network, workdir string, mounts []mount, env map[string]string, user, imageRef string, readOnly bool) []string {
	if !containerNamePattern.MatchString(name) {
		panic("invalid generated container name")
	}
	args := []string{
		"run", "--rm", "--pull=never", "--name", name,
		"--network", network,
		"--entrypoint", "",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--pids-limit", "512",
		"--memory", "4g",
		"--cpus", "2",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,mode=1777",
		"--tmpfs", "/run:rw,noexec,nosuid,nodev",
	}
	if readOnly {
		args = append(args, "--read-only")
	}
	if workdir != "" {
		args = append(args, "--workdir", workdir)
	}
	if user != "" {
		args = append(args, "--user", user)
	}
	for _, value := range []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TERM=dumb"} {
		args = append(args, "--env", value)
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := env[key]
		if !regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`).MatchString(key) {
			panic("invalid generated container environment key")
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			panic("invalid generated container environment value")
		}
		args = append(args, "--env", key+"="+value)
	}
	for _, value := range mounts {
		mountSpec := fmt.Sprintf("type=bind,src=%s,dst=%s", value.Source, value.Target)
		if value.ReadOnly {
			mountSpec += ",readonly"
		}
		args = append(args, "--mount", mountSpec)
	}
	args = append(args, imageRef)
	return args
}

func containerName(jobID, phase string) string {
	hash := sha256.Sum256([]byte(jobID))
	name := "opr-" + hex.EncodeToString(hash[:])[:16] + "-" + phase
	if len(name) > 63 {
		name = name[:63]
	}
	return name
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

func findArtifact(output, packageName string) (string, error) {
	entries, err := os.ReadDir(output)
	if err != nil {
		return "", err
	}
	var artifacts []string
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".pkg.tar.zst") {
			continue
		}
		if err := validateArtifactFilename(entry.Name()); err != nil {
			return "", err
		}
		artifacts = append(artifacts, filepath.Join(output, entry.Name()))
	}
	if len(artifacts) == 0 {
		return "", errors.New("build produced no matching .pkg.tar.zst artifact")
	}
	if len(artifacts) > 1 {
		return "", errors.New("build produced multiple artifacts but protocol accepts one")
	}
	if packageName != "" && !strings.HasPrefix(filepath.Base(artifacts[0]), packageName+"-") {
		return "", errors.New("build produced an artifact for a different package")
	}
	return artifacts[0], nil
}

type packageMetadata struct {
	Name          string   `json:"name"`
	FullVersion   string   `json:"fullVersion"`
	Architecture  string   `json:"architecture"`
	InstalledSize int64    `json:"installedSize"`
	Depends       []string `json:"depends"`
	Provides      []string `json:"provides"`
	Conflicts     []string `json:"conflicts"`
	Replaces      []string `json:"replaces"`
}

func readPackageMetadata(output, artifact string, job Job) (packageMetadata, error) {
	filename := filepath.Join(output, ".PKGINFO")
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return packageMetadata{}, errors.New("build did not produce regular .PKGINFO metadata")
	}
	file, err := os.Open(filename)
	if err != nil {
		return packageMetadata{}, fmt.Errorf("open .PKGINFO metadata: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	closeErr := file.Close()
	if err != nil {
		return packageMetadata{}, fmt.Errorf("read .PKGINFO metadata: %w", err)
	}
	if closeErr != nil {
		return packageMetadata{}, fmt.Errorf("close .PKGINFO metadata: %w", closeErr)
	}
	if len(data) > 1<<20 {
		return packageMetadata{}, errors.New("package metadata is too large")
	}
	metadata, err := parsePackageMetadata(data)
	if err != nil {
		return packageMetadata{}, err
	}
	if metadata.Name != job.PackageName {
		return packageMetadata{}, fmt.Errorf("package metadata name %q does not match job %q", metadata.Name, job.PackageName)
	}
	expectedVersion := job.Version
	if job.Pkgrel > 0 {
		suffix := "-" + strconv.FormatInt(job.Pkgrel, 10)
		if !strings.HasSuffix(expectedVersion, suffix) {
			expectedVersion += suffix
		}
	}
	if metadata.FullVersion != expectedVersion {
		return packageMetadata{}, fmt.Errorf("package metadata version %q does not match job %q", metadata.FullVersion, expectedVersion)
	}
	if metadata.Architecture != job.Architecture {
		return packageMetadata{}, fmt.Errorf("package metadata architecture %q does not match job %q", metadata.Architecture, job.Architecture)
	}
	expectedFilename := fmt.Sprintf("%s-%s-%s.pkg.tar.zst", job.PackageName, expectedVersion, job.Architecture)
	if filepath.Base(artifact) != expectedFilename {
		return packageMetadata{}, fmt.Errorf("artifact filename %q does not match package metadata", filepath.Base(artifact))
	}
	if metadata.InstalledSize < 0 {
		return packageMetadata{}, errors.New("package metadata installed size is negative")
	}
	if artifact == "" {
		return packageMetadata{}, errors.New("artifact path is required for package metadata")
	}
	return metadata, nil
}

func parsePackageMetadata(data []byte) (packageMetadata, error) {
	metadata := packageMetadata{
		Depends:   make([]string, 0),
		Provides:  make([]string, 0),
		Conflicts: make([]string, 0),
		Replaces:  make([]string, 0),
	}
	seen := make(map[string]bool, 4)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		if key == "pkgname" || key == "pkgver" || key == "arch" || key == "size" {
			if seen[key] {
				return packageMetadata{}, fmt.Errorf("duplicate .PKGINFO field %q", key)
			}
			seen[key] = true
		}
		switch key {
		case "pkgname":
			if !packageRelationNamePattern.MatchString(value) {
				return packageMetadata{}, errors.New("package metadata package name is invalid")
			}
			metadata.Name = value
		case "pkgver":
			if !parsePackageVersion(value) {
				return packageMetadata{}, errors.New("package metadata package version is invalid")
			}
			metadata.FullVersion = value
		case "arch":
			metadata.Architecture = value
		case "size":
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return packageMetadata{}, errors.New("package metadata installed size is invalid")
			}
			if size < 0 || size > 1<<53-1 {
				return packageMetadata{}, errors.New("package metadata installed size is outside JSON safe range")
			}
			metadata.InstalledSize = size
		case "depend", "provides", "conflict", "replaces":
			relation, err := parsePackageRelation(value, key == "provides", key == "depend" || key == "provides")
			if err != nil {
				return packageMetadata{}, fmt.Errorf("package metadata %s is invalid: %w", key, err)
			}
			var values *[]string
			switch key {
			case "depend":
				values = &metadata.Depends
			case "provides":
				values = &metadata.Provides
			case "conflict":
				values = &metadata.Conflicts
			case "replaces":
				values = &metadata.Replaces
			}
			if len(*values) >= maxPackageRelations {
				return packageMetadata{}, errors.New("package metadata relation list is too large")
			}
			*values = append(*values, relation)
		}
	}
	if !seen["pkgname"] || !seen["pkgver"] || !seen["arch"] || !seen["size"] {
		return packageMetadata{}, errors.New("package metadata is missing required fields")
	}
	return metadata, nil
}

var (
	packageRelationNamePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9@._+-]{0,63}$`)
	packageRelationSonameV1Pattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}\.so$`)
	packageRelationSonamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,31}:[A-Za-z0-9][A-Za-z0-9._+~^-]{0,127}$`)
	packageRelationVersionPattern  = regexp.MustCompile(`^(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9@._+%~^:-]{0,127}$`)
)

func parsePackageVersion(value string) bool {
	if !packageRelationVersionPattern.MatchString(value) {
		return false
	}
	separator := strings.IndexByte(value, ':')
	if separator < 0 {
		return true
	}
	if separator == 0 || separator == len(value)-1 || strings.Contains(value[separator+1:], ":") {
		return false
	}
	for _, character := range value[:separator] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func parsePackageRelation(value string, provides, allowSoname bool) (string, error) {
	if len(value) == 0 || len(value) > maxPackageRelationBytes || strings.ContainsAny(value, " \t\r\n\x00") {
		return "", errors.New("relation has invalid length or whitespace")
	}
	operatorAt := -1
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character != '<' && character != '>' && character != '=' {
			continue
		}
		if operatorAt >= 0 {
			return "", errors.New("relation has multiple comparison operators")
		}
		operatorAt = index
		if index+1 < len(value) && (value[index:index+2] == "<=" || value[index:index+2] == ">=") {
			index++
		}
	}
	name := value
	operator := ""
	if operatorAt >= 0 {
		operatorLength := 1
		if operatorAt+1 < len(value) && (value[operatorAt:operatorAt+2] == "<=" || value[operatorAt:operatorAt+2] == ">=") {
			operatorLength = 2
		}
		operator = value[operatorAt : operatorAt+operatorLength]
		if provides && operator != "=" {
			return "", errors.New("provides may only use =")
		}
		name = value[:operatorAt]
		version := value[operatorAt+operatorLength:]
		if !parsePackageVersion(version) {
			return "", errors.New("relation comparison operator is invalid")
		}
	}
	if packageRelationNamePattern.MatchString(name) {
		return value, nil
	}
	if packageRelationSonameV1Pattern.MatchString(name) {
		if !allowSoname || (operatorAt >= 0 && operator != "=") {
			return "", errors.New("legacy SONAME relation is not allowed here")
		}
		return value, nil
	}
	if operatorAt >= 0 && packageRelationSonamePattern.MatchString(name) {
		return "", errors.New("SONAME relations cannot use a comparison operator")
	}
	colon := strings.IndexByte(name, ':')
	if !allowSoname || !packageRelationSonamePattern.MatchString(name) || colon < 0 || !strings.Contains(strings.ToLower(name[colon+1:]), ".so") {
		return "", errors.New("relation name is invalid")
	}
	return value, nil
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

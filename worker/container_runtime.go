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
	"strings"
	"syscall"
	"time"
)

var containerNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type mount struct {
	Source   string
	Target   string
	ReadOnly bool
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

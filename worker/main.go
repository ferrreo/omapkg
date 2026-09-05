package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var workerVersion = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = enrollCommand(os.Args[2:])
	case "run":
		err = runCommand(os.Args[2:])
	case "version":
		fmt.Println(workerVersion)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "opr-worker:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: opr-worker enroll --origin URL --name NAME --architecture x86_64|aarch64 [--image IMAGE@sha256:DIGEST --image-digest sha256:DIGEST] [--token TOKEN | --token-stdin]")
	fmt.Fprintln(os.Stderr, "       opr-worker run [--config PATH] [--once]")
	fmt.Fprintln(os.Stderr, "       opr-worker version")
}

func enrollCommand(args []string) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	origin := flags.String("origin", "", "OPR origin")
	name := flags.String("name", "", "worker name")
	architecture := flags.String("architecture", "", "worker architecture")
	token := flags.String("token", "", "one-use enrollment token")
	tokenStdin := flags.Bool("token-stdin", false, "read enrollment token from stdin")
	stateDir := flags.String("state-dir", "", "worker state directory")
	image := flags.String("image", "", "pinned builder image reference")
	imageDigest := flags.String("image-digest", "", "pinned builder image digest")
	runtime := flags.String("runtime", "podman", "container runtime (podman or docker)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *origin == "" || *name == "" || *architecture == "" {
		return errors.New("origin, name, and architecture are required")
	}
	if !namePattern.MatchString(*name) {
		return errors.New("name must be a safe identifier")
	}
	if !archPattern.MatchString(*architecture) {
		return errors.New("architecture must be x86_64 or aarch64")
	}
	if (*image == "") != (*imageDigest == "") {
		return errors.New("image and image-digest must be provided together")
	}
	if *image != "" {
		if !digestPattern.MatchString(*imageDigest) || validateImageReference(*image, *imageDigest) != nil {
			return errors.New("image must include image-digest")
		}
	}
	metadata, err := daemonMetadata(*runtime)
	if err != nil {
		return err
	}
	if *token != "" && *tokenStdin {
		return errors.New("use only one of --token and --token-stdin")
	}
	enrollmentToken := *token
	if *tokenStdin || enrollmentToken == "" {
		var err error
		enrollmentToken, err = readToken()
		if err != nil {
			return err
		}
	}
	if enrollmentToken == "" {
		return errors.New("enrollment token is required")
	}
	if *stateDir == "" {
		*stateDir = filepath.Dir(defaultConfigPath())
	}
	absoluteStateDir, err := filepath.Abs(*stateDir)
	if err != nil {
		return fmt.Errorf("resolve state directory: %w", err)
	}
	privateKey, err := generateKey()
	if err != nil {
		return err
	}
	originURL, err := url.Parse(*origin)
	if err != nil {
		return err
	}
	if err := validateOrigin(originURL.String()); err != nil {
		return err
	}
	client := &Client{Origin: originURL, HTTP: &http.Client{Timeout: 45 * time.Second}}
	workerID, err := client.postEnrollment(context.Background(), enrollmentToken, *name, *architecture, privateKey.Public().(ed25519.PublicKey), metadata)
	if err != nil {
		return err
	}
	cfg := Config{
		Origin:           originURL.String(),
		WorkerID:         workerID,
		PrivateKey:       encodePrivateKey(privateKey),
		Image:            *image,
		ImageDigest:      *imageDigest,
		Architecture:     *architecture,
		Runtime:          *runtime,
		StateDir:         absoluteStateDir,
		MaxSourceBytes:   defaultMaxSourceBytes,
		SourceTimeoutSec: 600,
	}
	configPath := filepath.Join(absoluteStateDir, "config.json")
	if err := saveConfig(configPath, cfg); err != nil {
		return err
	}
	fmt.Println(workerID)
	return nil
}

func readToken() (string, error) {
	reader := bufio.NewReaderSize(os.Stdin, 1<<20)
	token, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, context.Canceled) {
		if !errors.Is(err, io.EOF) {
			return "", err
		}
	}
	return strings.TrimSpace(token), nil
}

func runCommand(args []string) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", defaultConfigPath(), "config file")
	once := flags.Bool("once", false, "claim at most one job")
	pollSeconds := flags.Int("poll-seconds", 10, "seconds between empty claims")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	client, err := newClient(cfg)
	if err != nil {
		return err
	}
	runner, err := newRunner(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runLoop(ctx, client, runner, cfg, *once, time.Duration(maxInt(*pollSeconds, 1))*time.Second)
}

func maxInt(value, minimum int) int {
	if value < minimum {
		return minimum
	}
	return value
}

func runLoop(ctx context.Context, client *Client, runner *Runner, cfg Config, once bool, pollInterval time.Duration) error {
	backoff := pollInterval
	for {
		job, err := client.claim(ctx)
		if err != nil {
			if once {
				return err
			}
			fmt.Fprintln(os.Stderr, "claim:", err)
			if err := sleepContext(ctx, backoff); err != nil {
				return err
			}
			if backoff < time.Minute {
				backoff *= 2
				if backoff > time.Minute {
					backoff = time.Minute
				}
			}
			continue
		}
		backoff = pollInterval
		if job == nil {
			if once {
				return nil
			}
			if err := sleepContext(ctx, pollInterval); err != nil {
				return err
			}
			continue
		}
		if err := runJob(ctx, client, runner, cfg, *job); err != nil {
			fmt.Fprintln(os.Stderr, "job:", err)
			if once {
				return err
			}
		}
		if once {
			return nil
		}
	}
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type heartbeatStatus struct {
	cancelled atomic.Bool
}

func heartbeatLoop(ctx context.Context, client *Client, job Job, status *heartbeatStatus, cancel context.CancelFunc) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			response, err := client.heartbeat(ctx, job.ID, job.LeaseToken)
			if err != nil {
				fmt.Fprintln(os.Stderr, "heartbeat:", err)
				continue
			}
			if response.Cancel {
				status.cancelled.Store(true)
				cancel()
				return
			}
		}
	}
}

func runJob(parent context.Context, client *Client, runner *Runner, cfg Config, job Job) error {
	if err := validateJob(job, cfg); err != nil {
		if job.ID != "" && job.LeaseToken != "" {
			_ = reportFailure(parent, client, job, nil, err)
		}
		return err
	}
	leaseExpiry, err := parseLeaseExpiry(job.LeaseExpiresAt)
	if err != nil || !leaseExpiry.After(time.Now()) {
		return fmt.Errorf("job lease is expired")
	}
	jobCtx, cancel := context.WithCancel(parent)
	defer cancel()
	status := &heartbeatStatus{}
	go heartbeatLoop(jobCtx, client, job, status, cancel)
	started := time.Now().UTC().Format(time.RFC3339Nano)
	sourceDir, err := os.MkdirTemp(cfg.StateDir, "sources-"+job.ID+"-")
	if err != nil {
		return reportFailure(parent, client, job, nil, err)
	}
	defer os.RemoveAll(sourceDir)
	sourceTimeout := time.Duration(cfg.SourceTimeoutSec) * time.Second
	if sourceTimeout <= 0 {
		sourceTimeout = 10 * time.Minute
	}
	fetchCtx, fetchCancel := context.WithTimeout(jobCtx, sourceTimeout)
	fetched, err := fetchSourcesForClient(fetchCtx, job.Sources, sourceDir, cfg.MaxSourceBytes, sourceTimeout, client)
	fetchCancel()
	if err != nil {
		return reportFailure(parent, client, job, nil, err)
	}
	buildCtx, buildCancel := context.WithTimeout(jobCtx, runner.BuildTimeout)
	result, buildErr := runner.ExecuteWithClient(buildCtx, job, fetched, client)
	buildCancel()
	if result.Cleanup != nil {
		defer result.Cleanup()
	}
	if buildErr != nil {
		if status.cancelled.Load() {
			buildErr = errors.New("build cancelled by coordinator")
		}
		return reportFailure(parent, client, job, &result, buildErr)
	}
	if status.cancelled.Load() {
		return reportFailure(parent, client, job, &result, errors.New("build cancelled by coordinator"))
	}
	if err := sendLogs(parent, client, job, result.Log); err != nil {
		return reportFailure(parent, client, job, &result, err)
	}
	artifactSHA, artifactSize, err := hashFile(result.ArtifactPath)
	if err != nil {
		return reportFailure(parent, client, job, &result, err)
	}
	var artifact *Artifact
	if job.Surface == "binary" {
		file, err := os.Open(result.ArtifactPath)
		if err != nil {
			return reportFailure(parent, client, job, &result, err)
		}
		response, uploadErr := client.uploadArtifact(parent, job.ID, job.LeaseToken, filepath.Base(result.ArtifactPath), file, artifactSize, artifactSHA)
		_ = file.Close()
		if uploadErr != nil {
			return reportFailure(parent, client, job, &result, uploadErr)
		}
		artifact = &Artifact{Key: response.Key, SHA256: response.SHA256, Size: response.Size, Filename: filepath.Base(result.ArtifactPath)}
	}
	finished := time.Now().UTC().Format(time.RFC3339Nano)
	provenance, err := provenanceFor(job, cfg.WorkerID, artifactSHA, result.InstalledSize, result.PackageMetadata, started, finished)
	if err != nil {
		return reportFailure(parent, client, job, &result, err)
	}
	key, err := decodePrivateKey(cfg.PrivateKey)
	if err != nil {
		return err
	}
	complete := CompleteRequest{
		LeaseToken:          job.LeaseToken,
		Status:              "succeeded",
		Artifact:            artifact,
		Provenance:          provenance,
		ProvenanceSignature: signProvenance(provenance, key),
		InstalledSize:       &result.InstalledSize,
		SmokePassed:         result.SmokePassed,
	}
	if err := client.complete(parent, job.ID, complete); err != nil {
		return err
	}
	return nil
}

func reportFailure(ctx context.Context, client *Client, job Job, result *BuildResult, cause error) error {
	if result != nil {
		if err := sendLogs(ctx, client, job, result.Log); err != nil {
			cause = fmt.Errorf("%v; upload logs: %w", cause, err)
		}
	}
	completeErr := client.complete(ctx, job.ID, CompleteRequest{LeaseToken: job.LeaseToken, Status: "failed", Error: compactError(cause), SmokePassed: false})
	if completeErr != nil {
		return fmt.Errorf("%v; complete failure: %w", cause, completeErr)
	}
	return cause
}

func sendLogs(ctx context.Context, client *Client, job Job, text string) error {
	if text == "" {
		return nil
	}
	sequence := 0
	for len(text) > 0 {
		chunk := text
		if len(chunk) > maxLogChunk {
			chunk = chunk[:maxLogChunk]
		}
		if err := client.appendLog(ctx, job.ID, LogRequest{LeaseToken: job.LeaseToken, Sequence: sequence, Text: chunk}); err != nil {
			return err
		}
		text = text[len(chunk):]
		sequence++
	}
	return nil
}

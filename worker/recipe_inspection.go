package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type recipeInspectionReport struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Kind          string              `json:"kind"`
	JobID         string              `json:"jobId"`
	Attempt       int64               `json:"attempt"`
	Capture       inputObject         `json:"capture"`
	Architecture  string              `json:"architecture"`
	ImageRef      string              `json:"imageRef"`
	Host          *nativeHostEvidence `json:"host"`
	Sandbox       struct {
		Network  string `json:"network"`
		ReadOnly bool   `json:"readOnly"`
		User     string `json:"user"`
	} `json:"sandbox"`
	StartedAt     string  `json:"startedAt"`
	FinishedAt    string  `json:"finishedAt"`
	Srcinfo       string  `json:"srcinfo"`
	SrcinfoSHA256 string  `json:"srcinfoSha256"`
	Log           string  `json:"log"`
	Error         *string `json:"error"`
}

func validateRecipeInspectionJob(job Job, cfg Config) error {
	if job.Kind != "recipe-inspection" || job.RecipeCapture == nil || !validInputObject(*job.RecipeCapture, 512<<10) ||
		!idPattern.MatchString(job.ID) || job.LeaseToken == "" || !depNamePattern.MatchString(job.PackageName) || job.Attempt < 1 ||
		job.Architecture != cfg.Architecture || !archPattern.MatchString(job.Architecture) || validateImageReference(job.ImageRef, job.ImageDigest) != nil ||
		job.InputLock != nil || job.OutputContract != nil || job.DependencyPlan != nil || len(job.Sources) != 0 || job.Recipe != "" {
		return errors.New("invalid isolated recipe inspection job")
	}
	expires, err := time.Parse(time.RFC3339, job.LeaseExpiresAt)
	if err != nil || !expires.After(time.Now()) || expires.After(time.Now().Add(12*time.Minute)) {
		return errors.New("recipe inspection lease is invalid or expired")
	}
	return nil
}

func (c *Client) inspectionHeartbeat(ctx context.Context, job Job) (HeartbeatResponse, error) {
	var response HeartbeatResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/worker/inspections/"+url.PathEscape(job.ID)+"/heartbeat", HeartbeatRequest{LeaseToken: job.LeaseToken}, &response)
	return response, err
}

func runRecipeInspection(parent context.Context, client *Client, runner *Runner, cfg Config, job Job) error {
	if err := validateRecipeInspectionJob(job, cfg); err != nil {
		return err
	}
	expires, _ := time.Parse(time.RFC3339, job.LeaseExpiresAt)
	ctx, cancel := context.WithDeadline(parent, expires.Add(-15*time.Second))
	defer cancel()
	status := &heartbeatStatus{}
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				response, err := client.inspectionHeartbeat(ctx, job)
				if err != nil || response.Cancel {
					status.cancelled.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	report := recipeInspectionReport{SchemaVersion: 1, Kind: "recipe-inspection", JobID: job.ID, Attempt: job.Attempt, Capture: *job.RecipeCapture,
		Architecture: job.Architecture, ImageRef: job.ImageRef, StartedAt: time.Now().UTC().Format(time.RFC3339)}
	report.Sandbox.Network = "disabled"
	report.Sandbox.ReadOnly = true
	report.Sandbox.User = "65534:65534"
	err := runner.inspectRecipeCapture(ctx, client, job, &report)
	if status.cancelled.Load() {
		return errors.New("recipe inspection cancelled or lease authority unavailable")
	}
	if err != nil {
		message := compactError(err)
		report.Error = &message
	}
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	report.SrcinfoSHA256 = hashBytes([]byte(report.Srcinfo))
	data, encodeErr := encodeJSON(report)
	if encodeErr != nil {
		return encodeErr
	}
	if len(data) > 2<<20 {
		message := "recipe inspection report exceeds byte budget"
		report.Error = &message
		report.Srcinfo = ""
		report.SrcinfoSHA256 = emptyRecipeSHA
		data, encodeErr = encodeJSON(report)
		if encodeErr != nil {
			return encodeErr
		}
	}
	input := struct {
		LeaseToken string `json:"leaseToken"`
		Report     string `json:"report"`
		Signature  string `json:"signature"`
	}{job.LeaseToken, string(data), base64.StdEncoding.EncodeToString(ed25519.Sign(client.PrivateKey, data))}
	completeCtx, completeCancel := context.WithTimeout(parent, 15*time.Second)
	defer completeCancel()
	var result struct {
		Status string `json:"status"`
	}
	if completeErr := client.doJSON(completeCtx, http.MethodPost, "/api/worker/inspections/"+url.PathEscape(job.ID)+"/complete", input, &result); completeErr != nil {
		return completeErr
	}
	if result.Status != "succeeded" && err == nil {
		return errors.New("recipe metadata failed coordinator inspection checks")
	}
	return err
}

func (r *Runner) inspectRecipeCapture(ctx context.Context, client *Client, job Job, report *recipeInspectionReport) error {
	host, err := r.nativeHost(ctx, job.Architecture)
	if err != nil {
		return err
	}
	report.Host = &host
	jobDir, err := r.createJobDirectory(job.ID)
	if err != nil {
		return err
	}
	defer os.RemoveAll(jobDir)
	workdir := filepath.Join(jobDir, "work")
	if _, err := materializeRecipeCapture(ctx, *job.RecipeCapture, job.PackageName, filepath.Join(jobDir, "objects"), workdir,
		func(ctx context.Context, ref inputObject, path string) error {
			return client.fetchPrivateInput(ctx, "inspections", job, ref, path)
		}); err != nil {
		return err
	}
	if err := r.ensureImageReference(ctx, job.ImageRef, job.ImageDigest, client.inspectionRegistryCredentials, job.ID, job.LeaseToken); err != nil {
		return err
	}
	imageArch, err := r.run(ctx, "image", "inspect", "--format", "{{.Architecture}}", job.ImageRef)
	if err != nil || strings.TrimSpace(imageArch) != map[string]string{"x86_64": "amd64", "aarch64": "arm64"}[job.Architecture] {
		return errors.New("inspection helper is not native for this architecture")
	}
	name := containerName(job.ID+"-"+strconv.FormatInt(job.Attempt, 10), "inspection")
	defer r.removeContainer(name)
	args := r.baseContainerArgsForImage(name, "none", "/recipe", []mount{{Source: workdir, Target: "/recipe", ReadOnly: true}},
		map[string]string{"HOME": "/tmp", "TZ": "UTC", "CARCH": job.Architecture}, "65534:65534", job.ImageRef)
	args = append(args, "/bin/sh", "-ceu", recipeInspectionScript)
	evalCtx, evalCancel := context.WithTimeout(ctx, time.Minute)
	defer evalCancel()
	command := r.command(evalCtx, args...)
	stdout := &boundedBuffer{limit: 1 << 20}
	stderr := &boundedBuffer{limit: 128 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	err = command.Run()
	report.Log = strings.ToValidUTF8(stderr.data.String(), "\uFFFD")
	report.Srcinfo = stdout.String()
	if stdout.truncated || stderr.truncated || !utf8.ValidString(report.Srcinfo) {
		report.Srcinfo = ""
		return errors.New("recipe inspection output is oversized or is not UTF-8")
	}
	for _, char := range report.Srcinfo {
		if (char < 32 && char != '\n' && char != '\t') || char == 127 {
			report.Srcinfo = ""
			return errors.New("recipe metadata contains invalid control characters")
		}
	}
	if err != nil {
		return fmt.Errorf("isolated recipe inspection failed: %w", err)
	}
	return nil
}

// makepkg checks writable destinations even for metadata-only inspection.
// All writes stay in temporary container storage; the recipe mount stays read-only.
const recipeInspectionScript = `mkdir /tmp/inspection
cp /etc/makepkg.conf /tmp/inspection/makepkg.conf
printf '\nBUILDDIR=/tmp/inspection\nPKGDEST=/tmp/inspection\nSRCDEST=/tmp/inspection\nSRCPKGDEST=/tmp/inspection\nLOGDEST=/tmp/inspection\n' >> /tmp/inspection/makepkg.conf
exec /usr/bin/makepkg --config /tmp/inspection/makepkg.conf --printsrcinfo
`

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxRepositoryDatabaseBytes = 128 << 20

type TransactionOptions struct {
	ManifestURL  string
	DiscoveryURL string
	ConfigPath   string
	StatePath    string
	StageDir     string
	Pacman       string
}

type stageMetadata struct {
	SchemaVersion      int    `json:"schemaVersion"`
	ManifestURL        string `json:"manifestUrl"`
	SignatureURL       string `json:"signatureUrl,omitempty"`
	Channel            string `json:"channel"`
	ManifestSHA256     string `json:"manifestSha256"`
	BaseConfigSHA256   string `json:"baseConfigSha256"`
	StagedConfig       string `json:"stagedConfig"`
	PlanPath           string `json:"planPath"`
	PlanSHA256         string `json:"planSha256"`
	StagedAt           int64  `json:"stagedAt"`
	RollbackAuthorized bool   `json:"rollbackAuthorized"`
}

type commitMarker struct {
	SchemaVersion int        `json:"schemaVersion"`
	ConfigPath    string     `json:"configPath"`
	StagedConfig  string     `json:"stagedConfig"`
	StatePath     string     `json:"statePath"`
	ConfigMode    uint32     `json:"configMode"`
	State         LocalState `json:"state"`
}

func (c *Client) Stage(ctx context.Context, options TransactionOptions) (Transaction, string, error) {
	if (options.ManifestURL == "" && options.DiscoveryURL == "" && (c.discoveryOrigin == "" || c.expectedChannel == "")) || options.ConfigPath == "" || options.StatePath == "" || options.StageDir == "" || options.Pacman == "" {
		return Transaction{}, "", errors.New("manifest, config, state, stage and pacman paths are required")
	}
	if err := recoverPending(options); err != nil {
		return Transaction{}, "", err
	}
	resolved, err := c.resolveRequestedRef(ctx, options.ManifestURL, options.DiscoveryURL)
	if err != nil {
		return Transaction{}, "", err
	}
	tx, err := c.resolveAt(ctx, resolved.ManifestURL, resolved.SignatureURL)
	if err != nil {
		return Transaction{}, "", err
	}
	if err := c.validateTimes(tx); err != nil {
		return Transaction{}, "", err
	}
	storedState, err := readState(options.StatePath)
	if err != nil {
		return Transaction{}, "", err
	}
	state := stateForChannel(storedState, tx.Channel)
	rollbackAuthorized := rollbackAllowed(state, tx)
	if err := validateFreshness(state, tx, rollbackAuthorized); err != nil {
		return Transaction{}, "", err
	}
	config, mode, err := readConfig(options.ConfigPath)
	if err != nil {
		return Transaction{}, "", err
	}
	configDigest := sha256Hex(config)
	rendered, err := rewriteConfig(config, tx.Repositories)
	if err != nil {
		return Transaction{}, "", err
	}
	if err := c.verifyRepositorySnapshots(ctx, resolved.ManifestURL, tx); err != nil {
		return Transaction{}, "", err
	}
	if err := os.MkdirAll(options.StageDir, 0o700); err != nil {
		return Transaction{}, "", err
	}
	stagedConfig := filepath.Join(options.StageDir, "pacman.conf")
	planPath := filepath.Join(options.StageDir, "transaction-plan.txt")
	metadataPath := filepath.Join(options.StageDir, "metadata.json")
	_ = os.Remove(metadataPath)
	_ = os.Remove(planPath)
	if err := atomicWrite(stagedConfig, rendered, mode); err != nil {
		return Transaction{}, "", err
	}
	plan, err := runPacmanPreview(ctx, options.Pacman, stagedConfig, tx, rollbackAuthorized)
	if err != nil {
		_ = atomicWrite(planPath, []byte(plan), 0o600)
		return Transaction{}, "", fmt.Errorf("pacman transaction preview failed: %w", err)
	}
	if err := atomicWrite(planPath, []byte(plan), 0o600); err != nil {
		return Transaction{}, "", err
	}
	metadata := stageMetadata{SchemaVersion: 1, ManifestURL: resolved.ManifestURL, SignatureURL: resolved.SignatureURL, ManifestSHA256: tx.Digest, Channel: tx.Channel,
		BaseConfigSHA256: configDigest, StagedConfig: stagedConfig, PlanPath: planPath, StagedAt: c.now().Unix(), RollbackAuthorized: rollbackAuthorized}
	metadata.PlanSHA256 = sha256Hex([]byte(plan))
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return Transaction{}, "", err
	}
	if err := atomicWrite(metadataPath, metadataJSON, 0o600); err != nil {
		return Transaction{}, "", err
	}
	return tx, plan, nil
}

func (c *Client) Apply(ctx context.Context, options TransactionOptions) (Transaction, error) {
	if err := recoverPending(options); err != nil {
		return Transaction{}, err
	}
	metadataPath := filepath.Join(options.StageDir, "metadata.json")
	metadataBytes, err := os.ReadFile(metadataPath)
	if err != nil {
		return Transaction{}, fmt.Errorf("read staged transaction: %w", err)
	}
	var metadata stageMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil || metadata.SchemaVersion != 1 {
		return Transaction{}, errors.New("staged transaction metadata is invalid")
	}
	if metadata.ManifestURL == "" || metadata.ManifestSHA256 == "" {
		return Transaction{}, errors.New("staged transaction metadata is incomplete")
	}
	tx, err := c.resolveAt(ctx, metadata.ManifestURL, metadata.SignatureURL)
	if err != nil {
		return Transaction{}, err
	}
	if tx.Digest != metadata.ManifestSHA256 {
		return Transaction{}, errors.New("staged manifest bytes changed")
	}
	if metadata.Channel != "" && metadata.Channel != tx.Channel {
		return Transaction{}, errors.New("staged channel changed")
	}
	if err := c.validateTimes(tx); err != nil {
		return Transaction{}, err
	}
	storedState, err := readState(options.StatePath)
	if err != nil {
		return Transaction{}, err
	}
	state := stateForChannel(storedState, tx.Channel)
	rollbackAuthorized := rollbackAllowed(state, tx)
	if err := validateFreshness(state, tx, rollbackAuthorized); err != nil {
		return Transaction{}, err
	}
	config, mode, err := readConfig(options.ConfigPath)
	if err != nil {
		return Transaction{}, err
	}
	if sha256Hex(config) != metadata.BaseConfigSHA256 {
		return Transaction{}, errors.New("pacman config changed after review; restage transaction")
	}
	if metadata.StagedConfig == "" {
		return Transaction{}, errors.New("staged config path is missing")
	}
	if metadata.PlanPath == "" || metadata.PlanSHA256 == "" {
		return Transaction{}, errors.New("staged transaction review plan is incomplete")
	}
	planBytes, err := os.ReadFile(metadata.PlanPath)
	if err != nil || sha256Hex(planBytes) != metadata.PlanSHA256 {
		return Transaction{}, errors.New("staged review plan changed; restage transaction")
	}
	if _, err := os.Stat(metadata.StagedConfig); err != nil {
		return Transaction{}, fmt.Errorf("staged pacman config is unavailable: %w", err)
	}
	if err := c.verifyRepositorySnapshots(ctx, metadata.ManifestURL, tx); err != nil {
		return Transaction{}, err
	}
	args := []string{"--config", metadata.StagedConfig, "--sync", "--sysupgrade", "--refresh"}
	if rollbackAuthorized {
		// Pacman requires the second --sysupgrade switch before downgrades are
		// considered. The signed rollback control is checked above.
		args = append(args, "--sysupgrade")
	}
	command := exec.CommandContext(ctx, options.Pacman, args...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		return Transaction{}, fmt.Errorf("pacman transaction failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	newConfig, err := os.ReadFile(metadata.StagedConfig)
	if err != nil {
		return Transaction{}, fmt.Errorf("read staged pacman config after transaction: %w", err)
	}
	systemSequence, oprSequence := tx.SystemRef.Sequence, tx.OPRRef.Sequence
	if state.SystemSequence > systemSequence {
		systemSequence = state.SystemSequence
	}
	if state.OPRSequence > oprSequence {
		oprSequence = state.OPRSequence
	}
	recoveryTarget := tx.Recovery.FromDigest
	if tx.Recovery.Target != nil {
		recoveryTarget = tx.Recovery.Target.Digest
	}
	state = LocalState{SchemaVersion: 1, ManifestSHA256: tx.Digest, ReleaseID: tx.ReleaseID,
		Channel:       tx.Channel,
		SystemVersion: tx.Identity.Version, OPRGeneration: tx.Identity.Generation, Architecture: tx.Architecture,
		SystemManifestSHA256: tx.SystemRef.Digest, OPRManifestSHA256: tx.OPRRef.Digest,
		Sequence: tx.Sequence, SystemSequence: systemSequence, OPRSequence: oprSequence,
		AppliedAt: c.now().Unix(), ConfigSHA256: sha256Hex(newConfig),
		RecoveryTarget: recoveryTarget, RecoveryLimits: strings.Join(tx.Recovery.Constraints, "; ")}
	saveChannelState(&storedState, tx.Channel, state)
	marker := commitMarker{SchemaVersion: 1, ConfigPath: options.ConfigPath, StagedConfig: metadata.StagedConfig, StatePath: options.StatePath, ConfigMode: uint32(mode.Perm()), State: storedState}
	markerJSON, err := json.Marshal(marker)
	if err != nil {
		return Transaction{}, err
	}
	if err := atomicWrite(options.StatePath+".commit", markerJSON, 0o600); err != nil {
		return Transaction{}, fmt.Errorf("persist commit marker: %w", err)
	}
	if err := recoverPending(options); err != nil {
		return Transaction{}, err
	}
	return tx, nil
}

func (c *Client) verifyRepositorySnapshots(ctx context.Context, manifestURL string, tx Transaction) error {
	for _, repository := range tx.Repositories {
		bytes, err := c.fetch(ctx, repository.DBURL, maxRepositoryDatabaseBytes)
		if err != nil {
			return fmt.Errorf("fetch %s repository database: %w", repository.Name, err)
		}
		if sha256Hex(bytes) != strings.ToLower(repository.SnapshotDigest) {
			return fmt.Errorf("%s repository database digest does not match manifest", repository.Name)
		}
		signature, err := c.fetch(ctx, repository.SignatureURL, maxSignatureBytes)
		if err != nil {
			return fmt.Errorf("fetch %s repository signature: %w", repository.Name, err)
		}
		if err := verifyOpenPGP(c.key, c.fingerprint, bytes, signature); err != nil {
			return fmt.Errorf("verify %s repository signature: %w", repository.Name, err)
		}
		if err := validateSameOrigin(manifestURL, repository.DBURL); err != nil {
			return err
		}
	}
	return nil
}

func runPacmanPreview(ctx context.Context, binary, config string, tx Transaction, rollbackAuthorized bool) (string, error) {
	args := []string{"--config", config, "--sync", "--sysupgrade", "--refresh", "--print"}
	if rollbackAuthorized {
		args = append(args, "--sysupgrade")
	}
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.CombinedOutput()
	if len(output) > maxPlanBytes {
		return string(output[:maxPlanBytes]), errors.New("pacman transaction preview exceeds size limit")
	}
	var plan strings.Builder
	fmt.Fprintf(&plan, "Release: %s\n", tx.ReleaseID)
	fmt.Fprintf(&plan, "System: %s\n", tx.Identity.Version)
	fmt.Fprintf(&plan, "OPR: %s\n", tx.Identity.Generation)
	fmt.Fprintf(&plan, "Architecture: %s\n", tx.Architecture)
	fmt.Fprintf(&plan, "Manifest: %s\n", tx.Digest)
	constraints := strings.Join(tx.Recovery.Constraints, "; ")
	if constraints == "" {
		constraints = "downgrade blocked unless a signed recovery transaction authorizes it"
	}
	fmt.Fprintf(&plan, "Recovery: %s\n", constraints)
	plan.WriteString("Repositories (signed order):\n")
	for _, repository := range tx.Repositories {
		fmt.Fprintf(&plan, "  %s %s\n", repository.Name, repository.PackageBaseURL)
	}
	plan.WriteString("\nPacman preview:\n")
	plan.Write(output)
	return plan.String(), err
}

func rollbackAllowed(state LocalState, tx Transaction) bool {
	return tx.Recovery.Authorized && tx.Recovery.Reason != "" && tx.Recovery.Target != nil && state.ManifestSHA256 != "" && tx.Recovery.FromDigest == state.ManifestSHA256 && tx.Sequence > state.Sequence
}

func readState(path string) (LocalState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return LocalState{}, nil
	}
	if err != nil {
		return LocalState{}, err
	}
	var state LocalState
	if err := json.Unmarshal(data, &state); err != nil || state.SchemaVersion != 1 {
		return LocalState{}, errors.New("local manifest state is invalid")
	}
	if !sha256Pattern.MatchString(state.ManifestSHA256) || state.Sequence == 0 {
		return LocalState{}, errors.New("local manifest state has invalid identity")
	}
	return state, nil
}

func writeState(path string, state LocalState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, 0o600)
}

func recoverPending(options TransactionOptions) error {
	markerPath := options.StatePath + ".commit"
	data, err := os.ReadFile(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var marker commitMarker
	if err := json.Unmarshal(data, &marker); err != nil || marker.SchemaVersion != 1 || marker.ConfigPath != options.ConfigPath || marker.StatePath != options.StatePath || marker.StagedConfig == "" {
		return errors.New("pending manifest commit marker is invalid")
	}
	config, err := os.ReadFile(marker.StagedConfig)
	if err != nil {
		return fmt.Errorf("recover pending staged config: %w", err)
	}
	if marker.State.ConfigSHA256 == "" || sha256Hex(config) != marker.State.ConfigSHA256 {
		return errors.New("pending manifest commit config digest is invalid")
	}
	mode := os.FileMode(marker.ConfigMode)
	if mode == 0 {
		mode = 0o644
	}
	if err := atomicWrite(marker.ConfigPath, config, mode); err != nil {
		return fmt.Errorf("recover pending pacman config: %w", err)
	}
	if err := writeState(marker.StatePath, marker.State); err != nil {
		return fmt.Errorf("recover pending manifest state: %w", err)
	}
	return os.Remove(markerPath)
}

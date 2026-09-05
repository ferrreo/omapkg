package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func defaultConfigPath() string {
	if state := os.Getenv("OPR_WORKER_STATE_DIR"); state != "" {
		return filepath.Join(state, "config.json")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "opr-worker", "config.json")
	}
	return "/etc/opr-worker/config.json"
}

func loadConfig(filename string) (Config, error) {
	filename, err := filepath.Abs(filename)
	if err != nil {
		return Config{}, err
	}
	linkInfo, err := os.Lstat(filename)
	if err != nil {
		return Config{}, err
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return Config{}, errors.New("config must be a regular file")
	}
	info, err := os.Stat(filename)
	if err != nil {
		return Config{}, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Config{}, fmt.Errorf("config %s is accessible by group or others", filename)
	}
	f, err := os.Open(filename)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	var cfg Config
	decoder := json.NewDecoder(io.LimitReader(f, 1<<20))
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	if filepath.Clean(cfg.StateDir) != filepath.Clean(filepath.Dir(filename)) {
		return Config{}, errors.New("config stateDir must be its parent directory")
	}
	return cfg, nil
}

func saveConfig(filename string, cfg Config) error {
	filename, err := filepath.Abs(filename)
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	dir := filepath.Dir(filename)
	if cfg.StateDir != "" && filepath.Clean(cfg.StateDir) != filepath.Clean(dir) {
		return errors.New("config stateDir must be its parent directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if info, err := os.Lstat(dir); err != nil {
		return fmt.Errorf("stat config directory: %w", err)
	} else if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("config directory must be a real directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect config directory: %w", err)
	}
	if info, err := os.Stat(dir); err != nil {
		return fmt.Errorf("stat config directory: %w", err)
	} else if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("config directory %s is accessible by group or others", dir)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create config temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod config temp file: %w", err)
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(cfg); err != nil {
		tmp.Close()
		return fmt.Errorf("encode config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close config temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod config: %w", err)
	}
	if err := os.Rename(tmpName, filename); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maxDependencyPlanPackages         = 64
	maxDependencyPackageBytes   int64 = 4 << 30
	maxDependencyPlanBytes      int64 = 8 << 30
	maxDependencyAuxiliaryBytes int64 = 1 << 20
)

var (
	dependencyFingerprintPattern = regexp.MustCompile(`^[A-Fa-f0-9]{40}$`)
	dependencyFilenamePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+:%~^\-]{0,220}\.pkg\.tar\.zst$`)
)

func validateDependencyPlan(plan *DependencyPlan, job Job, originRaw string) error {
	if plan == nil {
		return nil
	}
	if plan.Channel != "stable" && plan.Channel != "dev" {
		return errors.New("dependency plan channel must be stable or dev")
	}
	if !dependencyFingerprintPattern.MatchString(plan.PublicKeyFingerprint) {
		return errors.New("dependency plan public key fingerprint must be 40 hexadecimal characters")
	}
	origin, err := url.Parse(originRaw)
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" {
		return errors.New("dependency plan requires an HTTPS worker origin")
	}
	if err := validateDependencyURL(plan.PublicKeyURL, origin, "/repo/key.asc", "public key URL"); err != nil {
		return err
	}
	if len(plan.Packages) == 0 || len(plan.Packages) > maxDependencyPlanPackages {
		return fmt.Errorf("dependency plan must contain 1 to %d packages", maxDependencyPlanPackages)
	}
	var total int64
	seenRelease := make(map[string]struct{}, len(plan.Packages))
	seenName := make(map[string]struct{}, len(plan.Packages))
	seenFilename := make(map[string]struct{}, len(plan.Packages))
	for _, item := range plan.Packages {
		if !idPattern.MatchString(item.ReleaseID) {
			return errors.New("dependency plan release ID is invalid")
		}
		if _, exists := seenRelease[item.ReleaseID]; exists {
			return errors.New("dependency plan contains duplicate release IDs")
		}
		seenRelease[item.ReleaseID] = struct{}{}
		if !depNamePattern.MatchString(item.Name) {
			return errors.New("dependency plan package name is invalid")
		}
		nameKey := item.Name + ":" + item.Architecture
		if _, exists := seenName[nameKey]; exists {
			return errors.New("dependency plan contains duplicate package names")
		}
		seenName[nameKey] = struct{}{}
		if !validArchVersion(item.Version) {
			return errors.New("dependency plan package version is invalid")
		}
		if item.Architecture != job.Architecture {
			return errors.New("dependency plan package architecture does not match job")
		}
		if !dependencyFilenamePattern.MatchString(item.Filename) || item.Filename != item.Name+"-"+item.Version+"-"+item.Architecture+".pkg.tar.zst" {
			return errors.New("dependency plan package filename does not match package identity")
		}
		if _, exists := seenFilename[item.Filename]; exists {
			return errors.New("dependency plan contains duplicate package filenames")
		}
		seenFilename[item.Filename] = struct{}{}
		if !sha256Pattern.MatchString(item.SHA256) || !sha256Pattern.MatchString(item.SignatureSHA256) {
			return errors.New("dependency plan package checksum is invalid")
		}
		if item.Size <= 0 || item.Size > maxDependencyPackageBytes || total > maxDependencyPlanBytes-item.Size {
			return errors.New("dependency plan package size exceeds limit")
		}
		total += item.Size
		packagePaths := dependencyPackagePaths(plan.Channel, item.Architecture, item.Filename)
		if err := validateDependencyURLAny(item.URL, origin, packagePaths, "dependency package URL"); err != nil {
			return err
		}
		signaturePaths := make([]string, len(packagePaths))
		for index, packagePath := range packagePaths {
			signaturePaths[index] = packagePath + ".sig"
		}
		if err := validateDependencyURLAny(item.SignatureURL, origin, signaturePaths, "dependency signature URL"); err != nil {
			return err
		}
	}
	return nil
}

func dependencyPackagePath(channel, architecture, filename string) string {
	if channel == "dev" {
		return "/repo/dev/" + architecture + "/" + filename
	}
	return "/repo/" + architecture + "/" + filename
}

func dependencyPackagePaths(channel, architecture, filename string) []string {
	path := dependencyPackagePath(channel, architecture, filename)
	if channel == "dev" {
		return []string{path, dependencyPackagePath("stable", architecture, filename)}
	}
	return []string{path}
}

func validateDependencyURL(raw string, origin *url.URL, expectedPath, label string) error {
	return validateDependencyURLAny(raw, origin, []string{expectedPath}, label)
}

func validateDependencyURLAny(raw string, origin *url.URL, expectedPaths []string, label string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be an HTTPS URL without credentials or query parameters", label)
	}
	if !sameOrigin(u, origin) {
		return fmt.Errorf("%s must use the worker origin", label)
	}
	if err := validateSourceURL(raw); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	validPath := false
	for _, expectedPath := range expectedPaths {
		if u.Path == expectedPath {
			validPath = true
			break
		}
	}
	if !validPath {
		return fmt.Errorf("%s is outside the approved repository path", label)
	}
	return nil
}

func materializeDependencyPlan(ctx context.Context, plan *DependencyPlan, job Job, originRaw, directory string) error {
	if err := validateDependencyPlan(plan, job, originRaw); err != nil {
		return err
	}
	if plan == nil {
		return nil
	}
	origin, err := url.Parse(originRaw)
	if err != nil {
		return fmt.Errorf("parse dependency plan origin: %w", err)
	}
	return materializeDependencyPlanWithClient(ctx, plan, job, origin, directory, safeSameOriginHTTPClient(origin))
}

func materializeDependencyPlanWithClient(ctx context.Context, plan *DependencyPlan, job Job, origin *url.URL, directory string, client *http.Client) error {
	if plan == nil {
		return nil
	}
	if origin == nil || client == nil {
		return errors.New("dependency plan origin and HTTP client are required")
	}
	if err := validateDependencyPlan(plan, job, origin.String()); err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create dependency plan directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect dependency plan directory: %w", err)
	}
	keyPath := filepath.Join(directory, "public-key")
	if err := fetchDependencyKey(ctx, client, plan.PublicKeyURL, origin, keyPath); err != nil {
		return err
	}
	planFile, err := os.OpenFile(filepath.Join(directory, "plan.tsv"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create dependency plan manifest: %w", err)
	}
	defer planFile.Close()
	for _, item := range plan.Packages {
		packagePath := filepath.Join(directory, item.Filename)
		if err := fetchDependencyObject(ctx, client, item.URL, item.SHA256, item.Size, maxDependencyPackageBytes, packagePath); err != nil {
			return fmt.Errorf("fetch dependency package %s: %w", item.Name, err)
		}
		signaturePath := packagePath + ".sig"
		if err := fetchDependencyObject(ctx, client, item.SignatureURL, item.SignatureSHA256, 0, maxDependencyAuxiliaryBytes, signaturePath); err != nil {
			return fmt.Errorf("fetch dependency signature %s: %w", item.Name, err)
		}
		if _, err := fmt.Fprintf(planFile, "%s\t%s\t%s\t%s\n", item.Name, item.Version, item.Architecture, item.Filename); err != nil {
			return fmt.Errorf("write dependency plan manifest: %w", err)
		}
	}
	if err := planFile.Sync(); err != nil {
		return fmt.Errorf("sync dependency plan manifest: %w", err)
	}
	return nil
}

func safeSameOriginHTTPClient(origin *url.URL) *http.Client {
	client := safeSourceHTTPClient()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 {
			return errors.New("dependency URLs must not redirect")
		}
		if !sameOrigin(req.URL, origin) {
			return errors.New("dependency URL redirected to another origin")
		}
		return validateSourceURL(req.URL.String())
	}
	return client
}

func fetchDependencyObject(ctx context.Context, client *http.Client, rawURL, checksum string, expectedSize, maxBytes int64, destination string) error {
	tempName := "dependency-download-" + hashBytes([]byte(rawURL))[:16]
	tempPath := filepath.Join(filepath.Dir(destination), tempName)
	if err := fetchSource(ctx, client, Source{Name: tempName, URL: rawURL, SHA256: checksum}, tempPath, maxBytes); err != nil {
		return err
	}
	info, err := os.Stat(tempPath)
	if err != nil {
		return fmt.Errorf("stat downloaded dependency: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || (expectedSize > 0 && info.Size() != expectedSize) {
		_ = os.Remove(tempPath)
		return errors.New("downloaded dependency size does not match plan")
	}
	if err := os.Rename(tempPath, destination); err != nil {
		return fmt.Errorf("install downloaded dependency: %w", err)
	}
	return nil
}

func fetchDependencyKey(ctx context.Context, client *http.Client, rawURL string, origin *url.URL, destination string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("create dependency key request: %w", err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "opr-worker/1")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch dependency key: %w", err)
	}
	if resp == nil || resp.Body == nil {
		return errors.New("fetch dependency key returned no body")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dependency key returned %s", resp.Status)
	}
	if resp.Request == nil || !sameOrigin(resp.Request.URL, origin) {
		return errors.New("dependency key response origin changed")
	}
	if encoding := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding"))); encoding != "" && encoding != "identity" {
		return errors.New("dependency key response is compressed")
	}
	if resp.ContentLength > maxDependencyAuxiliaryBytes {
		return errors.New("dependency key exceeds 1 MiB")
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".dependency-key-*")
	if err != nil {
		return fmt.Errorf("create dependency key temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("protect dependency key temporary file: %w", err)
	}
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxDependencyAuxiliaryBytes+1))
	if err != nil {
		tmp.Close()
		return fmt.Errorf("save dependency key: %w", err)
	}
	if n <= 0 || n > maxDependencyAuxiliaryBytes {
		tmp.Close()
		return errors.New("dependency key size is invalid")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync dependency key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close dependency key: %w", err)
	}
	if err := os.Rename(tmpName, destination); err != nil {
		return fmt.Errorf("install dependency key: %w", err)
	}
	return nil
}

func dependencyPrepScript(dependencies []string, plan *DependencyPlan) (string, error) {
	var script strings.Builder
	script.WriteString("set -eu\n")
	script.WriteString("command -v pacman >/dev/null 2>&1\n")
	script.WriteString("pacman_conf=/tmp/opr-pacman.conf\n")
	script.WriteString("missing_dependencies=/tmp/opr-missing-dependencies\n")
	script.WriteString("keycheck=/tmp/opr-dependency-keycheck\n")
	script.WriteString("keyring=/tmp/opr-pacman-gnupg\n")
	script.WriteString("cleanup() { rm -rf \"$keycheck\" \"$keyring\" \"$pacman_conf\" \"$missing_dependencies\"; }\n")
	script.WriteString("trap cleanup EXIT\n")
	script.WriteString("cp /etc/pacman.conf \"$pacman_conf\"\n")
	script.WriteString("sed -i '/^[#[:space:]]*GPGDir[[:space:]]*=/d; /^[#[:space:]]*LocalFileSigLevel[[:space:]]*=/d; /^[#[:space:]]*DownloadUser[[:space:]]*=/d; /^[#[:space:]]*DisableSandboxSyscalls[[:space:]]*$/d' \"$pacman_conf\"\n")
	if plan != nil {
		script.WriteString("command -v gpg >/dev/null 2>&1\n")
		script.WriteString("mkdir -m 700 \"$keycheck\" \"$keyring\"\n")
		script.WriteString("gpg --batch --homedir \"$keycheck\" --import /opr/dependencies/public-key >/dev/null\n")
		script.WriteString("primary_count=$(gpg --batch --homedir \"$keycheck\" --with-colons --list-keys | awk -F: '$1 == \"pub\" { count++ } END { print count + 0 }')\n")
		script.WriteString("test \"$primary_count\" = 1\n")
		script.WriteString("actual_fingerprint=$(gpg --batch --homedir \"$keycheck\" --with-colons --fingerprint | awk -F: '$1 == \"fpr\" { print toupper($10); exit }')\n")
		script.WriteString("expected_fingerprint=$(printf '%s' \"$OPR_DEP_KEY_FINGERPRINT\" | tr '[:lower:]' '[:upper:]')\n")
		script.WriteString("test \"$actual_fingerprint\" = \"$expected_fingerprint\"\n")
		script.WriteString("while IFS= read -r package; do gpg --batch --quiet --homedir \"$keycheck\" --verify \"$package.sig\" \"$package\" >/dev/null; done < <(find /opr/dependencies -maxdepth 1 -type f -name '*.pkg.tar.zst' -print | sort)\n")
		script.WriteString("cp -a /etc/pacman.d/gnupg/. \"$keyring/\"\n")
		script.WriteString("pacman-key --gpgdir \"$keyring\" --add /opr/dependencies/public-key >/dev/null\n")
		script.WriteString("printf '%s:6:\\n' \"$OPR_DEP_KEY_FINGERPRINT\" | gpg --batch --homedir \"$keyring\" --import-ownertrust >/dev/null\n")
		script.WriteString("pacman-key --gpgdir \"$keyring\" --updatedb >/dev/null\n")
		script.WriteString("sed -i '/^\\[options\\]$/a GPGDir = /tmp/opr-pacman-gnupg\\nLocalFileSigLevel = Required\\nDownloadUser = root\\nDisableSandboxSyscalls' \"$pacman_conf\"\n")
		script.WriteString("set -- /opr/dependencies/*.pkg.tar.zst\n")
		script.WriteString("pacman --config \"$pacman_conf\" -U --noconfirm -- \"$@\"\n")
		script.WriteString("while IFS=$(printf '\\t') read -r expected_name expected_version expected_arch expected_filename; do\n")
		script.WriteString("  test -f \"/opr/dependencies/$expected_filename\"\n")
		script.WriteString("  package_info=$(pacman --config \"$pacman_conf\" -Qi -- \"$expected_name\")\n")
		script.WriteString("  field() { printf '%s\\n' \"$package_info\" | awk -F: -v key=\"$1\" '$1 ~ \"^[[:space:]]*\" key \"[[:space:]]*$\" { sub(/^[^:]*:[[:space:]]*/, \"\", $0); print; exit }'; }\n")
		script.WriteString("  test \"$(field Name)\" = \"$expected_name\"\n")
		script.WriteString("  test \"$(field Version)\" = \"$expected_version\"\n")
		script.WriteString("  test \"$(field Architecture)\" = \"$expected_arch\"\n")
		script.WriteString("done < /opr/dependencies/plan.tsv\n")
	} else {
		script.WriteString("sed -i '/^\\[options\\]$/a DownloadUser = root\\nDisableSandboxSyscalls' \"$pacman_conf\"\n")
	}
	if len(dependencies) > 0 {
		quoted := mapShellQuote(dependencies)
		script.WriteString("if pacman")
		script.WriteString(" --config \"$pacman_conf\"")
		script.WriteString(" -T -- " + strings.Join(quoted, " ") + " > \"$missing_dependencies\"; then\n")
		script.WriteString("  :\nelse\n  status=$?\n  test \"$status\" -eq 127\n")
		script.WriteString("  mapfile -t missing_args < \"$missing_dependencies\"\n")
		script.WriteString("  test \"${#missing_args[@]}\" -gt 0\n")
		script.WriteString("  pacman --config \"$pacman_conf\"")
		script.WriteString(" -S --noconfirm --needed -- \"${missing_args[@]}\"\nfi\n")
	}
	if plan != nil {
		script.WriteString("pacman --config \"$pacman_conf\" -Scc --noconfirm\n")
	}
	return script.String(), nil
}

func mapShellQuote(values []string) []string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = dependencyShellQuote(value)
	}
	return quoted
}

func dependencyShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

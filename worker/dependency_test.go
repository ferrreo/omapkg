package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func dependencyPlanFixture() (*DependencyPlan, Job) {
	packageName := "opr-lib"
	version := "1.2-1"
	filename := packageName + "-" + version + "-x86_64.pkg.tar.zst"
	return &DependencyPlan{
		Channel:              "stable",
		PublicKeyURL:         "https://omapkg.example/repo/key.asc",
		PublicKeyFingerprint: strings.Repeat("A", 40),
		Packages: []DependencyPackage{{
			ReleaseID:       "release-1",
			Name:            packageName,
			Version:         version,
			Architecture:    "x86_64",
			Filename:        filename,
			URL:             "https://omapkg.example/repo/x86_64/" + filename,
			SHA256:          strings.Repeat("b", 64),
			Size:            123,
			SignatureURL:    "https://omapkg.example/repo/x86_64/" + filename + ".sig",
			SignatureSHA256: strings.Repeat("c", 64),
		}},
	}, Job{Architecture: "x86_64"}
}

func TestValidateDependencyPlanBindsExactPublishedPaths(t *testing.T) {
	plan, job := dependencyPlanFixture()
	if err := validateDependencyPlan(plan, job, "https://omapkg.example"); err != nil {
		t.Fatal(err)
	}
	wrong := *plan
	wrong.Packages = append([]DependencyPackage(nil), plan.Packages...)
	wrong.Packages[0].URL = "https://other.example/repo/x86_64/" + wrong.Packages[0].Filename
	if err := validateDependencyPlan(&wrong, job, "https://omapkg.example"); err == nil {
		t.Fatal("dependency package from another origin was accepted")
	}
	wrong = *plan
	wrong.Packages = append([]DependencyPackage(nil), plan.Packages...)
	wrong.Packages[0].SignatureURL = "https://omapkg.example/repo/dev/x86_64/" + wrong.Packages[0].Filename + ".sig"
	if err := validateDependencyPlan(&wrong, job, "https://omapkg.example"); err == nil {
		t.Fatal("signature from another channel was accepted")
	}
	wrong = *plan
	wrong.Packages = append([]DependencyPackage(nil), plan.Packages...)
	wrong.Packages[0].Architecture = "aarch64"
	if err := validateDependencyPlan(&wrong, job, "https://omapkg.example"); err == nil {
		t.Fatal("dependency for another architecture was accepted")
	}
	wrong = *plan
	wrong.Packages = make([]DependencyPackage, maxDependencyPlanPackages+1)
	if err := validateDependencyPlan(&wrong, job, "https://omapkg.example"); err == nil {
		t.Fatal("oversized dependency plan was accepted")
	}
}

func TestDevelopmentDependencyPlanAllowsStableFallback(t *testing.T) {
	plan, job := dependencyPlanFixture()
	plan.Channel = "dev"
	if err := validateDependencyPlan(plan, job, "https://omapkg.example"); err != nil {
		t.Fatalf("dev package path rejected: %v", err)
	}
	plan.Packages[0].URL = strings.Replace(plan.Packages[0].URL, "/repo/x86_64/", "/repo/dev/x86_64/", 1)
	plan.Packages[0].SignatureURL = strings.Replace(plan.Packages[0].SignatureURL, "/repo/x86_64/", "/repo/dev/x86_64/", 1)
	if err := validateDependencyPlan(plan, job, "https://omapkg.example"); err != nil {
		t.Fatalf("dev package path rejected: %v", err)
	}
	plan.Channel = "stable"
	if err := validateDependencyPlan(plan, job, "https://omapkg.example"); err == nil {
		t.Fatal("stable plan accepted a dev package path")
	}
}

func TestDependencyPrepScriptVerifiesPlanAndKeepsNoNodeps(t *testing.T) {
	plan, _ := dependencyPlanFixture()
	script, err := dependencyPrepScript([]string{"glibc>=2.0"}, plan)
	if err != nil {
		t.Fatal(err)
	}
	check := exec.Command("bash", "-n")
	check.Stdin = bytes.NewBufferString(script)
	if output, err := check.CombinedOutput(); err != nil {
		t.Fatalf("generated prep script is invalid: %v\n%s", err, output)
	}
	for _, required := range []string{
		"gpg --batch",
		"--verify",
		"pacman-key --gpgdir",
		"pacman --config \"$pacman_conf\" -U --noconfirm --",
		"pacman --config \"$pacman_conf\" -T",
		"pacman --config \"$pacman_conf\" -S --noconfirm --needed -- \"${missing_args[@]}\"",
		"pacman --config \"$pacman_conf\" -Scc --noconfirm",
		"trap cleanup EXIT",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("prep script missing %q:\n%s", required, script)
		}
	}
	if strings.Contains(script, "--nodeps") {
		t.Fatal("prep script disables dependency validation")
	}
}

func TestDependencyPrepScriptInstallsOnlyPacmanMissingRelations(t *testing.T) {
	plan, _ := dependencyPlanFixture()
	script, err := dependencyPrepScript([]string{"opr-lib=1.2-1", "tree"}, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, " -S ") && strings.Contains(line, "opr-lib=1.2-1") {
			t.Fatalf("native pacman install reattempts hosted dependency: %s", line)
		}
	}
	if !strings.Contains(script, "mapfile -t missing_args") || !strings.Contains(script, "\"${missing_args[@]}\"") {
		t.Fatalf("prep script does not pass pacman -T output to pacman -S:\n%s", script)
	}
}

func TestDependencyPrepScriptUsesOnlyPacmanMissingRelations(t *testing.T) {
	plan, _ := dependencyPlanFixture()
	script, err := dependencyPrepScript([]string{"opr-lib=1.2-1", "tree"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	missingLog := runDependencyPrepWithFakePacman(t, script, "missing")
	if len(missingLog) != 2 || !strings.Contains(missingLog[0], "-T") || !strings.Contains(missingLog[1], "-S") {
		t.Fatalf("unexpected pacman calls: %v", missingLog)
	}
	if strings.Contains(missingLog[1], plan.Packages[0].Name) || !strings.Contains(missingLog[1], "tree") {
		t.Fatalf("pacman -S received hosted or missing relation set: %v", missingLog[1])
	}
	errorLog := runDependencyPrepWithFakePacman(t, script, "error")
	if len(errorLog) != 1 || !strings.Contains(errorLog[0], "-T") {
		t.Fatalf("pacman -S ran after non-missing pacman -T error: %v", errorLog)
	}
}

func runDependencyPrepWithFakePacman(t *testing.T, script, mode string) []string {
	t.Helper()
	directory := t.TempDir()
	logPath := filepath.Join(directory, "pacman.log")
	program := filepath.Join(directory, "pacman")
	contents := `#!/bin/bash
printf '%s\n' "$*" >> "$PACMAN_LOG"
if [[ "$1" == --config ]]; then shift 2; fi
if [[ "$1" == -T ]]; then
  if [[ "$PACMAN_MODE" == missing ]]; then printf 'tree\n'; exit 127; fi
  printf 'pacman internal failure\n' >&2
  exit 2
fi
if [[ "$1" == -S ]]; then exit 0; fi
exit 0
`
	if err := os.WriteFile(program, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "cp"), []byte(`#!/bin/bash
if [[ "$1" == /etc/pacman.conf ]]; then printf '[options]\n' > "$2"; else exec /bin/cp "$@"; fi
`), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PACMAN_LOG", logPath)
	t.Setenv("PACMAN_MODE", mode)
	t.Setenv("PATH", directory+":"+os.Getenv("PATH"))
	command := exec.Command("bash", "-ceu", script)
	if output, err := command.CombinedOutput(); mode == "missing" && err != nil {
		t.Fatalf("missing dependency prep failed: %v\n%s", err, output)
	} else if mode == "error" && err == nil {
		t.Fatal("non-missing pacman error unexpectedly succeeded")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

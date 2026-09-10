package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func shellWord(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func (recipe *materializedRecipe) buildMounts(workdir, output string, env map[string]string) ([]mount, error) {
	mounts := []mount{{Source: workdir, Target: "/opr/work", ReadOnly: true}, {Source: output, Target: "/opr/output"}}
	for _, name := range []string{"sources", "caches", "keys", "build"} {
		directory := filepath.Join(recipe.Directory, name)
		// Rootful Docker uses the existing numeric fallback build user. Rootless
		// workers retain their own UID through the container's keep-id mapping.
		if os.Getuid() == 0 {
			if err := filepath.WalkDir(directory, func(path string, _ fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				return os.Lchown(path, 65534, 65534)
			}); err != nil {
				return nil, err
			}
		}
		target := "/opr/" + name
		if name == "build" {
			target = "/opr/work/build"
		}
		mounts = append(mounts, mount{Source: directory, Target: target, ReadOnly: name == "keys"})
	}
	for key, value := range map[string]string{
		"SRCDEST": "/opr/sources", "BUILDDIR": "/opr/work/build", "CARCH": recipe.Plan.Architecture,
		"GOMODCACHE": "/opr/caches/go", "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local",
		"CARGO_HOME": "/opr/caches/cargo", "CARGO_NET_OFFLINE": "true", "NPM_CONFIG_CACHE": "/opr/caches/npm", "NPM_CONFIG_OFFLINE": "true",
		"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": "/dev/null",
	} {
		env[key] = value
	}
	settings := [][2]string{{"core.hooksPath", "/dev/null"}, {"core.fsmonitor", "false"}, {"credential.helper", ""},
		{"protocol.allow", "never"}, {"protocol.file.allow", "always"}, {"submodule.recurse", "false"}, {"safe.bareRepository", "all"}}
	env["GIT_CONFIG_COUNT"] = fmt.Sprint(len(settings))
	for i, setting := range settings {
		env[fmt.Sprintf("GIT_CONFIG_KEY_%d", i)] = setting[0]
		env[fmt.Sprintf("GIT_CONFIG_VALUE_%d", i)] = setting[1]
	}
	return mounts, nil
}

func (recipe *materializedRecipe) verificationScript() (string, error) {
	var script strings.Builder
	script.WriteString(`export HOME="$TMPDIR/home" GNUPGHOME="$TMPDIR/gnupg"
mkdir -m 700 "$HOME" "$GNUPGHOME"
printf 'no-auto-key-retrieve\nauto-key-locate clear\n' > "$GNUPGHOME/gpg.conf"
	printf '\nBUILDDIR=/opr/work/build\nPKGDEST=/opr/output\nSRCDEST=/opr/sources\nSRCPKGDEST=/opr/output\nLOGDEST=/opr/output\n' >> "$MAKEPKG_CONF"
`)
	for _, key := range recipe.Bundle.Keys {
		path := shellWord("/opr/keys/" + key.Fingerprint)
		script.WriteString("gpg --batch --no-options --with-colons --import-options show-only --dry-run --import " + path + " > \"$TMPDIR/key-info\"\n")
		script.WriteString("test \"$(awk -F: '$1==\"pub\" { n++ } END { print n+0 }' \"$TMPDIR/key-info\")\" = 1 || { echo 'Source key must contain exactly one public key' >&2; exit 1; }\n")
		script.WriteString("! grep -Eq '^(sec|ssb):' \"$TMPDIR/key-info\" || { echo 'Secret source keys are forbidden' >&2; exit 1; }\n")
		script.WriteString("test \"$(awk -F: '$1==\"fpr\" { print $10; exit }' \"$TMPDIR/key-info\")\" = " + shellWord(key.Fingerprint) + " || { echo 'Source key fingerprint differs from retained manifest' >&2; exit 1; }\n")
		script.WriteString("gpg --batch --import " + path + "\n")
	}
	for _, source := range recipe.Plan.Sources {
		if source.Kind != "git" {
			continue
		}
		ref, err := sourceGitRef(source)
		if err != nil {
			return "", err
		}
		commit := ""
		for _, entry := range recipe.Bundle.Sources {
			if entry.Name == source.Name {
				commit = entry.Commit
			}
		}
		if !sourceCommit.MatchString(commit) {
			return "", fmt.Errorf("missing retained Git commit for %s", source.Name)
		}
		git := "git --git-dir=" + shellWord("/opr/sources/"+source.Name)
		if source.Ref.Kind == "tag" || source.Ref.Kind == "branch" {
			script.WriteString("git check-ref-format " + shellWord(ref) + "\n")
		}
		script.WriteString("test \"$(" + git + " rev-parse --is-bare-repository)\" = true\n")
		script.WriteString("test \"$(" + git + " rev-parse --verify --end-of-options " + shellWord(ref+"^{commit}") + ")\" = " + shellWord(commit) + " || { echo 'Retained Git source commit differs from source plan' >&2; exit 1; }\n")
		script.WriteString(git + " fsck --full --no-reflogs\n")
	}
	// The original PKGBUILD runs only in this network-disabled, unprivileged
	// container. Its metadata must still equal the signed native inspection.
	script.WriteString("(ulimit -f 2048; makepkg --config \"$MAKEPKG_CONF\" --printsrcinfo > \"$TMPDIR/srcinfo\")\n")
	inspectionSHA := recipe.Plan.Inspection.SrcinfoSHA256
	if recipe.Inputs.Inspection != nil && recipe.Inputs.Inspection.SrcinfoSHA256 != "" {
		inspectionSHA = recipe.Inputs.Inspection.SrcinfoSHA256
		if architectureSHA := recipe.Inputs.Inspection.Architectures[recipe.Plan.Architecture]; architectureSHA != "" {
			inspectionSHA = architectureSHA
		}
	}
	script.WriteString("printf '%s  %s\\n' " + shellWord(inspectionSHA) + " \"$TMPDIR/srcinfo\" | sha256sum -c -\n")
	return script.String(), nil
}

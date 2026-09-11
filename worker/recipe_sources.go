package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxRecipeSourceObject int64 = 32 << 30
const maxRecipeSourceEntries = 200000

type preservedBuildInputs struct {
	Capture      inputObject  `json:"capture"`
	SourceBundle inputObject  `json:"sourceBundle"`
	Recipe       *inputObject `json:"recipe,omitempty"`
	Inspection   *struct {
		SrcinfoSHA256 string            `json:"srcinfoSha256"`
		Architectures map[string]string `json:"architectures,omitempty"`
	} `json:"inspection,omitempty"`
}
type plannedRecipeSource struct {
	Kind      string            `json:"kind"`
	Source    string            `json:"source"`
	Name      string            `json:"name"`
	Checksums map[string]string `json:"checksums"`
	Path      string            `json:"path,omitempty"`
	URL       string            `json:"url,omitempty"`
	Ref       *struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	} `json:"ref,omitempty"`
	Signed *bool `json:"signed,omitempty"`
}
type recipeSourcePlan struct {
	SchemaVersion int         `json:"schemaVersion"`
	Kind          string      `json:"kind"`
	Capture       inputObject `json:"capture"`
	Inspection    struct {
		JobID         string `json:"jobId"`
		Attempt       int64  `json:"attempt"`
		ReportSHA256  string `json:"reportSha256"`
		SrcinfoSHA256 string `json:"srcinfoSha256"`
	} `json:"inspection"`
	Pkgbase      string                `json:"pkgbase"`
	Version      string                `json:"version"`
	Architecture string                `json:"architecture"`
	Sources      []plannedRecipeSource `json:"sources"`
	ValidPGPKeys []string              `json:"validpgpkeys"`
}
type retainedRecipeSource struct {
	Kind          string      `json:"kind"`
	Name          string      `json:"name"`
	Object        inputObject `json:"object"`
	Redirects     []string    `json:"redirects,omitempty"`
	Commit        string      `json:"commit,omitempty"`
	Entries       *int        `json:"entries,omitempty"`
	ExpandedBytes *int64      `json:"expandedBytes,omitempty"`
}
type recipeSourceBundle struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Kind          string                 `json:"kind"`
	Plan          inputObject            `json:"plan"`
	Sources       []retainedRecipeSource `json:"sources"`
	Caches        []struct {
		Kind          string      `json:"kind"`
		Object        inputObject `json:"object"`
		Entries       int         `json:"entries"`
		ExpandedBytes int64       `json:"expandedBytes"`
	} `json:"caches"`
	Keys []struct {
		Fingerprint string      `json:"fingerprint"`
		Object      inputObject `json:"object"`
	} `json:"keys"`
}
type materializedRecipe struct {
	Directory string
	Inputs    preservedBuildInputs
	Plan      recipeSourcePlan
	Bundle    recipeSourceBundle
}

var sourceFingerprint = regexp.MustCompile(`^(?:[A-F0-9]{40}|[A-F0-9]{64})$`)
var sourceCommit = regexp.MustCompile(`^[a-f0-9]{40}$`)

func safeSourceArchivePath(value string) bool {
	if value == "" || len(value) > 512 || !utf8.ValidString(value) || strings.Contains(value, "\\") {
		return false
	}
	for _, char := range value {
		if char < 32 || char == 127 {
			return false
		}
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func safeSourceName(value string) bool {
	return safeRecipePath(value, false) && len(value) <= 255 && !strings.Contains(value, "/") && !strings.HasPrefix(value, "-")
}

// Retained archives are plain tar. No links become traversable until every entry
// has passed path, type, duplicate and exact expansion-budget checks.
func extractRecipeSource(ctx context.Context, path, destination string, entries int, expanded int64) error {
	if entries < 0 || entries > maxRecipeSourceEntries || expanded < 0 || expanded > maxRecipeSourceObject {
		return errors.New("source archive exceeds its expansion budget")
	}
	if err := os.Mkdir(destination, 0o755); err != nil {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := tar.NewReader(contextReader{ctx, file})
	seen, links := map[string]byte{}, map[string]string{}
	var total int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimSuffix(header.Name, "/")
		_, duplicate := seen[name]
		if !safeSourceArchivePath(name) || duplicate || len(seen) >= entries || header.Size < 0 || header.Size > expanded-total ||
			(header.Mode != 0o644 && header.Mode != 0o755) || (header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeDir && header.Typeflag != tar.TypeSymlink) ||
			(header.Typeflag != tar.TypeReg && header.Size != 0) {
			return errors.New("unsafe source archive entry, mode or size")
		}
		for parent := filepath.Dir(name); parent != "."; parent = filepath.Dir(parent) {
			if kind, exists := seen[parent]; exists && kind != tar.TypeDir {
				return errors.New("source archive entry has a non-directory parent")
			}
		}
		seen[name] = header.Typeflag
		total += header.Size
		path := filepath.Join(destination, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeSymlink:
			links[name] = header.Linkname
		case tar.TypeReg:
			output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(output, reader)
			closeErr := output.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	if len(seen) != entries || total != expanded {
		return errors.New("source archive differs from retained expansion inventory")
	}
	if err := validateContainedLinks(links, safeSourceArchivePath); err != nil {
		return err
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(destination, name)); err != nil {
			return err
		}
	}
	return nil
}

func materializePreservedRecipe(ctx context.Context, job Job, directory, workdir string, get inputObjectGetter) (*materializedRecipe, error) {
	if job.PreservedRecipe == nil || job.OutputContract == nil || job.InputLock == nil || get == nil {
		return nil, errors.New("preserved recipe requires native inputs and authenticated object access")
	}
	if err := os.Mkdir(directory, 0o755); err != nil {
		return nil, err
	}
	capture, err := materializeRecipeCapture(ctx, job.PreservedRecipe.Capture, job.PackageName, filepath.Join(directory, "capture-objects"), workdir, get)
	if err != nil {
		return nil, err
	}
	if job.PreservedRecipe.Recipe != nil {
		if !validInputObject(*job.PreservedRecipe.Recipe, maxRecipeBytes) {
			return nil, errors.New("recipe override exceeds its size budget")
		}
		override := filepath.Join(directory, "recipe-override")
		if err := get(ctx, *job.PreservedRecipe.Recipe, override); err != nil {
			return nil, err
		}
		if err := os.Remove(filepath.Join(workdir, "PKGBUILD")); err != nil {
			return nil, err
		}
		if err := os.Rename(override, filepath.Join(workdir, "PKGBUILD")); err != nil {
			return nil, err
		}
		if err := os.Chmod(filepath.Join(workdir, "PKGBUILD"), 0o644); err != nil {
			return nil, err
		}
	}
	recipe, err := os.ReadFile(filepath.Join(workdir, "PKGBUILD"))
	if err != nil || hashBytes(recipe) != job.RecipeSHA256 {
		return nil, errors.New("captured PKGBUILD differs from reviewed recipe")
	}
	for _, name := range []string{"objects", "sources", "caches", "keys", "build"} {
		if err := os.Mkdir(filepath.Join(directory, name), 0o755); err != nil {
			return nil, err
		}
	}
	seen := map[string]int64{}
	var transferred int64
	load := func(ref inputObject, max int64) (string, error) {
		if !sha256Pattern.MatchString(ref.SHA256) || ref.Size < 0 || ref.Size > max || (ref.Size == 0) != (ref.SHA256 == emptyRecipeSHA) {
			return "", errors.New("source object exceeds its size budget")
		}
		path := filepath.Join(directory, "objects", ref.SHA256)
		if size, exists := seen[ref.SHA256]; exists {
			if size != ref.Size {
				return "", errors.New("source object has inconsistent size")
			}
			return path, nil
		}
		transferred += ref.Size
		if transferred > maxFrozenTransferBytes {
			return "", errors.New("recipe source transfer exceeds budget")
		}
		if ref.Size == 0 {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				return "", err
			}
		} else if err := get(ctx, ref, path); err != nil {
			return "", err
		}
		stat, err := os.Lstat(path)
		if err != nil || !stat.Mode().IsRegular() || stat.Size() != ref.Size {
			return "", errors.New("retained source is not an exact-size regular file")
		}
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		hash := sha256.New()
		_, err = io.Copy(hash, contextReader{ctx, file})
		file.Close()
		if err != nil || hex.EncodeToString(hash.Sum(nil)) != ref.SHA256 {
			return "", errors.New("retained source checksum differs")
		}
		seen[ref.SHA256] = ref.Size
		return path, nil
	}
	readJSON := func(ref inputObject, target any) error {
		path, err := load(ref, 2<<20)
		if err != nil {
			return err
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return decodeCanonicalDocument(bytes, target)
	}
	result := &materializedRecipe{Directory: directory, Inputs: *job.PreservedRecipe}
	if err := readJSON(job.PreservedRecipe.SourceBundle, &result.Bundle); err != nil {
		return nil, err
	}
	bundle := &result.Bundle
	if bundle.SchemaVersion != 1 || bundle.Kind != "recipe-source-bundle" || bundle.Sources == nil || bundle.Caches == nil || bundle.Keys == nil || len(bundle.Sources) > 2048 || len(bundle.Caches) > 3 || len(bundle.Keys) > 256 {
		return nil, errors.New("invalid retained source bundle")
	}
	// Count repeated references too: separate source/cache paths consume disk
	// even when their downloaded object bytes can be shared.
	refs := []inputObject{job.PreservedRecipe.SourceBundle, bundle.Plan}
	for _, source := range bundle.Sources {
		refs = append(refs, source.Object)
	}
	for _, cache := range bundle.Caches {
		refs = append(refs, cache.Object)
	}
	for _, key := range bundle.Keys {
		refs = append(refs, key.Object)
	}
	var referenced int64
	for _, ref := range refs {
		if ref.Size < 0 || ref.Size > maxRecipeSourceObject || referenced > maxFrozenTransferBytes-ref.Size {
			return nil, errors.New("recipe source inventory exceeds total byte budget")
		}
		referenced += ref.Size
	}
	if err := readJSON(bundle.Plan, &result.Plan); err != nil {
		return nil, err
	}
	plan := &result.Plan
	if plan.SchemaVersion != 1 || plan.Kind != "recipe-source-plan" || plan.Pkgbase != job.PackageName || plan.Architecture != job.Architecture ||
		plan.Capture != job.PreservedRecipe.Capture || plan.Sources == nil || plan.ValidPGPKeys == nil || len(plan.Sources) > 2048 || len(plan.ValidPGPKeys) > 256 || !idPattern.MatchString(plan.Inspection.JobID) ||
		plan.Inspection.Attempt < 1 || !sha256Pattern.MatchString(plan.Inspection.ReportSHA256) || !sha256Pattern.MatchString(plan.Inspection.SrcinfoSHA256) {
		return nil, errors.New("source plan differs from reviewed native scope")
	}
	repairVersion := ""
	if job.PreservedRecipe.Recipe != nil && job.PreservedRecipe.Inspection != nil {
		parts := regexp.MustCompile(`^(.+)-([1-9][0-9]{0,3})(?:\.[1-9][0-9]{0,3})?$`).FindStringSubmatch(plan.Version)
		if len(parts) == 3 {
			previousRelease, _ := strconv.ParseInt(parts[2], 10, 64)
			if job.Pkgrel > previousRelease {
				repairVersion = fmt.Sprintf("%s-%d", parts[1], job.Pkgrel)
			}
		}
	}
	for _, output := range job.OutputContract.Outputs {
		if output.FullVersion != plan.Version && (repairVersion == "" || output.FullVersion != repairVersion) {
			return nil, errors.New("source plan version differs from reviewed outputs")
		}
	}
	names, remote := map[string]bool{}, 0
	for _, source := range plan.Sources {
		if !safeSourceName(source.Name) || names[source.Name] || source.Source == "" || len(source.Source) > 4096 || source.Checksums == nil {
			return nil, errors.New("invalid or duplicate planned source name")
		}
		names[source.Name] = true
		if source.Kind == "local" {
			found := false
			for _, file := range capture.Files {
				found = found || file.Path == source.Name
			}
			if source.Path != source.Name || !found || source.URL != "" || source.Ref != nil || source.Signed != nil {
				return nil, errors.New("local source is absent from captured recipe")
			}
			continue
		}
		if source.Path != "" || validateSourceURL(source.URL) != nil || remote >= len(bundle.Sources) {
			return nil, errors.New("source bundle omits a planned remote source")
		}
		entry := bundle.Sources[remote]
		remote++
		if entry.Name != source.Name || entry.Kind != source.Kind {
			return nil, errors.New("source bundle differs from inspected inventory")
		}
		path, err := load(entry.Object, maxRecipeSourceObject)
		if err != nil {
			return nil, err
		}
		destination := filepath.Join(directory, "sources", entry.Name)
		switch source.Kind {
		case "file":
			if len(entry.Redirects) < 1 || len(entry.Redirects) > 9 || entry.Redirects[0] != source.URL || entry.Commit != "" || entry.Entries != nil || entry.ExpandedBytes != nil || source.Ref != nil || source.Signed != nil {
				return nil, errors.New("invalid retained file source")
			}
			for _, redirect := range entry.Redirects {
				if validateSourceURL(redirect) != nil {
					return nil, errors.New("invalid source redirect evidence")
				}
			}
			if err := copyFile(ctx, path, destination); err != nil {
				return nil, err
			}
		case "git":
			if source.Ref == nil || source.Signed == nil || !sourceCommit.MatchString(entry.Commit) || entry.Entries == nil || entry.ExpandedBytes == nil || len(entry.Redirects) != 0 || entry.Object.Size == 0 || *entry.ExpandedBytes > entry.Object.Size {
				return nil, errors.New("invalid retained Git source")
			}
			if _, err := sourceGitRef(source); err != nil {
				return nil, err
			}
			if source.Ref.Kind == "commit" && !strings.EqualFold(source.Ref.Value, entry.Commit) {
				return nil, errors.New("Git source commit differs from inspected pin")
			}
			if err := extractRecipeSource(ctx, path, destination, *entry.Entries, *entry.ExpandedBytes); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("unsupported preserved source kind")
		}
	}
	if remote != len(bundle.Sources) {
		return nil, errors.New("source bundle has extra remote sources")
	}
	kinds := map[string]bool{}
	for _, cache := range bundle.Caches {
		if (cache.Kind != "go" && cache.Kind != "cargo" && cache.Kind != "npm") || kinds[cache.Kind] || cache.Object.Size == 0 || cache.ExpandedBytes > cache.Object.Size {
			return nil, errors.New("invalid or duplicate source cache")
		}
		kinds[cache.Kind] = true
		path, err := load(cache.Object, maxRecipeSourceObject)
		if err != nil {
			return nil, err
		}
		if err := extractRecipeSource(ctx, path, filepath.Join(directory, "caches", cache.Kind), cache.Entries, cache.ExpandedBytes); err != nil {
			return nil, err
		}
	}
	for _, kind := range []string{"go", "cargo", "npm"} {
		if !kinds[kind] {
			if err := os.Mkdir(filepath.Join(directory, "caches", kind), 0o755); err != nil {
				return nil, err
			}
		}
	}
	fingerprints := map[string]bool{}
	for _, key := range bundle.Keys {
		if !sourceFingerprint.MatchString(key.Fingerprint) || fingerprints[key.Fingerprint] || key.Object.Size == 0 {
			return nil, errors.New("invalid or duplicate source signing key")
		}
		fingerprints[key.Fingerprint] = true
		path, err := load(key.Object, 1<<20)
		if err != nil {
			return nil, err
		}
		if err := copyFile(ctx, path, filepath.Join(directory, "keys", key.Fingerprint)); err != nil {
			return nil, err
		}
	}
	for _, fingerprint := range plan.ValidPGPKeys {
		if !sourceFingerprint.MatchString(fingerprint) || !fingerprints[fingerprint] {
			return nil, errors.New("source signing keys are incomplete")
		}
	}
	return result, nil
}

func sourceGitRef(source plannedRecipeSource) (string, error) {
	if source.Ref == nil || source.Ref.Value == "" || strings.HasPrefix(source.Ref.Value, "-") || strings.ContainsAny(source.Ref.Value, "\x00\r\n") {
		return "", errors.New("invalid Git source reference")
	}
	switch source.Ref.Kind {
	case "head":
		if source.Ref.Value == "HEAD" {
			return "HEAD", nil
		}
	case "commit":
		if sourceCommit.MatchString(strings.ToLower(source.Ref.Value)) {
			return source.Ref.Value, nil
		}
	case "tag", "branch":
		prefix := "refs/tags/"
		if source.Ref.Kind == "branch" {
			prefix = "refs/heads/"
		}
		return prefix + source.Ref.Value, nil // git check-ref-format runs in the offline container.
	}
	return "", fmt.Errorf("unsupported Git source reference kind %q", source.Ref.Kind)
}

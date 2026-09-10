package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const maxRecipeTreeBytes int64 = 32 << 20
const emptyRecipeSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type recipeCaptureFile struct {
	Path   string      `json:"path"`
	Mode   string      `json:"mode"`
	Object inputObject `json:"object"`
}
type recipeCaptureManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Kind          string `json:"kind"`
	Pkgbase       string `json:"pkgbase"`
	Origin        string `json:"origin"`
	Repository    string `json:"repository"`
	Commit        string `json:"commit"`
	Directory     string `json:"directory"`
	Git           struct {
		Commit inputObject   `json:"commit"`
		Trees  []inputObject `json:"trees"`
	} `json:"git"`
	Files []recipeCaptureFile `json:"files"`
}
type recipeGitEntry struct{ mode, name, sha string }

func safeRecipePath(value string, empty bool) bool {
	if value == "" && empty {
		return true
	}
	if len(value) > 512 || !utf8.ValidString(value) || strings.Contains(value, "\\") {
		return false
	}
	for _, char := range value {
		if char < 32 || char == 127 {
			return false
		}
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.EqualFold(part, ".git") {
			return false
		}
	}
	return true
}

func recipeGitHash(kind string, bytes []byte) string {
	hash := sha1.New()
	fmt.Fprintf(hash, "%s %d\x00", kind, len(bytes))
	hash.Write(bytes)
	return hex.EncodeToString(hash.Sum(nil))
}

func parseRecipeGitTree(raw []byte) ([]recipeGitEntry, error) {
	var result []recipeGitEntry
	seen := map[string]bool{}
	for len(raw) > 0 {
		space := bytes.IndexByte(raw, ' ')
		end := bytes.IndexByte(raw, 0)
		if space < 0 || end <= space || end+21 > len(raw) {
			return nil, errors.New("truncated recipe Git tree")
		}
		entry := recipeGitEntry{string(raw[:space]), string(raw[space+1 : end]), hex.EncodeToString(raw[end+1 : end+21])}
		if !utf8.ValidString(entry.name) || entry.name == "" || strings.Contains(entry.name, "/") || seen[entry.name] {
			return nil, errors.New("invalid recipe Git tree name")
		}
		seen[entry.name] = true
		result = append(result, entry)
		raw = raw[end+21:]
	}
	return result, nil
}

func validateRecipeLinks(links map[string]string) error {
	return validateContainedLinks(links, func(path string) bool { return safeRecipePath(path, false) })
}

func validateContainedLinks(links map[string]string, validPath func(string) bool) error {
	for path, target := range links {
		if target == "" || len(target) > 512 || strings.HasPrefix(target, "/") {
			return errors.New("unsafe recipe symlink")
		}
		parts := strings.Split(path, "/")
		parts = parts[:len(parts)-1]
		remaining := strings.Split(target, "/")
		seen := map[string]bool{path: true}
		for len(remaining) > 0 {
			part := remaining[0]
			remaining = remaining[1:]
			if part == ".." {
				if len(parts) == 0 {
					return errors.New("recipe symlink escapes directory")
				}
				parts = parts[:len(parts)-1]
			} else if part != "." {
				if !validPath(part) {
					return errors.New("unsafe recipe symlink target")
				}
				parts = append(parts, part)
				resolved := strings.Join(parts, "/")
				if link, exists := links[resolved]; exists {
					if seen[resolved] || len(seen) > 32 || strings.HasPrefix(link, "/") {
						return errors.New("cyclic or unsafe recipe symlink")
					}
					seen[resolved] = true
					parts = parts[:len(parts)-1]
					remaining = append(strings.Split(link, "/"), remaining...)
				}
			}
		}
	}
	return nil
}

// Validate the whole proof before materializing any executable recipe path.
func materializeRecipeCapture(ctx context.Context, ref inputObject, pkgbase, objectDir, workdir string, get inputObjectGetter) (*recipeCaptureManifest, error) {
	if !validInputObject(ref, 512<<10) || get == nil {
		return nil, errors.New("invalid recipe capture reference")
	}
	if err := os.Mkdir(objectDir, 0o700); err != nil {
		return nil, err
	}
	seen := map[string]int64{}
	var transferred int64
	load := func(ref inputObject, max int64) ([]byte, error) {
		if !sha256Pattern.MatchString(ref.SHA256) || ref.Size < 0 || ref.Size > max || (ref.Size == 0) != (ref.SHA256 == emptyRecipeSHA) {
			return nil, errors.New("recipe object exceeds its size budget")
		}
		if ref.Size == 0 {
			return []byte{}, nil
		}
		path := filepath.Join(objectDir, ref.SHA256)
		if size, exists := seen[ref.SHA256]; exists {
			if size != ref.Size {
				return nil, errors.New("recipe object has inconsistent size")
			}
		} else {
			transferred += ref.Size
			if transferred > maxRecipeTreeBytes+(4<<20)+(512<<10) {
				return nil, errors.New("recipe capture transfer exceeds budget")
			}
			if err := get(ctx, ref, path); err != nil {
				return nil, err
			}
			seen[ref.SHA256] = ref.Size
		}
		stat, err := os.Lstat(path)
		if err != nil || !stat.Mode().IsRegular() || stat.Size() != ref.Size {
			return nil, errors.New("recipe object is not a regular exact-size file")
		}
		data, err := os.ReadFile(path)
		if err != nil || hashBytes(data) != ref.SHA256 {
			return nil, errors.New("recipe object checksum changed")
		}
		return data, nil
	}
	root, err := load(ref, 512<<10)
	if err != nil {
		return nil, err
	}
	var manifest recipeCaptureManifest
	if err := decodeCanonicalDocument(root, &manifest); err != nil {
		return nil, err
	}
	if manifest.SchemaVersion != 1 || manifest.Kind != "recipe-capture" || manifest.Pkgbase != pkgbase || !depNamePattern.MatchString(pkgbase) ||
		!safeRecipePath(manifest.Directory, true) || len(manifest.Files) == 0 || len(manifest.Files) > 2048 || len(manifest.Git.Trees) == 0 || len(manifest.Git.Trees) > 512 ||
		len(manifest.Commit) != 40 || validateSourceURL(manifest.Repository) != nil {
		return nil, errors.New("invalid recipe capture identity or inventory")
	}
	files := map[string]recipeCaptureFile{}
	var size int64
	for _, file := range manifest.Files {
		_, duplicate := files[file.Path]
		if !safeRecipePath(file.Path, false) || duplicate || file.Object.Size < 0 || file.Object.Size > maxRecipeTreeBytes ||
			(file.Mode != "100644" && file.Mode != "100755" && file.Mode != "120000") || (file.Mode == "120000" && file.Object.Size > 512) {
			return nil, errors.New("invalid recipe capture file or mode")
		}
		size += file.Object.Size
		if size > maxRecipeTreeBytes {
			return nil, errors.New("recipe directory exceeds byte budget")
		}
		files[file.Path] = file
		if (file.Path == ".SRCINFO" && (file.Mode == "120000" || file.Object.Size > 1<<20)) ||
			(file.Path == ".omarchy/package.json" && (file.Mode == "120000" || file.Object.Size > 64<<10)) {
			return nil, errors.New("recipe metadata exceeds inspection budget")
		}
	}
	for path := range files {
		for parent := filepath.Dir(path); parent != "."; parent = filepath.Dir(parent) {
			if _, exists := files[parent]; exists {
				return nil, errors.New("recipe file has a non-directory parent")
			}
		}
	}
	recipe, exists := files["PKGBUILD"]
	if !exists || recipe.Mode == "120000" || recipe.Object.Size == 0 || recipe.Object.Size > maxRecipeBytes {
		return nil, errors.New("recipe capture has no bounded regular PKGBUILD")
	}
	commit, err := load(manifest.Git.Commit, 128<<10)
	if err != nil {
		return nil, err
	}
	line, _, _ := strings.Cut(string(commit), "\n")
	if recipeGitHash("commit", commit) != manifest.Commit || !strings.HasPrefix(line, "tree ") || len(line) != 45 {
		return nil, errors.New("recipe Git commit proof differs")
	}
	trees := map[string][]recipeGitEntry{}
	proofSize := manifest.Git.Commit.Size
	for _, ref := range manifest.Git.Trees {
		proofSize += ref.Size
		if proofSize > 4<<20 {
			return nil, errors.New("recipe Git proof exceeds budget")
		}
		data, err := load(ref, 1<<20)
		if err != nil {
			return nil, err
		}
		sha := recipeGitHash("tree", data)
		if _, duplicate := trees[sha]; duplicate {
			return nil, errors.New("duplicate recipe Git tree proof")
		}
		entries, err := parseRecipeGitTree(data)
		if err != nil {
			return nil, err
		}
		trees[sha] = entries
	}
	used := map[string]bool{}
	tree := func(sha string) ([]recipeGitEntry, error) {
		entries, exists := trees[sha]
		if !exists {
			return nil, errors.New("recipe Git tree proof is incomplete")
		}
		used[sha] = true
		return entries, nil
	}
	treeSHA := line[5:]
	if manifest.Directory != "" {
		for _, part := range strings.Split(manifest.Directory, "/") {
			entries, err := tree(treeSHA)
			if err != nil {
				return nil, err
			}
			treeSHA = ""
			for _, entry := range entries {
				if entry.name == part && entry.mode == "40000" {
					treeSHA = entry.sha
				}
			}
			if treeSHA == "" {
				return nil, errors.New("recipe directory is absent from Git commit")
			}
		}
	}
	expected := map[string]recipeGitEntry{}
	directories := 0
	var walk func(string, string) error
	walk = func(sha, prefix string) error {
		directories++
		if directories > 2048 || strings.Count(prefix, "/") > 32 {
			return errors.New("recipe Git tree is too large or deep")
		}
		entries, err := tree(sha)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			path := prefix + entry.name
			if !safeRecipePath(path, false) {
				return errors.New("unsafe recipe Git path")
			}
			if entry.mode == "40000" {
				if err := walk(entry.sha, path+"/"); err != nil {
					return err
				}
			} else {
				if len(expected) >= 2048 {
					return errors.New("recipe Git tree has too many files")
				}
				expected[path] = entry
			}
		}
		return nil
	}
	if err := walk(treeSHA, ""); err != nil {
		return nil, err
	}
	if len(used) != len(trees) || len(expected) != len(files) {
		return nil, errors.New("recipe directory inventory is incomplete or has extra files")
	}
	links := map[string]string{}
	for _, file := range manifest.Files {
		bytes, err := load(file.Object, maxRecipeTreeBytes)
		if err != nil {
			return nil, err
		}
		entry, exists := expected[file.Path]
		if !exists || file.Mode != entry.mode || entry.sha != recipeGitHash("blob", bytes) {
			return nil, errors.New("recipe file differs from original Git blob")
		}
		if file.Mode == "120000" {
			links[file.Path] = string(bytes)
		}
	}
	if err := validateRecipeLinks(links); err != nil {
		return nil, err
	}
	if err := os.Chmod(workdir, 0o755); err != nil {
		return nil, err
	}
	for _, file := range manifest.Files {
		path := filepath.Join(workdir, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		for parent := filepath.Dir(path); parent != workdir; parent = filepath.Dir(parent) {
			if err := os.Chmod(parent, 0o755); err != nil {
				return nil, err
			}
		}
		if file.Mode == "120000" {
			continue
		}
		bytes, err := load(file.Object, maxRecipeTreeBytes)
		if err != nil {
			return nil, err
		}
		mode := os.FileMode(0o644)
		if file.Mode == "100755" {
			mode = 0o755
		}
		if err := os.WriteFile(path, bytes, mode); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, mode); err != nil {
			return nil, err
		}
	}
	for path, target := range links {
		if err := os.Symlink(target, filepath.Join(workdir, path)); err != nil {
			return nil, err
		}
	}
	return &manifest, nil
}

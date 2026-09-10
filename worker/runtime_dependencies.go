package main

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type installedPackage struct {
	name, version     string
	depends, provides []string
}
type runtimePackages struct {
	packages    map[string]*installedPackage
	providers   map[string][]*installedPackage
	owners      map[string][]string
	comparisons map[string]int
}

func readPacmanFields(filename string, limit int64) (map[string][]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return scanPacmanFields(file, limit)
}

func scanPacmanFields(source io.Reader, limit int64) (map[string][]string, error) {
	reader := bufio.NewScanner(io.LimitReader(source, limit+1))
	reader.Buffer(make([]byte, 4096), 64*1024)
	fields := map[string][]string{}
	section, size := "", int64(0)
	for reader.Scan() {
		line := reader.Text()
		size += int64(len(line)) + 1
		if size > limit || !analysisText(strings.ReplaceAll(line, "\t", ""), 64*1024) {
			return nil, errors.New("installed package metadata exceeds limit")
		}
		if section == "" && strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") {
			section = line[1 : len(line)-1]
			if section == "" || !pacmanFieldPattern.MatchString(section) {
				return nil, errors.New("invalid installed package metadata field")
			}
			if fields[section] != nil {
				return nil, errors.New("duplicate installed package field")
			}
			fields[section] = []string{}
			continue
		}
		if line == "" {
			section = ""
			continue
		}
		if section == "" {
			return nil, errors.New("invalid installed package metadata")
		}
		fields[section] = append(fields[section], line)
	}
	return fields, reader.Err()
}

var pacmanFieldPattern = regexp.MustCompile(`^[A-Z0-9_]+$`)

func installedRuntimePackages(root string) (*runtimePackages, error) {
	directory := filepath.Join(root, "var/lib/pacman/local")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := &runtimePackages{packages: map[string]*installedPackage{}, providers: map[string][]*installedPackage{}, owners: map[string][]string{}, comparisons: map[string]int{}}
	paths := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if len(result.packages) >= 4096 {
			return nil, errors.New("installed package inventory exceeds 4096 packages")
		}
		fields, err := readPacmanFields(filepath.Join(directory, entry.Name(), "desc"), 1<<20)
		if err != nil {
			return nil, err
		}
		if len(fields["NAME"]) != 1 || len(fields["VERSION"]) != 1 || !depNamePattern.MatchString(fields["NAME"][0]) || !validArchVersion(fields["VERSION"][0]) {
			return nil, errors.New("invalid installed package identity")
		}
		pkg := &installedPackage{name: fields["NAME"][0], version: fields["VERSION"][0], depends: fields["DEPENDS"], provides: fields["PROVIDES"]}
		if result.packages[pkg.name] != nil {
			return nil, errors.New("duplicate installed package identity")
		}
		result.packages[pkg.name] = pkg
		result.providers[pkg.name] = append(result.providers[pkg.name], pkg)
		for _, relation := range append(append([]string{}, pkg.depends...), pkg.provides...) {
			if _, err := parsePackageRelation(relation, false, true); err != nil {
				return nil, err
			}
		}
		for _, relation := range pkg.provides {
			name, _, _ := dependencyParts(relation)
			if name != pkg.name {
				result.providers[name] = append(result.providers[name], pkg)
			}
		}
		files, err := readPacmanFields(filepath.Join(directory, entry.Name(), "files"), 32<<20)
		if err != nil {
			return nil, err
		}
		for _, name := range files["FILES"] {
			paths++
			if paths > 2_000_000 || !analysisText(name, 4096) || filepath.IsAbs(name) || strings.HasPrefix(filepath.Clean(name), "../") {
				return nil, errors.New("installed file ownership exceeds limit or contains unsafe paths")
			}
			if strings.HasSuffix(name, "/") {
				continue
			}
			result.owners["/"+name] = append(result.owners["/"+name], pkg.name)
		}
	}
	if len(result.packages) == 0 {
		return nil, errors.New("installed runtime package inventory is empty")
	}
	return result, nil
}

func dependencyParts(relation string) (name, operator, version string) {
	index := strings.IndexAny(relation, "<>=")
	if index < 0 {
		return relation, "", ""
	}
	end := index + 1
	if end < len(relation) && relation[end] == '=' {
		end++
	}
	return relation[:index], relation[index:end], relation[end:]
}

func (packages *runtimePackages) satisfies(pkg *installedPackage, relation string) (bool, error) {
	name, operator, wanted := dependencyParts(relation)
	available := []string{}
	if name == pkg.name {
		available = append(available, pkg.version)
	}
	for _, provided := range pkg.provides {
		identity, _, version := dependencyParts(provided)
		if identity == name {
			available = append(available, version)
		}
	}
	for _, version := range available {
		if operator == "" {
			return true, nil
		}
		if version == "" {
			continue
		}
		key := version + "\n" + wanted
		comparison, cached := packages.comparisons[key]
		if !cached && version != wanted {
			output, err := exec.Command("/usr/bin/vercmp", version, wanted).Output()
			if err != nil {
				return false, fmt.Errorf("native version comparison failed: %w", err)
			}
			comparison, err = strconv.Atoi(strings.TrimSpace(string(output)))
			if err != nil || comparison < -1 || comparison > 1 {
				return false, errors.New("invalid native version comparison")
			}
			packages.comparisons[key] = comparison
		}
		if operator == "=" && comparison == 0 || operator == ">" && comparison > 0 || operator == "<" && comparison < 0 ||
			operator == ">=" && comparison >= 0 || operator == "<=" && comparison <= 0 {
			return true, nil
		}
	}
	return false, nil
}

func (packages *runtimePackages) closure(relations []string) (map[string]bool, []string, error) {
	result, seen := map[string]bool{}, map[string]bool{}
	queue, missing := append([]string{}, relations...), []string{}
	for len(queue) > 0 {
		relation := queue[0]
		queue = queue[1:]
		if seen[relation] {
			continue
		}
		seen[relation] = true
		name, _, _ := dependencyParts(relation)
		found := false
		for _, pkg := range packages.providers[name] {
			matches, err := packages.satisfies(pkg, relation)
			if err != nil {
				return nil, nil, err
			}
			if !matches {
				continue
			}
			found = true
			if !result[pkg.name] {
				result[pkg.name] = true
				queue = append(queue, pkg.depends...)
			}
		}
		if !found {
			missing = append(missing, relation)
		}
	}
	return result, missing, nil
}

func libraryCache(root string) (map[string][]string, error) {
	result := map[string][]string{}
	cache := filepath.Join(root, "etc/ld.so.cache")
	if _, err := os.Stat(cache); errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	var output boundedBuffer
	output.limit = 2 << 20
	command := exec.Command("/usr/bin/ldconfig", "-p", "-C", cache)
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil || output.truncated {
		return nil, errors.New("native library cache could not be inspected")
	}
	for _, line := range strings.Split(output.String(), "\n") {
		left, right, ok := strings.Cut(line, " => ")
		if !ok {
			continue
		}
		fields := strings.Fields(left)
		if len(fields) == 0 || !strings.HasPrefix(right, "/") || !analysisText(right, 4096) {
			return nil, errors.New("invalid native library cache entry")
		}
		result[fields[0]] = append(result[fields[0]], right)
	}
	return result, nil
}

func resolveRuntimeFile(root, name string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Join(root, name))
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", errors.New("runtime path escapes inspected root")
	}
	return "/" + relative, nil
}

func (s *packageInspection) checkDependencies(root string, analysis *runtimeAnalysis) error {
	packages, err := installedRuntimePackages(root)
	if err != nil {
		return err
	}
	required, missing, err := packages.closure(s.metadata.Depends)
	if err != nil {
		return err
	}
	optional, _, err := packages.closure(s.optional)
	if err != nil {
		return err
	}
	cache, err := libraryCache(root)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	add := func(code, level, detail, dependency string) error {
		if len(detail) > 4096 {
			return errors.New("runtime finding exceeds limit")
		}
		digest := hashBytes([]byte(level + "\n" + code + "\n" + detail))
		if seen[digest] {
			return nil
		}
		seen[digest] = true
		if len(analysis.Findings) >= 1024 {
			return errors.New("runtime findings exceed 1024 entries")
		}
		var relation *string
		if dependency != "" {
			relation = &dependency
		}
		analysis.Findings = append(analysis.Findings, analysisFinding{Code: code, Level: level, Detail: detail, Dependency: relation, SHA256: digest})
		return nil
	}
	for _, relation := range missing {
		if err := add("dependency-not-satisfied", "error", "dependency-not-satisfied "+relation, relation); err != nil {
			return err
		}
	}
	for _, relation := range s.metadata.Depends {
		name, _, _ := dependencyParts(relation)
		for _, optional := range s.optional {
			other, _, _ := dependencyParts(optional)
			if name == other {
				if err := add("dependency-duplicated-optdepend", "error", "dependency-duplicated-optdepend "+name, name); err != nil {
					return err
				}
			}
		}
	}
	for _, group := range []struct {
		values []string
		code   string
	}{{s.metadata.Depends, "libdepends-without-version"}, {s.metadata.Provides, "libprovides-without-version"}} {
		for _, relation := range group.values {
			if strings.HasSuffix(relation, ".so") {
				if err := add(group.code, "error", group.code+" "+relation, relation); err != nil {
					return err
				}
			}
		}
	}
	checkOwner := func(path, usedBy string) error {
		resolved, err := resolveRuntimeFile(root, path)
		if err != nil {
			return add("runtime-file-missing", "error", "runtime-file-missing "+path+" used by "+usedBy, "")
		}
		info, err := os.Stat(filepath.Join(root, resolved))
		if err != nil || !info.Mode().IsRegular() {
			return add("runtime-file-missing", "error", "runtime-file-missing "+path+" used by "+usedBy, "")
		}
		owners := append(append([]string{}, packages.owners[path]...), packages.owners[resolved]...)
		for _, name := range owners {
			if name == s.metadata.Name || required[name] {
				return nil
			}
		}
		if len(owners) == 0 {
			return add("library-no-package-associated", "warning", "library-no-package-associated "+path+" used by "+usedBy, "")
		}
		sort.Strings(owners)
		for _, name := range owners {
			if optional[name] {
				return add("dependency-detected-but-optional", "warning", "dependency-detected-but-optional "+name+" used by "+usedBy, name)
			}
		}
		return add("dependency-detected-not-included", "error", "dependency-detected-not-included "+owners[0]+" used by "+usedBy, owners[0])
	}
	for _, observation := range s.elfs {
		if observation.Interpreter != "" {
			if err := checkOwner(observation.Interpreter, observation.Path); err != nil {
				return err
			}
		}
		for _, needed := range observation.Needed {
			paths, unknown := librarySearchPaths(observation, needed, cache)
			if unknown {
				if err := add("library-no-package-associated", "warning", "library-no-package-associated: unresolved loader search token for "+observation.Path+" needing "+needed, ""); err != nil {
					return err
				}
			}
			found := ""
			for _, path := range paths {
				resolved, err := resolveRuntimeFile(root, path)
				if err != nil {
					continue
				}
				file, err := elf.Open(filepath.Join(root, resolved))
				if err != nil {
					continue
				}
				matches := file.Machine.String() == observation.Machine && (file.Class == elf.ELFCLASS64) == (observation.Bits == 64)
				file.Close()
				if matches {
					found = path
					break
				}
			}
			if found == "" {
				if err := add("library-not-found", "error", "library-not-found "+needed+" needed by "+observation.Path, ""); err != nil {
					return err
				}
				continue
			}
			if err := checkOwner(found, observation.Path); err != nil {
				return err
			}
		}
	}
	for name, line := range s.shebangs {
		interpreter, err := shebangInterpreter(line)
		if err != nil {
			if err := add("script-interpreter-invalid", "error", "script-interpreter-invalid "+name+": "+err.Error(), ""); err != nil {
				return err
			}
			continue
		}
		if err := checkOwner(interpreter, name); err != nil {
			return err
		}
	}
	sort.Slice(analysis.Findings, func(i, j int) bool { return analysis.Findings[i].SHA256 < analysis.Findings[j].SHA256 })
	return nil
}

func librarySearchPaths(observation elfObservation, needed string, cache map[string][]string) ([]string, bool) {
	if strings.Contains(needed, "/") {
		if filepath.IsAbs(needed) {
			return []string{needed}, false
		}
		return nil, true
	}
	search := observation.Rpath
	if len(observation.Runpath) > 0 {
		search = observation.Runpath
	}
	paths, unknown := []string{}, false
	for _, list := range search {
		for _, path := range strings.Split(list, ":") {
			path = strings.ReplaceAll(strings.ReplaceAll(path, "${ORIGIN}", filepath.Dir("/"+observation.Path)), "$ORIGIN", filepath.Dir("/"+observation.Path))
			if !filepath.IsAbs(path) || strings.Contains(path, "$") {
				unknown = true
				continue
			}
			paths = append(paths, filepath.Join(path, needed))
		}
	}
	paths = append(paths, cache[needed]...)
	defaults := []string{"/usr/lib", "/lib", "/usr/lib64", "/lib64"}
	if observation.Bits == 32 {
		defaults = []string{"/usr/lib32", "/lib32", "/usr/lib", "/lib"}
	}
	for _, path := range defaults {
		paths = append(paths, filepath.Join(path, needed))
	}
	return paths, unknown
}

func shebangInterpreter(line string) (string, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 || !filepath.IsAbs(parts[0]) {
		return "", errors.New("absolute interpreter path is required")
	}
	if parts[0] != "/usr/bin/env" && parts[0] != "/bin/env" {
		return parts[0], nil
	}
	args := parts[1:]
	if len(args) > 0 && args[0] == "-S" {
		args = args[1:]
	} else if len(args) != 1 {
		return "", errors.New("env with multiple arguments requires -S")
	}
	if len(args) == 0 || strings.ContainsAny(args[0], "'\"\\$=") || strings.HasPrefix(args[0], "-") || strings.Contains(args[0], "/") {
		return "", errors.New("env interpreter cannot be resolved statically")
	}
	return "/usr/bin/" + args[0], nil
}

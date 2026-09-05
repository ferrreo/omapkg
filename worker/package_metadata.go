package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func findArtifact(output, packageName string) (string, error) {
	entries, err := os.ReadDir(output)
	if err != nil {
		return "", err
	}
	var artifacts []string
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".pkg.tar.zst") {
			continue
		}
		if err := validateArtifactFilename(entry.Name()); err != nil {
			return "", err
		}
		artifacts = append(artifacts, filepath.Join(output, entry.Name()))
	}
	if len(artifacts) == 0 {
		return "", errors.New("build produced no matching .pkg.tar.zst artifact")
	}
	if len(artifacts) > 1 {
		return "", errors.New("build produced multiple artifacts but protocol accepts one")
	}
	if packageName != "" && !strings.HasPrefix(filepath.Base(artifacts[0]), packageName+"-") {
		return "", errors.New("build produced an artifact for a different package")
	}
	return artifacts[0], nil
}

type packageMetadata struct {
	Name          string   `json:"name"`
	FullVersion   string   `json:"fullVersion"`
	Architecture  string   `json:"architecture"`
	InstalledSize int64    `json:"installedSize"`
	Depends       []string `json:"depends"`
	Provides      []string `json:"provides"`
	Conflicts     []string `json:"conflicts"`
	Replaces      []string `json:"replaces"`
}

func readPackageMetadata(output, artifact string, job Job) (packageMetadata, error) {
	filename := filepath.Join(output, ".PKGINFO")
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return packageMetadata{}, errors.New("build did not produce regular .PKGINFO metadata")
	}
	file, err := os.Open(filename)
	if err != nil {
		return packageMetadata{}, fmt.Errorf("open .PKGINFO metadata: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	closeErr := file.Close()
	if err != nil {
		return packageMetadata{}, fmt.Errorf("read .PKGINFO metadata: %w", err)
	}
	if closeErr != nil {
		return packageMetadata{}, fmt.Errorf("close .PKGINFO metadata: %w", closeErr)
	}
	if len(data) > 1<<20 {
		return packageMetadata{}, errors.New("package metadata is too large")
	}
	metadata, err := parsePackageMetadata(data)
	if err != nil {
		return packageMetadata{}, err
	}
	if metadata.Name != job.PackageName {
		return packageMetadata{}, fmt.Errorf("package metadata name %q does not match job %q", metadata.Name, job.PackageName)
	}
	expectedVersion := job.Version
	if job.Pkgrel > 0 {
		suffix := "-" + strconv.FormatInt(job.Pkgrel, 10)
		if !strings.HasSuffix(expectedVersion, suffix) {
			expectedVersion += suffix
		}
	}
	if metadata.FullVersion != expectedVersion {
		return packageMetadata{}, fmt.Errorf("package metadata version %q does not match job %q", metadata.FullVersion, expectedVersion)
	}
	if metadata.Architecture != job.Architecture {
		return packageMetadata{}, fmt.Errorf("package metadata architecture %q does not match job %q", metadata.Architecture, job.Architecture)
	}
	expectedFilename := fmt.Sprintf("%s-%s-%s.pkg.tar.zst", job.PackageName, expectedVersion, job.Architecture)
	if filepath.Base(artifact) != expectedFilename {
		return packageMetadata{}, fmt.Errorf("artifact filename %q does not match package metadata", filepath.Base(artifact))
	}
	if metadata.InstalledSize < 0 {
		return packageMetadata{}, errors.New("package metadata installed size is negative")
	}
	if artifact == "" {
		return packageMetadata{}, errors.New("artifact path is required for package metadata")
	}
	return metadata, nil
}

func parsePackageMetadata(data []byte) (packageMetadata, error) {
	metadata := packageMetadata{
		Depends:   make([]string, 0),
		Provides:  make([]string, 0),
		Conflicts: make([]string, 0),
		Replaces:  make([]string, 0),
	}
	seen := make(map[string]bool, 4)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		if key == "pkgname" || key == "pkgver" || key == "arch" || key == "size" {
			if seen[key] {
				return packageMetadata{}, fmt.Errorf("duplicate .PKGINFO field %q", key)
			}
			seen[key] = true
		}
		switch key {
		case "pkgname":
			if !packageRelationNamePattern.MatchString(value) {
				return packageMetadata{}, errors.New("package metadata package name is invalid")
			}
			metadata.Name = value
		case "pkgver":
			if !parsePackageVersion(value) {
				return packageMetadata{}, errors.New("package metadata package version is invalid")
			}
			metadata.FullVersion = value
		case "arch":
			metadata.Architecture = value
		case "size":
			size, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return packageMetadata{}, errors.New("package metadata installed size is invalid")
			}
			if size < 0 || size > 1<<53-1 {
				return packageMetadata{}, errors.New("package metadata installed size is outside JSON safe range")
			}
			metadata.InstalledSize = size
		case "depend", "provides", "conflict", "replaces":
			relation, err := parsePackageRelation(value, key == "provides", key == "depend" || key == "provides")
			if err != nil {
				return packageMetadata{}, fmt.Errorf("package metadata %s is invalid: %w", key, err)
			}
			var values *[]string
			switch key {
			case "depend":
				values = &metadata.Depends
			case "provides":
				values = &metadata.Provides
			case "conflict":
				values = &metadata.Conflicts
			case "replaces":
				values = &metadata.Replaces
			}
			if len(*values) >= maxPackageRelations {
				return packageMetadata{}, errors.New("package metadata relation list is too large")
			}
			*values = append(*values, relation)
		}
	}
	if !seen["pkgname"] || !seen["pkgver"] || !seen["arch"] || !seen["size"] {
		return packageMetadata{}, errors.New("package metadata is missing required fields")
	}
	return metadata, nil
}

var (
	packageRelationNamePattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9@._+-]{0,63}$`)
	packageRelationSonameV1Pattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}\.so$`)
	packageRelationSonamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,31}:[A-Za-z0-9][A-Za-z0-9._+~^-]{0,127}$`)
	packageRelationVersionPattern  = regexp.MustCompile(`^(?:[0-9]+:)?[A-Za-z0-9][A-Za-z0-9@._+%~^:-]{0,127}$`)
)

func parsePackageVersion(value string) bool {
	if !packageRelationVersionPattern.MatchString(value) {
		return false
	}
	separator := strings.IndexByte(value, ':')
	if separator < 0 {
		return true
	}
	if separator == 0 || separator == len(value)-1 || strings.Contains(value[separator+1:], ":") {
		return false
	}
	for _, character := range value[:separator] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func parsePackageRelation(value string, provides, allowSoname bool) (string, error) {
	if len(value) == 0 || len(value) > maxPackageRelationBytes || strings.ContainsAny(value, " \t\r\n\x00") {
		return "", errors.New("relation has invalid length or whitespace")
	}
	operatorAt := -1
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character != '<' && character != '>' && character != '=' {
			continue
		}
		if operatorAt >= 0 {
			return "", errors.New("relation has multiple comparison operators")
		}
		operatorAt = index
		if index+1 < len(value) && (value[index:index+2] == "<=" || value[index:index+2] == ">=") {
			index++
		}
	}
	name := value
	operator := ""
	if operatorAt >= 0 {
		operatorLength := 1
		if operatorAt+1 < len(value) && (value[operatorAt:operatorAt+2] == "<=" || value[operatorAt:operatorAt+2] == ">=") {
			operatorLength = 2
		}
		operator = value[operatorAt : operatorAt+operatorLength]
		if provides && operator != "=" {
			return "", errors.New("provides may only use =")
		}
		name = value[:operatorAt]
		version := value[operatorAt+operatorLength:]
		if !parsePackageVersion(version) {
			return "", errors.New("relation comparison operator is invalid")
		}
	}
	if packageRelationNamePattern.MatchString(name) {
		return value, nil
	}
	if packageRelationSonameV1Pattern.MatchString(name) {
		if !allowSoname || (operatorAt >= 0 && operator != "=") {
			return "", errors.New("legacy SONAME relation is not allowed here")
		}
		return value, nil
	}
	if operatorAt >= 0 && packageRelationSonamePattern.MatchString(name) {
		return "", errors.New("SONAME relations cannot use a comparison operator")
	}
	colon := strings.IndexByte(name, ':')
	if !allowSoname || !packageRelationSonamePattern.MatchString(name) || colon < 0 || !strings.Contains(strings.ToLower(name[colon+1:]), ".so") {
		return "", errors.New("relation name is invalid")
	}
	return value, nil
}

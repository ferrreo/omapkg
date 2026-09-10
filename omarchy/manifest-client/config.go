package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var sectionPattern = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)

type configSection struct {
	name  string
	lines []string
}

func readConfig(path string) ([]byte, os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.New("pacman config is not a regular file")
	}
	data, err := os.ReadFile(path)
	return data, info.Mode().Perm(), err
}

func rewriteConfig(input []byte, repositories []Repository) ([]byte, error) {
	if len(repositories) == 0 {
		return nil, errors.New("cannot render pacman config without repositories")
	}
	sections, prefix := parseSections(input)
	if activeRepoDirective(append([]string{"[prefix]"}, strings.SplitAfter(string(prefix), "\n")...)) {
		return nil, errors.New("unmanaged pacman Include directive remains before repository sections; migrate it before using signed transaction")
	}
	owned := make(map[string]Repository, len(repositories))
	order := make([]string, 0, len(repositories))
	for _, repository := range repositories {
		if _, exists := owned[repository.Name]; exists {
			return nil, fmt.Errorf("duplicate repository %q", repository.Name)
		}
		owned[repository.Name] = repository
		order = append(order, repository.Name)
	}
	present := make([]string, 0, len(repositories))
	seenSections := map[string]bool{}
	for _, section := range sections {
		if _, isOwned := owned[section.name]; !isOwned && activeRepoDirective(section.lines) {
			return nil, fmt.Errorf("unmanaged enabled repository [%s] remains; remove or migrate it before using signed transaction (AUR/ALARM/live upstream fallback is forbidden)", section.name)
		}
		if _, isOwned := owned[section.name]; !isOwned {
			continue
		}
		if seenSections[section.name] {
			return nil, fmt.Errorf("pacman config contains duplicate owned section [%s]", section.name)
		}
		seenSections[section.name] = true
		for _, line := range section.lines[1:] {
			trimmed := strings.TrimSpace(line)
			lower := strings.ToLower(trimmed)
			if strings.HasPrefix(lower, "siglevel") && strings.Contains(trimmed, "=") && !strings.Contains(lower, "required") {
				return nil, fmt.Errorf("owned repository [%s] does not require package signatures", section.name)
			}
		}
		present = append(present, section.name)
	}
	if !isSubsequence(order, present) {
		return nil, errors.New("local owned repository order differs from signed transaction")
	}
	var output bytes.Buffer
	output.Write(prefix)
	for _, section := range sections {
		repository, isOwned := owned[section.name]
		if isOwned {
			output.WriteString(renderOwnedSection(section, repository))
		} else {
			for _, line := range section.lines {
				output.WriteString(line)
			}
		}
	}
	for _, name := range order {
		if seenSections[name] {
			continue
		}
		if output.Len() > 0 && !bytes.HasSuffix(output.Bytes(), []byte("\n")) {
			output.WriteByte('\n')
		}
		if output.Len() > 0 {
			output.WriteByte('\n')
		}
		output.WriteString(renderMissingSection(owned[name]))
	}
	return output.Bytes(), nil
}

func activeRepoDirective(lines []string) bool {
	for _, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if (strings.HasPrefix(lower, "server") || strings.HasPrefix(lower, "include")) && strings.Contains(trimmed, "=") {
			return true
		}
	}
	return false
}

func parseSections(input []byte) ([]configSection, []byte) {
	lines := strings.SplitAfter(string(input), "\n")
	var prefix []byte
	sections := []configSection{}
	current := -1
	for _, line := range lines {
		match := sectionPattern.FindStringSubmatch(strings.TrimSuffix(line, "\n"))
		if match != nil {
			sections = append(sections, configSection{name: match[1], lines: []string{line}})
			current = len(sections) - 1
			continue
		}
		if current < 0 {
			prefix = append(prefix, line...)
		} else {
			sections[current].lines = append(sections[current].lines, line)
		}
	}
	return sections, prefix
}

func renderOwnedSection(section configSection, repository Repository) string {
	var output strings.Builder
	inserted := false
	sigLevel := false
	for index, line := range section.lines {
		if index == 0 {
			output.WriteString(line)
			if !strings.HasSuffix(line, "\n") {
				output.WriteByte('\n')
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "server") && strings.Contains(trimmed, "=") {
			if !inserted {
				output.WriteString("Server = ")
				output.WriteString(repository.PackageBaseURL)
				output.WriteByte('\n')
				inserted = true
			}
			continue
		}
		if strings.HasPrefix(lower, "siglevel") && strings.Contains(trimmed, "=") {
			sigLevel = true
		}
		// Includes in owned sections can point to mutable mirrors. The signed
		// transaction's exact package base is the only allowed source.
		if strings.HasPrefix(lower, "include") && strings.Contains(trimmed, "=") {
			continue
		}
		output.WriteString(line)
	}
	if !sigLevel {
		output.WriteString("SigLevel = Required TrustedOnly\n")
	}
	if !inserted {
		output.WriteString("Server = ")
		output.WriteString(repository.PackageBaseURL)
		output.WriteByte('\n')
	}
	return output.String()
}

func renderMissingSection(repository Repository) string {
	return fmt.Sprintf("[%s]\nSigLevel = Required TrustedOnly\nServer = %s\n", repository.Name, repository.PackageBaseURL)
}

func isSubsequence(expected, actual []string) bool {
	if len(actual) > len(expected) {
		return false
	}
	position := 0
	for _, value := range expected {
		if position < len(actual) && value == actual[position] {
			position++
		}
	}
	return position == len(actual)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if path == "" {
		return errors.New("output path is empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".omapkg-atomic-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func digestFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

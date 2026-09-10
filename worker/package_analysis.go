package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"unicode/utf8"
)

type packageInspection struct {
	metadata  packageMetadata
	optional  []string
	payload   map[string][]any
	elfs      []elfObservation
	shebangs  map[string]string
	native    []string
	unpacked  int64
	inventory *abiInventoryWriter
}

func analysisText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsFunc(value, func(c rune) bool { return c < 32 || c == 127 })
}

func analyzePackageCommand(args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return errors.New("usage: opr-worker analyze-package ARTIFACT [EVIDENCE_DIRECTORY]")
	}
	artifact, _, err := hashFile(args[0])
	if err != nil {
		return err
	}
	var inventory *abiInventoryWriter
	if len(args) == 2 {
		inventory = &abiInventoryWriter{directory: args[1], artifact: artifact}
	}
	command := exec.Command("/usr/bin/bsdtar", "-cf", "-", "@"+args[0])
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	var diagnostic boundedBuffer
	diagnostic.limit = 4096
	command.Stderr = &diagnostic
	pipe, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	inspection, scanErr := inspectPackageTar(pipe, inventory)
	if scanErr != nil {
		_ = command.Process.Kill()
	}
	// Read to EOF so an archive conversion error cannot be hidden by tar's end marker.
	if scanErr == nil {
		_, scanErr = io.Copy(io.Discard, pipe)
	}
	waitErr := command.Wait()
	if scanErr != nil {
		return scanErr
	}
	if waitErr != nil {
		return fmt.Errorf("package archive conversion failed: %w: %s", waitErr, diagnostic.String())
	}
	analysis, err := inspection.runtimeAnalysis("/")
	if err != nil {
		return err
	}
	encoded, err := encodeJSON(analysis)
	if err != nil {
		return err
	}
	if len(encoded) > 256*1024 {
		return errors.New("runtime dependency evidence exceeds 256 KiB")
	}
	_, err = fmt.Fprintln(os.Stdout, string(encoded))
	return err
}

func inspectPackageTar(source io.Reader, inventory *abiInventoryWriter) (*packageInspection, error) {
	inspection := &packageInspection{payload: map[string][]any{}, shebangs: map[string]string{}, native: []string{}, inventory: inventory}
	archive := tar.NewReader(source)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name := strings.TrimRight(header.Name, "/")
		if strings.HasSuffix(header.Name, "//") || header.Typeflag != tar.TypeDir && header.Name != name {
			return nil, errors.New("noncanonical package archive path")
		}
		if !analysisText(name, 4096) || name == "" || len(inspection.payload) >= 100_000 || inspection.payload[name] != nil ||
			!analysisText(header.Linkname, 4096) || header.Mode < 0 || header.Mode > 0o7777 || header.Uid < 0 || header.Gid < 0 {
			return nil, errors.New("duplicate, unsafe or oversized package inventory")
		}
		for _, part := range strings.Split(name, "/") {
			if part == "" || part == "." || part == ".." {
				return nil, errors.New("unsafe package path")
			}
		}
		if header.Typeflag < '0' || header.Typeflag > '7' {
			return nil, errors.New("unsupported package entry type")
		}
		inspection.payload[name] = []any{name, string(header.Typeflag), header.Mode, header.Uid, header.Gid, header.Linkname, nil}
		record := map[string]any{"kind": "file", "path": name, "type": string(header.Typeflag), "mode": header.Mode, "link": header.Linkname, "sha256": nil, "nativeKind": nil, "elf": nil}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeCont {
			if err := inventory.append(record); err != nil {
				return nil, err
			}
			continue
		}
		if header.Size < 0 || header.Size > 4<<30 || inspection.unpacked+header.Size > 32<<30 {
			return nil, errors.New("package analysis exceeds 4 GiB per file or 32 GiB payload budget")
		}
		inspection.unpacked += header.Size
		if err := inspection.regularFile(archive, header, name, record); err != nil {
			return nil, err
		}
	}
	if inspection.metadata.Name == "" {
		return nil, errors.New("package analysis requires .PKGINFO metadata")
	}
	return inspection, nil
}

func (s *packageInspection) regularFile(source io.Reader, header *tar.Header, name string, record map[string]any) error {
	first := make([]byte, min(header.Size, 4097))
	if _, err := io.ReadFull(source, first); err != nil {
		return err
	}
	reader := io.MultiReader(bytes.NewReader(first), source)
	hash := sha256.New()
	reader = io.TeeReader(reader, hash)
	native := nativeMagic(first)
	if native != "" {
		s.native = append(s.native, name)
		if len(s.native) > 4096 {
			return errors.New("native code inventory exceeds 4096 files")
		}
		record["nativeKind"] = native
	}
	var temporary *os.File
	if native == "elf" {
		file, err := os.CreateTemp("", "opr-elf-")
		if err != nil {
			return err
		}
		temporary = file
		defer func() { file.Close(); os.Remove(file.Name()) }()
		if _, err := io.Copy(file, reader); err != nil {
			return err
		}
	} else if name == ".PKGINFO" {
		if header.Size > 1<<20 {
			return errors.New("package metadata exceeds 1 MiB")
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		s.metadata, err = parsePackageMetadata(data)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			if value, ok := strings.CutPrefix(line, "optdepend = "); ok {
				// An optional dependency description starts with ': '; epochs have no space.
				value, _, _ = strings.Cut(value, ": ")
				if !validArchDependency(value) || len(s.optional) >= 256 {
					return errors.New("invalid optional dependency metadata")
				}
				s.optional = append(s.optional, value)
			}
		}
	} else {
		if _, err := io.Copy(io.Discard, reader); err != nil {
			return err
		}
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	s.payload[name][6], record["sha256"] = digest, digest
	if native == "elf" {
		file, observation, details, err := inspectELF(temporary, name)
		if err != nil {
			return err
		}
		defer file.Close()
		if file.Data != elf.ELFDATA2LSB || observation.Machine == "EM_386" && observation.Bits != 32 || observation.Machine != "EM_386" && observation.Bits != 64 {
			return errors.New("ELF byte order or class differs from native analysis target")
		}
		if runtime.GOARCH == "arm64" && (observation.Machine != "EM_AARCH64" || observation.Bits != 64) ||
			runtime.GOARCH == "amd64" && observation.Machine != "EM_X86_64" && observation.Machine != "EM_386" {
			return errors.New("ELF machine differs from native analysis target")
		}
		s.elfs = append(s.elfs, observation)
		record["elf"] = details
		if err := s.inventory.append(record); err != nil {
			return err
		}
		return s.inventory.elfSymbols(file, name)
	}
	if bytes.HasPrefix(first, []byte("#!")) {
		line, _, _ := bytes.Cut(first, []byte("\n"))
		if len(line) > 4096 || !analysisText(string(line), 4096) {
			return errors.New("script interpreter exceeds analysis limit")
		}
		s.shebangs[name] = strings.TrimSpace(string(line[2:]))
	}
	return s.inventory.append(record)
}

func (s *packageInspection) runtimeAnalysis(root string) (*runtimeAnalysis, error) {
	files := make([]string, 0, len(s.payload))
	for name := range s.payload {
		if name != ".BUILDINFO" && name != ".MTREE" {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	payload := make([][]any, 0, len(files))
	for _, name := range files {
		payload = append(payload, s.payload[name])
	}
	encoded, err := encodeJSON(payload)
	if err != nil {
		return nil, err
	}
	analysis := &runtimeAnalysis{SchemaVersion: 2, Tool: "go-native-analysis", ToolVersion: runtime.Version(), PayloadSHA256: hashBytes(encoded),
		ELF: []json.RawMessage{}, NativeCode: &s.native, Findings: []analysisFinding{}, Unknowns: []string{"unexercised dlopen", "plugins", "runtime-selected subprocesses", "data paths", "C/C++ type ABI not checked"}}
	for _, observation := range s.elfs {
		data, err := encodeJSON(observation)
		if err != nil {
			return nil, err
		}
		analysis.ELF = append(analysis.ELF, data)
	}
	if err := s.checkDependencies(root, analysis); err != nil {
		return nil, err
	}
	analysis.ABIInventory, err = s.inventory.finish()
	return analysis, err
}

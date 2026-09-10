package main

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"strings"
)

type elfObservation struct {
	Path           string   `json:"path"`
	Machine        string   `json:"machine"`
	Needed         []string `json:"needed"`
	SearchPaths    []string `json:"searchPaths"`
	Bits           int      `json:"-"`
	Rpath, Runpath []string `json:"-"`
	Interpreter    string   `json:"-"`
}

func inspectELF(source io.ReaderAt, name string) (*elf.File, elfObservation, map[string]any, error) {
	file, err := elf.NewFile(source)
	if err != nil {
		return nil, elfObservation{}, nil, err
	}
	if err := validateELFMetadata(file); err != nil {
		return nil, elfObservation{}, nil, err
	}
	observation := elfObservation{Path: name, Machine: file.Machine.String(), Needed: []string{}, SearchPaths: []string{}, Bits: 32}
	if file.Class == elf.ELFCLASS64 {
		observation.Bits = 64
	}
	values := map[elf.DynTag][]string{}
	for _, tag := range []elf.DynTag{elf.DT_NEEDED, elf.DT_RPATH, elf.DT_RUNPATH, elf.DT_SONAME} {
		entries, err := file.DynString(tag)
		if err != nil {
			return nil, observation, nil, err
		}
		values[tag] = append([]string{}, entries...)
		if len(entries) > 4096 {
			return nil, observation, nil, errors.New("ELF dynamic string inventory exceeds limit")
		}
		for _, entry := range entries {
			if !analysisText(entry, 4096) {
				return nil, observation, nil, errors.New("invalid ELF dynamic string")
			}
			if (tag == elf.DT_NEEDED || tag == elf.DT_SONAME) && entry == "" {
				return nil, observation, nil, errors.New("empty ELF dynamic identity")
			}
		}
	}
	if len(values[elf.DT_SONAME]) > 1 {
		return nil, observation, nil, errors.New("ELF has duplicate SONAME")
	}
	interpreterSeen := false
	for _, program := range file.Progs {
		if program.Type != elf.PT_INTERP {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(program.Open(), 4097))
		if err != nil || len(data) == 0 || len(data) > 4096 || uint64(len(data)) != program.Filesz || data[len(data)-1] != 0 || interpreterSeen {
			return nil, observation, nil, errors.New("invalid ELF interpreter")
		}
		interpreterSeen = true
		observation.Interpreter = string(data[:len(data)-1])
		if !analysisText(observation.Interpreter, 4096) || !strings.HasPrefix(observation.Interpreter, "/") {
			return nil, observation, nil, errors.New("invalid ELF interpreter path")
		}
	}
	observation.Needed, observation.Rpath, observation.Runpath = values[elf.DT_NEEDED], values[elf.DT_RPATH], values[elf.DT_RUNPATH]
	observation.SearchPaths = append(observation.SearchPaths, observation.Rpath...)
	observation.SearchPaths = append(observation.SearchPaths, observation.Runpath...)
	byteOrder := "little"
	if file.Data == elf.ELFDATA2MSB {
		byteOrder = "big"
	}
	debugInfo, dynamicSymbols := "absent", "absent"
	if file.Section(".debug_info") != nil || file.Section(".zdebug_info") != nil {
		debugInfo = "present"
	}
	if file.SectionByType(elf.SHT_DYNSYM) != nil {
		dynamicSymbols = "present"
	}
	var soname any
	if len(values[elf.DT_SONAME]) == 1 {
		soname = values[elf.DT_SONAME][0]
	}
	return file, observation, map[string]any{"machine": observation.Machine, "type": file.Type.String(), "bits": observation.Bits,
		"byteOrder": byteOrder, "soname": soname, "needed": observation.Needed, "rpath": observation.Rpath, "runpath": observation.Runpath,
		"interpreter": nullableString(observation.Interpreter), "debugInfo": debugInfo, "dynamicSymbols": dynamicSymbols}, nil
}

func validateELFMetadata(file *elf.File) error {
	for _, section := range file.Sections {
		switch section.Type {
		case elf.SHT_SYMTAB, elf.SHT_DYNSYM, elf.SHT_STRTAB, elf.SHT_GNU_VERDEF, elf.SHT_GNU_VERNEED, elf.SHT_GNU_VERSYM:
			if section.Size > 256<<20 {
				return errors.New("ELF metadata section exceeds 256 MiB")
			}
		}
		if section.Type == elf.SHT_DYNAMIC && section.Size > 16<<20 {
			return errors.New("ELF dynamic section exceeds 16 MiB")
		}
		if (section.Type == elf.SHT_SYMTAB || section.Type == elf.SHT_DYNSYM) && (section.Entsize == 0 || section.Size/section.Entsize > 2_000_000) {
			return errors.New("ELF symbol table exceeds two million entries")
		}
	}
	dynamic := file.SectionByType(elf.SHT_DYNAMIC)
	programs := 0
	for _, program := range file.Progs {
		if program.Type != elf.PT_DYNAMIC {
			continue
		}
		programs++
		if program.Filesz > 16<<20 || dynamic == nil || program.Off != dynamic.Offset || program.Filesz != dynamic.Size || programs > 1 {
			return errors.New("ELF dynamic program and section metadata disagree")
		}
	}
	if programs == 0 {
		return nil
	}
	for _, pair := range []struct {
		tag     elf.DynTag
		section elf.SectionType
	}{
		{elf.DT_STRTAB, elf.SHT_STRTAB}, {elf.DT_SYMTAB, elf.SHT_DYNSYM}, {elf.DT_VERSYM, elf.SHT_GNU_VERSYM},
		{elf.DT_VERNEED, elf.SHT_GNU_VERNEED}, {elf.DT_VERDEF, elf.SHT_GNU_VERDEF},
	} {
		values, err := file.DynValue(pair.tag)
		if err != nil {
			return err
		}
		if len(values) == 0 {
			continue
		}
		section := file.SectionByType(pair.section)
		if pair.tag == elf.DT_STRTAB {
			if int(dynamic.Link) >= len(file.Sections) {
				return errors.New("ELF dynamic string table is missing")
			}
			section = file.Sections[dynamic.Link]
		}
		if len(values) != 1 || section == nil || section.Type != pair.section || values[0] != section.Addr {
			return errors.New("ELF runtime table differs from section metadata")
		}
		mapped := false
		for _, program := range file.Progs {
			if program.Type == elf.PT_LOAD && program.Off <= 4<<30 && section.Addr >= program.Vaddr && section.Size <= program.Filesz &&
				section.Addr-program.Vaddr <= program.Filesz-section.Size && section.Offset == program.Off+(section.Addr-program.Vaddr) {
				mapped = true
				break
			}
		}
		if !mapped {
			return errors.New("ELF runtime metadata is outside its load segment")
		}
	}
	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (w *abiInventoryWriter) elfSymbols(file *elf.File, name string) error {
	if w == nil {
		return nil
	}
	var err error
	for _, dynamic := range []bool{true, false} {
		var symbols []elf.Symbol
		var section *elf.Section
		if dynamic {
			symbols, err = file.DynamicSymbols()
			section = file.SectionByType(elf.SHT_DYNSYM)
		} else {
			symbols, err = file.Symbols()
			section = file.SectionByType(elf.SHT_SYMTAB)
		}
		if errors.Is(err, elf.ErrNoSymbols) {
			continue
		}
		if err != nil {
			return err
		}
		if section == nil || len(symbols) > 2_000_000 {
			return errors.New("ELF symbol table exceeds limit")
		}
		for index, symbol := range symbols {
			if symbol.Name == "" || elf.ST_BIND(symbol.Info) == elf.STB_LOCAL {
				continue
			}
			if !analysisText(symbol.Name, 16384) || symbol.Size > 1<<53-1 {
				return errors.New("ELF symbol exceeds evidence limit")
			}
			version := symbol.Version
			if symbol.HasVersion && symbol.VersionIndex.Index() > 1 && version == "" {
				return fmt.Errorf("ELF symbol %s has unresolved version", symbol.Name)
			}
			if !analysisText(version, 4096) || !analysisText(symbol.Library, 4096) {
				return errors.New("invalid ELF symbol version")
			}
			if err := w.append(map[string]any{"kind": "symbol", "path": name, "table": section.Name, "dynamic": dynamic, "index": index + 1,
				"name": symbol.Name, "defined": symbol.Section != elf.SHN_UNDEF, "binding": elf.ST_BIND(symbol.Info).String(), "type": elf.ST_TYPE(symbol.Info).String(),
				"visibility": elf.ST_VISIBILITY(symbol.Other).String(), "size": symbol.Size, "version": nullableString(version), "versionFile": nullableString(symbol.Library),
				"versionHidden": symbol.HasVersion && symbol.VersionIndex.IsHidden()}); err != nil {
				return err
			}
		}
	}
	return nil
}

func nativeMagic(magic []byte) string {
	value := string(magic)
	if strings.HasPrefix(value, "\x7fELF") {
		return "elf"
	}
	if strings.HasPrefix(value, "!<arch>\n") {
		return "static-archive"
	}
	if strings.HasPrefix(value, "!<thin>\n") {
		return "thin-archive"
	}
	if strings.HasPrefix(value, "MZ") {
		return "other"
	}
	if len(magic) < 4 {
		return ""
	}
	switch value[:4] {
	case "\xfe\xed\xfa\xce", "\xce\xfa\xed\xfe", "\xfe\xed\xfa\xcf", "\xcf\xfa\xed\xfe":
		return "other"
	}
	if len(magic) >= 8 && (value[:4] == "\xca\xfe\xba\xbe" && magic[4] == 0 && magic[5] == 0 && magic[6] == 0 && magic[7] >= 1 && magic[7] <= 32 ||
		value[:4] == "\xbe\xba\xfe\xca" && magic[7] == 0 && magic[6] == 0 && magic[5] == 0 && magic[4] >= 1 && magic[4] <= 32) {
		return "other"
	}
	return ""
}

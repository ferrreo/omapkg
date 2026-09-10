package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

type abiChunkRef struct {
	inputObject
	Start   int `json:"start"`
	Count   int `json:"count"`
	Files   int `json:"files"`
	Symbols int `json:"symbols"`
}

type abiInventoryWriter struct {
	directory, artifact                      string
	records                                  []json.RawMessage
	chunks                                   []abiChunkRef
	files, symbols, start, bytes, chunkFiles int
}

func (w *abiInventoryWriter) store(value any) (inputObject, error) {
	data, err := encodeJSON(value)
	if err != nil {
		return inputObject{}, err
	}
	if len(data) > maxABIDocument {
		return inputObject{}, errors.New("ABI document exceeds 512 KiB")
	}
	ref := inputObject{SHA256: hashBytes(data), Size: int64(len(data))}
	return ref, os.WriteFile(filepath.Join(w.directory, ref.SHA256+".json"), data, 0o644)
}

func (w *abiInventoryWriter) append(record map[string]any) error {
	if w == nil {
		return nil
	}
	data, err := encodeJSON(record)
	if err != nil {
		return err
	}
	if len(data) > 64*1024 || w.files+w.symbols >= 2_100_000 {
		return errors.New("ABI record inventory exceeds limit")
	}
	if len(w.records) > 0 && (w.bytes+len(data) > maxABIDocument-1024 || len(w.records) >= 2048) {
		if err := w.flush(); err != nil {
			return err
		}
	}
	w.records = append(w.records, data)
	w.bytes += len(data) + 1
	if record["kind"] == "file" {
		w.files++
		w.chunkFiles++
	} else {
		w.symbols++
	}
	if w.files > 100_000 || w.symbols > 2_000_000 {
		return errors.New("ABI inventory exceeds file or symbol budget")
	}
	return nil
}

func (w *abiInventoryWriter) flush() error {
	if len(w.records) == 0 {
		return nil
	}
	if len(w.chunks) >= 2048 {
		return errors.New("ABI inventory exceeds 2048 chunks")
	}
	ref, err := w.store(map[string]any{"schemaVersion": 1, "kind": "abi-records", "artifactSha256": w.artifact, "start": w.start, "records": w.records})
	if err != nil {
		return err
	}
	w.chunks = append(w.chunks, abiChunkRef{inputObject: ref, Start: w.start, Count: len(w.records), Files: w.chunkFiles, Symbols: len(w.records) - w.chunkFiles})
	w.start += len(w.records)
	w.records, w.bytes, w.chunkFiles = nil, 0, 0
	return nil
}

func (w *abiInventoryWriter) finish() (*inputObject, error) {
	if w == nil {
		return nil, nil
	}
	if err := w.flush(); err != nil {
		return nil, err
	}
	ref, err := w.store(map[string]any{"schemaVersion": 1, "kind": "abi-inventory", "artifactSha256": w.artifact,
		"tool": "go-debug-elf", "toolVersion": runtime.Version(), "files": w.files, "symbols": w.symbols, "chunks": w.chunks, "typeAbi": "not-checked"})
	return &ref, err
}

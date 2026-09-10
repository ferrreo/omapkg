package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// OCI tests mount the running executable, including when it is the Go test binary.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "analyze-package" {
		if err := analyzePackageCommand(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestNativeAnalysisRetainsVersionedSymbolsAndBlocksUndeclaredProviders(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("native ELF fixture needs cc")
	}
	directory := t.TempDir()
	write := func(name, contents string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(directory, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("provider.c", "int exported = 7; int add(int value) { return value + 1; }\n")
	write("provider.map", "ABI_1 { global: add; exported; local: *; };\n")
	write("consumer.c", "extern int add(int); int use(void) { return add(2); }\n")
	write("copy.c", "extern int exported; int main(void) { return exported; }\n")
	compile := func(args ...string) {
		t.Helper()
		command := exec.Command(compiler, args...)
		command.Dir = directory
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("compile ELF fixture: %v: %s", err, output)
		}
	}
	compile("-fPIC", "-shared", "-nostdlib", "-g", "provider.c", "-Wl,-soname,libprovider.so.1", "-Wl,--version-script=provider.map", "-o", "libprovider.so.1")
	compile("-fPIC", "-shared", "-nostdlib", "consumer.c", "-L.", "-l:libprovider.so.1", "-Wl,-rpath,$ORIGIN/..", "-o", "consumer.so")
	compile("-fno-pic", "-no-pie", "-nostdlib", "-Wl,-e,main", "copy.c", "-L.", "-l:libprovider.so.1", "-o", "copy")
	provider, _ := os.ReadFile(filepath.Join(directory, "libprovider.so.1"))
	consumer, _ := os.ReadFile(filepath.Join(directory, "consumer.so"))
	copyRelocation, _ := os.ReadFile(filepath.Join(directory, "copy"))
	malformed := append([]byte(nil), consumer...)
	needed := []byte("libprovider.so.1")
	if offset := bytes.Index(malformed, needed); offset < 0 {
		t.Fatal("consumer fixture has no dynamic dependency string")
	} else {
		for index := range needed {
			malformed[offset+index] = 0
		}
		if _, _, _, err := inspectELF(bytes.NewReader(malformed), "malformed"); err == nil {
			t.Fatal("accepted empty ELF DT_NEEDED identity")
		}
	}
	write("root/usr/lib/libprovider.so.1", string(provider))
	write("root/usr/lib/plugin/consumer.so", string(consumer))
	write("root/var/lib/pacman/local/provider-1-1/desc", "%NAME%\nprovider\n\n%VERSION%\n1-1\n\n%PROVIDES%\nlibprovider.so=1-64\n\n")
	write("root/var/lib/pacman/local/provider-1-1/files", "%FILES%\nusr/lib/libprovider.so.1\n\n")
	write("root/var/lib/pacman/local/consumer-1-1/desc", "%NAME%\nconsumer\n\n%VERSION%\n1-1\n\n")
	write("root/var/lib/pacman/local/consumer-1-1/files", "%FILES%\nusr/lib/plugin/consumer.so\n\n")
	archive := func(entries map[string][]byte) []byte {
		t.Helper()
		var data bytes.Buffer
		writer := tar.NewWriter(&data)
		for _, name := range slices.Sorted(maps.Keys(entries)) {
			value := entries[name]
			if err := writer.WriteHeader(&tar.Header{Name: name, Size: int64(len(value)), Mode: 0o644}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(value); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return data.Bytes()
	}
	pkginfo := "pkgbase = consumer\npkgname = consumer\npkgver = 1-1\narch = x86_64\nsize = 123\n"
	for _, dependency := range []string{"depend = provider\n", "depend = libprovider.so=1-64\n", "", "optdepend = provider: Optional plugin\n"} {
		data := archive(map[string][]byte{".PKGINFO": []byte(pkginfo + dependency), "usr/lib/plugin/consumer.so": consumer})
		writer := &abiInventoryWriter{directory: directory, artifact: hashBytes(data)}
		inspection, err := inspectPackageTar(bytes.NewReader(data), writer)
		if err != nil {
			t.Fatal(err)
		}
		report, err := inspection.runtimeAnalysis(filepath.Join(directory, "root"))
		if err != nil {
			t.Fatal(err)
		}
		if report.Tool != "go-native-analysis" || report.SchemaVersion != 2 || report.RuntimeClosureComplete || report.ABIInventory == nil {
			t.Fatal("missing native analysis contract")
		}
		if strings.HasPrefix(dependency, "depend =") && len(report.Findings) != 0 {
			t.Fatalf("declared provider rejected: %+v", report.Findings)
		}
		if dependency == "" && (len(report.Findings) != 1 || report.Findings[0].Code != "dependency-detected-not-included") {
			t.Fatalf("undeclared provider passed: %+v", report.Findings)
		}
		if strings.HasPrefix(dependency, "optdepend") && (len(report.Findings) != 1 || report.Findings[0].Code != "dependency-detected-but-optional") {
			t.Fatalf("optional provider was not reported: %+v", report.Findings)
		}
		for _, finding := range report.Findings {
			if finding.SHA256 != hashBytes([]byte(finding.Level+"\n"+finding.Code+"\n"+finding.Detail)) {
				t.Fatal("finding digest changed")
			}
		}
		root, err := readABIObject(directory, *report.ABIInventory)
		if err != nil {
			t.Fatal(err)
		}
		var manifest struct {
			Chunks  []abiChunkRef `json:"chunks"`
			Files   int           `json:"files"`
			Symbols int           `json:"symbols"`
		}
		if err := json.Unmarshal(root, &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.Files != 2 || manifest.Symbols < 1 {
			t.Fatal("incomplete ABI inventory")
		}
		versioned := false
		for _, ref := range manifest.Chunks {
			chunk, err := readABIObject(directory, ref.inputObject)
			if err != nil {
				t.Fatal(err)
			}
			var records struct {
				Records []map[string]any `json:"records"`
			}
			if err := json.Unmarshal(chunk, &records); err != nil {
				t.Fatal(err)
			}
			for _, record := range records.Records {
				if record["name"] == "add" && record["dynamic"] == true && record["defined"] == false {
					if record["version"] != "ABI_1" || record["versionFile"] != "libprovider.so.1" {
						t.Fatalf("lost imported symbol version: %+v", record)
					}
					versioned = true
				}
			}
		}
		if !versioned {
			t.Fatal("missing versioned import")
		}
	}
	data := archive(map[string][]byte{".PKGINFO": []byte(strings.Replace(pkginfo, "consumer", "provider", -1)), "usr/lib/libprovider.so.1": provider, "usr/lib/libstatic.a": []byte("!<arch>\n")})
	writer := &abiInventoryWriter{directory: directory, artifact: hashBytes(data)}
	inspection, err := inspectPackageTar(bytes.NewReader(data), writer)
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.native) != 2 {
		t.Fatal("static archive was not detected")
	}
	records, err := encodeJSON(writer.records)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(records, []byte(`"version":"ABI_1"`)) {
		t.Fatal("exported symbol version is missing")
	}
	if !bytes.Contains(records, []byte(`"debugInfo":"present"`)) {
		t.Fatal("debug information presence is missing")
	}
	copyWriter := &abiInventoryWriter{directory: directory, artifact: strings.Repeat("a", 64)}
	if _, err := inspectPackageTar(bytes.NewReader(archive(map[string][]byte{".PKGINFO": []byte(pkginfo), "usr/bin/copy": copyRelocation})), copyWriter); err != nil {
		t.Fatalf("copy relocation inventory: %v", err)
	}
	copyFound := false
	for _, data := range copyWriter.records {
		var record map[string]any
		json.Unmarshal(data, &record)
		if record["name"] == "exported" && record["dynamic"] == true && record["defined"] == true {
			if record["version"] != "ABI_1" || record["versionFile"] != "libprovider.so.1" {
				t.Fatal("copy relocation lost provider version")
			}
			copyFound = true
		}
	}
	if !copyFound {
		t.Fatal("copy relocation fixture did not retain its versioned provider")
	}
	directoryInspection := &packageInspection{metadata: packageMetadata{Name: "consumer"}, elfs: []elfObservation{{Path: "usr/bin/fake", Interpreter: "/usr/lib"}}}
	directoryAnalysis := &runtimeAnalysis{Findings: []analysisFinding{}}
	if err := directoryInspection.checkDependencies(filepath.Join(directory, "root"), directoryAnalysis); err != nil {
		t.Fatalf("interpreter directory analysis: %v", err)
	}
	if len(directoryAnalysis.Findings) != 1 || directoryAnalysis.Findings[0].Code != "runtime-file-missing" {
		t.Fatalf("interpreter directory was treated as a file: %+v", directoryAnalysis.Findings)
	}
	for _, bad := range []string{"../escape", "/absolute", "usr//invalid"} {
		if _, err := inspectPackageTar(bytes.NewReader(archive(map[string][]byte{bad: []byte("x")})), nil); err == nil {
			t.Fatal("accepted unsafe archive path")
		}
	}
	for _, check := range []struct{ input, want string }{{"/bin/sh", "/bin/sh"}, {"/usr/bin/env python3", "/usr/bin/python3"}, {"/usr/bin/env -S python3 -O", "/usr/bin/python3"}} {
		actual, err := shebangInterpreter(check.input)
		if err != nil || actual != check.want {
			t.Fatalf("interpreter %q: %s %v", check.input, actual, err)
		}
	}
	if _, err := shebangInterpreter("/usr/bin/env python3 -O"); err == nil {
		t.Fatal("ambiguous env interpreter accepted")
	}
}

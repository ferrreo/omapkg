package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

const maxFrozenTransferBytes int64 = 256 << 30

type inputObject struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type frozenPackage struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	Architecture   string      `json:"architecture"`
	Filename       string      `json:"filename"`
	Package        inputObject `json:"package"`
	Signature      inputObject `json:"signature"`
	PublicKey      inputObject `json:"publicKey"`
	Fingerprint    string      `json:"fingerprint"`
	Origin         string      `json:"origin"`
	OriginEvidence string      `json:"originEvidence"`
}

type frozenEnvironment struct {
	Name            string        `json:"name"`
	PackageCount    int           `json:"packageCount"`
	TotalBytes      int64         `json:"totalBytes"`
	InventorySHA256 string        `json:"inventorySha256"`
	Chunks          []inputObject `json:"chunks"`
}

type frozenInputManifest struct {
	SchemaVersion      int                 `json:"schemaVersion"`
	Purpose            string              `json:"purpose"`
	Architecture       string              `json:"architecture"`
	RecipeSHA256       string              `json:"recipeSha256"`
	CohortSHA256       string              `json:"cohortSha256"`
	SourceDateEpoch    int64               `json:"sourceDateEpoch"`
	HelperImage        string              `json:"helperImage"`
	HelperArchive      inputObject         `json:"helperArchive"`
	MakepkgConfig      inputObject         `json:"makepkgConfig"`
	TransferLimitBytes int64               `json:"transferLimitBytes"`
	Environments       []frozenEnvironment `json:"environments"`
	ShellAnalysis      string              `json:"shellAnalysis,omitempty"`
}

func verifyHelperArchive(path, imageRef string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	seen := map[string]bool{}
	expectedDigest := imageRef[strings.LastIndex(imageRef, "@")+1:]
	manifestDigest := ""
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(header.Name, "./")
		if header.Typeflag == tar.TypeDir && (name == "." || name == "blobs/" || name == "blobs/sha256/") {
			continue
		}
		if header.Typeflag != tar.TypeReg || seen[name] || (name != "index.json" && name != "oci-layout" && !strings.HasPrefix(name, "blobs/sha256/")) {
			return errors.New("retained helper is not a bounded regular OCI archive")
		}
		seen[name] = true
		if name == "index.json" {
			if header.Size > 1<<20 {
				return errors.New("retained OCI index exceeds limit")
			}
			data, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			var index struct {
				SchemaVersion int `json:"schemaVersion"`
				Manifests     []struct {
					Digest string `json:"digest"`
				} `json:"manifests"`
			}
			if json.Unmarshal(data, &index) != nil || index.SchemaVersion != 2 || len(index.Manifests) != 1 || index.Manifests[0].Digest != expectedDigest {
				return errors.New("retained helper manifest does not match pinned image digest")
			}
			manifestDigest = index.Manifests[0].Digest
		} else if strings.HasPrefix(name, "blobs/sha256/") {
			digest := strings.TrimPrefix(name, "blobs/sha256/")
			if !sha256Pattern.MatchString(digest) {
				return errors.New("unsafe OCI blob name")
			}
			hash := sha256.New()
			if _, err := io.Copy(hash, reader); err != nil {
				return err
			}
			if hex.EncodeToString(hash.Sum(nil)) != digest {
				return errors.New("retained OCI blob checksum differs from descriptor")
			}
		}
		if len(seen) > 1024 {
			return errors.New("retained OCI archive has too many objects")
		}
	}
	if manifestDigest == "" || !seen["blobs/sha256/"+strings.TrimPrefix(manifestDigest, "sha256:")] || !seen["oci-layout"] {
		return errors.New("retained OCI archive omits image manifest or layout")
	}
	return nil
}

// The signed lease supplies the root digest. Every subsequent object is reached
// through that root, never through a URL supplied by a package or recipe.
type inputObjectGetter func(context.Context, inputObject, string) error

func validInputObject(ref inputObject, max int64) bool {
	return sha256Pattern.MatchString(ref.SHA256) && ref.Size > 0 && ref.Size <= max
}

func (c *Client) fetchInputObject(ctx context.Context, job Job, ref inputObject, destination string) error {
	return c.fetchPrivateInput(ctx, "jobs", job, ref, destination)
}

func (c *Client) fetchPrivateInput(ctx context.Context, scope string, job Job, ref inputObject, destination string) error {
	if !idPattern.MatchString(job.ID) || !validInputObject(ref, maxFrozenTransferBytes) {
		return errors.New("invalid frozen input reference")
	}
	body, err := encodeJSON(HeartbeatRequest{LeaseToken: job.LeaseToken})
	if err != nil {
		return err
	}
	resp, err := c.signedRequest(ctx, http.MethodPost, "/api/worker/"+scope+"/"+url.PathEscape(job.ID)+"/inputs/"+ref.SHA256, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return readHTTPError(resp)
	}
	if resp.ContentLength >= 0 && resp.ContentLength != ref.Size {
		return errors.New("frozen input response size differs from lock")
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return errors.New("frozen input response must use identity encoding")
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(file, io.LimitReader(resp.Body, ref.Size+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || n != ref.Size {
		_ = os.Remove(destination)
		return fmt.Errorf("frozen input download is incomplete or oversized (%s expected=%d got=%d contentLength=%d err=%v)", ref.SHA256, ref.Size, n, resp.ContentLength, copyErr)
	}
	digest, _, err := hashFile(destination)
	if err != nil || digest != ref.SHA256 {
		_ = os.Remove(destination)
		return errors.New("frozen input download checksum differs from lock")
	}
	return nil
}

type materializedInputs struct {
	Manifest     frozenInputManifest
	Reference    inputObject
	Directory    string
	Environments map[string][]frozenPackage
}

type frozenInputEvidence struct {
	Lock     inputObject         `json:"lock"`
	Manifest frozenInputManifest `json:"manifest"`
	Host     nativeHostEvidence  `json:"host"`
}

type nativeHostEvidence struct {
	Architecture   string `json:"architecture"`
	Kernel         string `json:"kernel"`
	CPUInfoSHA256  string `json:"cpuInfoSha256"`
	CPUModel       string `json:"cpuModel"`
	Runtime        string `json:"runtime"`
	RuntimeVersion string `json:"runtimeVersion"`
	GoVersion      string `json:"goVersion"`
}

func (r *Runner) nativeInputEvidence(ctx context.Context, job Job) (*frozenInputEvidence, error) {
	host, err := r.nativeHost(ctx, job.Architecture)
	if err != nil {
		return nil, err
	}
	return &frozenInputEvidence{Lock: *job.InputLock, Host: host}, nil
}

func (r *Runner) nativeHost(ctx context.Context, target string) (nativeHostEvidence, error) {
	architecture := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	var kernel syscall.Utsname
	if err := syscall.Uname(&kernel); err != nil {
		return nativeHostEvidence{}, err
	}
	field := func(value []int8) string {
		var result []byte
		for _, char := range value {
			if char == 0 {
				break
			}
			result = append(result, byte(char))
		}
		return string(result)
	}
	if architecture != target || field(kernel.Machine[:]) != architecture {
		return nativeHostEvidence{}, errors.New("native jobs require matching worker and kernel architectures")
	}
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return nativeHostEvidence{}, err
	}
	info, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	file.Close()
	if err != nil || len(info) == 0 || len(info) > 1<<20 {
		return nativeHostEvidence{}, errors.New("native CPU evidence is missing or oversized")
	}
	if cpuInfoArchitecture(info) != architecture {
		return nativeHostEvidence{}, errors.New("native worker architecture differs from kernel CPU information")
	}
	model := ""
	for _, line := range strings.Split(string(info), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && (strings.TrimSpace(key) == "model name" || strings.TrimSpace(key) == "CPU implementer") {
			model = strings.TrimSpace(value)
			break
		}
	}
	if len(model) > 256 {
		return nativeHostEvidence{}, errors.New("native CPU model is oversized")
	}
	version, err := r.run(ctx, "--version")
	if err != nil || len(version) > 1024 {
		return nativeHostEvidence{}, errors.New("container runtime version is unavailable")
	}
	return nativeHostEvidence{
		Architecture: architecture, Kernel: field(kernel.Release[:]), CPUInfoSHA256: hashBytes(info), CPUModel: model,
		Runtime: runtimeKind(r.Runtime), RuntimeVersion: strings.TrimSpace(version), GoVersion: runtime.Version(),
	}, nil
}

// User-mode emulation can rewrite uname; procfs still describes the host kernel's CPU family.
func cpuInfoArchitecture(info []byte) string {
	var x86, arm bool
	for _, line := range strings.Split(string(info), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		x86 = x86 || strings.TrimSpace(key) == "vendor_id"
		arm = arm || (strings.TrimSpace(key) == "CPU architecture" && strings.TrimSpace(value) == "8")
	}
	if x86 && !arm {
		return "x86_64"
	}
	if arm && !x86 {
		return "aarch64"
	}
	return ""
}

func (inputs *materializedInputs) verifyEnvironment(name string, evidence environmentEvidence) error {
	inventory := append([]string{}, evidence.Packages...)
	sort.Strings(inventory)
	for _, environment := range inputs.Manifest.Environments {
		if environment.Name == name && len(inventory) == environment.PackageCount &&
			hashBytes([]byte(strings.Join(inventory, "\n")+"\n")) == environment.InventorySHA256 {
			return nil
		}
	}
	return errors.New("installed inventory differs from complete frozen lock")
}

func (r *Runner) checkFrozenDependencies(ctx context.Context, name, image string, dependencies []string) error {
	if len(dependencies) == 0 {
		return nil
	}
	container := containerName(name, "frozen-deps")
	args := r.baseContainerArgsForImage(container, "none", "", nil, nil, "65534:65534", image)
	args = append(args, "/usr/bin/pacman", "--config", "/dev/null", "-T", "--")
	args = append(args, dependencies...)
	output, err := r.runContainer(ctx, container, args...)
	if err != nil {
		return fmt.Errorf("frozen environment does not satisfy reviewed dependencies: %s: %w", output, err)
	}
	return nil
}

func materializeFrozenInputs(ctx context.Context, job Job, directory string, get inputObjectGetter) (*materializedInputs, error) {
	if job.InputLock == nil || get == nil || !validInputObject(*job.InputLock, 128<<10) || job.OutputContract == nil || job.DependencyPlan != nil {
		return nil, errors.New("frozen input lock requires a native output contract and authenticated object reader")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		return nil, err
	}
	var transferred int64
	seen := map[string]int64{}
	getObject := func(ref inputObject, max int64) (string, error) {
		if !validInputObject(ref, max) {
			return "", errors.New("frozen input exceeds object budget")
		}
		path := filepath.Join(directory, ref.SHA256)
		if size, exists := seen[ref.SHA256]; exists {
			if size != ref.Size {
				return "", errors.New("frozen input digest has conflicting sizes")
			}
			return path, nil
		}
		if transferred > maxFrozenTransferBytes-ref.Size {
			return "", errors.New("frozen input transfer exceeds worker limit")
		}
		if err := get(ctx, ref, path); err != nil {
			return "", err
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != ref.Size {
			return "", errors.New("frozen input is not a regular exact-size object")
		}
		digest, _, err := hashFile(path)
		if err != nil || digest != ref.SHA256 {
			return "", errors.New("frozen input checksum differs from lock")
		}
		transferred += ref.Size
		seen[ref.SHA256] = ref.Size
		return path, nil
	}
	readJSON := func(ref inputObject, max int64, target any) error {
		path, err := getObject(ref, max)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return decodeCanonicalDocument(data, target)
	}
	result := &materializedInputs{Reference: *job.InputLock, Directory: directory, Environments: map[string][]frozenPackage{}}
	if err := readJSON(*job.InputLock, 128<<10, &result.Manifest); err != nil {
		return nil, err
	}
	m := result.Manifest
	if (m.ShellAnalysis != "" && m.ShellAnalysis != "helper") || m.SchemaVersion != 1 || (m.Purpose != "bootstrap" && m.Purpose != "owned") || m.Architecture != job.Architecture ||
		m.RecipeSHA256 != job.RecipeSHA256 || m.CohortSHA256 != job.OutputContract.Cohort.ManifestSHA256 || m.SourceDateEpoch != job.SourceDateEpoch ||
		m.HelperImage != job.ImageRef || len(m.Environments) != len(job.OutputContract.RuntimeGroups)+1 ||
		m.TransferLimitBytes < 1 || m.TransferLimitBytes > maxFrozenTransferBytes {
		return nil, errors.New("frozen input manifest differs from native job or exceeds budget")
	}
	// Account for each unique retained byte before downloading large objects.
	budget := transferred
	objects := map[string]inputObject{}
	addObject := func(ref inputObject, max int64) error {
		if !validInputObject(ref, max) {
			return errors.New("invalid frozen object reference")
		}
		if previous, ok := objects[ref.SHA256]; ok {
			if previous != ref {
				return errors.New("conflicting frozen object size")
			}
			return nil
		}
		objects[ref.SHA256] = ref
		budget += ref.Size
		if budget > m.TransferLimitBytes {
			return errors.New("frozen inputs exceed reviewed transfer budget")
		}
		return nil
	}
	for _, item := range []struct {
		ref inputObject
		max int64
	}{{m.HelperArchive, 32 << 30}, {m.MakepkgConfig, 64 << 10}} {
		if err := addObject(item.ref, item.max); err != nil {
			return nil, err
		}
	}
	uniquePackages := map[string]bool{}
	totalChunks := 0
	for index, environment := range m.Environments {
		expectedName := "build"
		if index > 0 {
			expectedName = fmt.Sprintf("runtime-%d", index-1)
		}
		if environment.Name != expectedName || environment.PackageCount < 1 || environment.PackageCount > 4096 ||
			environment.TotalBytes < 1 || environment.TotalBytes > m.TransferLimitBytes || !sha256Pattern.MatchString(environment.InventorySHA256) ||
			len(environment.Chunks) < 1 || len(environment.Chunks) > 64 {
			return nil, errors.New("invalid frozen environment inventory or budget")
		}
		totalChunks += len(environment.Chunks)
		if totalChunks > 1024 {
			return nil, errors.New("frozen input page count exceeds limit")
		}
		packages, inventory := []frozenPackage{}, []string{}
		names := map[string]bool{}
		var total int64
		for _, ref := range environment.Chunks {
			if err := addObject(ref, 1<<20); err != nil {
				return nil, err
			}
			var page []frozenPackage
			if err := readJSON(ref, 1<<20, &page); err != nil {
				return nil, err
			}
			if len(page) < 1 || len(page) > 64 {
				return nil, errors.New("frozen input page must contain 1 to 64 packages")
			}
			for _, item := range page {
				fileVersion := item.Version
				if colon := strings.IndexByte(fileVersion, ':'); colon >= 0 {
					fileVersion = fileVersion[colon+1:]
				}
				extension := filepath.Ext(item.Filename)
				validFilename := (extension == ".zst" || extension == ".xz") && (item.Filename == item.Name+"-"+item.Version+"-"+item.Architecture+".pkg.tar"+extension || item.Filename == item.Name+"-"+fileVersion+"-"+item.Architecture+".pkg.tar"+extension)
				if !depNamePattern.MatchString(item.Name) || names[item.Name] || !validArchVersion(item.Version) ||
					(item.Architecture != m.Architecture && item.Architecture != "any") ||
					!validFilename || len(item.Filename) > 256 ||
					!dependencyFingerprintPattern.MatchString(item.Fingerprint) || !sha256Pattern.MatchString(item.OriginEvidence) ||
					(item.Origin != "external-bootstrap" && item.Origin != "owned-build") || (m.Purpose == "owned" && item.Origin != "owned-build") {
					return nil, errors.New("invalid, repeated or ineligible frozen package")
				}
				names[item.Name] = true
				uniquePackages[item.Package.SHA256] = true
				if len(uniquePackages) > 4096 {
					return nil, errors.New("frozen inputs exceed 4096 unique packages")
				}
				for _, entry := range []struct {
					ref inputObject
					max int64
				}{{item.Package, maxDependencyPackageBytes}, {item.Signature, 1 << 20}, {item.PublicKey, 1 << 20}} {
					if err := addObject(entry.ref, entry.max); err != nil {
						return nil, err
					}
				}
				total += item.Package.Size
				inventory = append(inventory, item.Name+" "+item.Version)
				packages = append(packages, item)
			}
		}
		sort.Strings(inventory)
		if len(packages) != environment.PackageCount || total != environment.TotalBytes || hashBytes([]byte(strings.Join(inventory, "\n")+"\n")) != environment.InventorySHA256 {
			return nil, errors.New("frozen environment count, size or inventory digest differs from lock")
		}
		result.Environments[environment.Name] = packages
	}
	for _, ref := range objects {
		if _, err := getObject(ref, maxFrozenTransferBytes); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (r *Runner) prepareFrozenEnvironment(ctx context.Context, name string, inputs *materializedInputs, environmentName string) (preparedImage, error) {
	packages, ok := inputs.Environments[environmentName]
	if !ok {
		return preparedImage{}, errors.New("missing frozen environment")
	}
	directory, err := os.MkdirTemp(r.StateDir, "frozen-root-")
	if err != nil {
		return preparedImage{}, err
	}
	defer func() { r.cleanupJobDirectory(directory, inputs.Manifest.HelperImage); _ = os.RemoveAll(directory) }()
	var manifest strings.Builder
	for _, item := range packages {
		fmt.Fprintf(&manifest, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", item.Name, item.Version, item.Architecture, item.Package.SHA256, item.Signature.SHA256, item.PublicKey.SHA256, strings.ToUpper(item.Fingerprint))
	}
	if err := os.WriteFile(filepath.Join(directory, "packages.tsv"), []byte(manifest.String()), 0o644); err != nil {
		return preparedImage{}, err
	}
	container := containerName(name+environmentName, "frozen")
	mounts := []mount{
		{Source: inputs.Directory, Target: "/inputs", ReadOnly: true},
		{Source: directory, Target: "/result"},
	}
	env := map[string]string{"OPR_ARCH": inputs.Manifest.Architecture, "OPR_MAKEPKG": inputs.Manifest.MakepkgConfig.SHA256}
	args := r.mutableContainerArgsForImage(container, "none", "", mounts, env, "", inputs.Manifest.HelperImage)
	args = insertBeforeImage(args, "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--cap-add", "SYS_CHROOT")
	args = append(args, "/bin/bash", "-ceu", frozenPreparationScript)
	log, err := r.runContainer(ctx, container, args...)
	if err != nil {
		return preparedImage{log: log}, fmt.Errorf("prepare frozen root: %w", err)
	}
	imageTag := "opr-frozen-" + strings.TrimPrefix(container, "opr-") + ":1"
	initialTag := "opr-frozen-" + strings.TrimPrefix(container, "opr-") + ":initial"
	r.removeImage(imageTag)
	r.removeImage(initialTag)
	ociArch := "amd64"
	if inputs.Manifest.Architecture == "aarch64" {
		ociArch = "arm64"
	}
	importArgs := []string{"import", "--arch", ociArch}
	if runtimeKind(r.Runtime) == "docker" {
		importArgs = []string{"import", "--platform", "linux/" + ociArch}
	}
	importArgs = append(importArgs, filepath.Join(directory, "rootfs.tar"), initialTag)
	importLog, err := r.run(ctx, importArgs...)
	log += importLog
	if err != nil {
		r.removeImage(initialTag)
		return preparedImage{log: log}, err
	}
	defer r.removeImage(initialTag)
	args = r.mutableContainerArgsForImage(container, "none", "", mounts, env, "", initialTag)
	args = withoutArgument(args, "--rm")
	args = insertBeforeImage(args, "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER", "--cap-add", "SYS_CHROOT")
	args = append(args, "/bin/bash", "-ceu", frozenFinalizationScript)
	args = append([]string{"create"}, withoutFirstArgument(args, "run")...)
	defer r.removeContainer(container)
	if output, err := r.run(ctx, args...); err != nil {
		return preparedImage{log: log + output}, err
	}
	output, err := r.startAndCollect(ctx, container)
	log += output
	if err != nil {
		return preparedImage{log: log}, fmt.Errorf("finalize frozen installation: %w", err)
	}
	inventory, err := os.ReadFile(filepath.Join(directory, "inventory"))
	if err != nil {
		return preparedImage{log: log}, err
	}
	var expected frozenEnvironment
	for _, environment := range inputs.Manifest.Environments {
		if environment.Name == environmentName {
			expected = environment
		}
	}
	if hashBytes(inventory) != expected.InventorySHA256 {
		return preparedImage{log: log}, errors.New("prepared inventory differs from complete frozen environment")
	}
	if output, err := r.run(ctx, "commit", container, imageTag); err != nil {
		r.removeImage(imageTag)
		return preparedImage{log: log + output}, err
	}
	r.removeContainer(container)
	return preparedImage{ref: imageTag, log: log, cleanup: func() { r.removeImage(imageTag) }}, nil
}

const frozenPreparationScript = `set -eu
test ! -e /frozen-root
mkdir -p /frozen-root/etc /frozen-root/var/lib/pacman /frozen-root/var/cache/pacman/pkg /tmp/empty-hooks
printf '[options]\nArchitecture = %s\nSigLevel = Never\n' "$OPR_ARCH" > /tmp/frozen-pacman.conf
# Each archive is verified against its own retained, fingerprint-pinned key.
# No shared keyring can allow another package's key to satisfy this signature.
while IFS=$'\t' read -r name version arch package signature public_key fingerprint; do
  mkdir -m 700 /tmp/frozen-key
  gpg --batch --homedir /tmp/frozen-key --import "/inputs/$public_key" >/dev/null 2>&1
  actual=$(gpg --batch --homedir /tmp/frozen-key --with-colons --list-keys | awk -F: '$1=="pub" {p++} $1=="fpr" && !f {f=$10} END {if(p!=1) exit 1; print f}')
  test "$actual" = "$fingerprint"
  gpg --batch --homedir /tmp/frozen-key --no-auto-key-retrieve --verify "/inputs/$signature" "/inputs/$package"
  rm -rf /tmp/frozen-key
  bsdtar -xOf "/inputs/$package" .PKGINFO > /tmp/frozen-pkginfo
  field() { awk -F ' = ' -v key="$1" '$1==key {n++; value=$2} END {if(n!=1) exit 1; print value}' /tmp/frozen-pkginfo; }
  test "$(field pkgname)" = "$name"
  test "$(field pkgver)" = "$version"
  test "$(field arch)" = "$arch"
  bsdtar -tf "/inputs/$package" | while IFS= read -r path; do
    case "$path" in usr/share/libalpm/hooks/*.hook) ln -sf /dev/null "/tmp/empty-hooks/${path##*/}";; esac
  done
  printf '/inputs/%s\n' "$package"
done < /result/packages.tsv > /tmp/frozen-targets
# --root starts empty. This config has no sync repositories. -U checks the
# complete transaction, including version constraints, conflicts and providers.
mapfile -t targets < /tmp/frozen-targets
pacman --root /frozen-root --config /tmp/frozen-pacman.conf --hookdir /tmp/empty-hooks --noscriptlet -U --noconfirm -- "${targets[@]}"
cp /tmp/frozen-pacman.conf /frozen-root/etc/pacman.conf
tar --numeric-owner -cpf /result/rootfs.tar -C /frozen-root .
`

// The first transaction checked dependencies and file conflicts but deferred
// hooks/scriptlets until the new root has its own OCI /proc and /dev. Reinstall
// the same bytes as a fresh transaction so post_install, not post_upgrade, runs.
const frozenFinalizationScript = `set -euo pipefail
test -d /var/lib/pacman/local
mapfile -t targets < <(awk -F '\t' '{print "/inputs/" $4}' /result/packages.tsv)
rm -rf /var/lib/pacman/local
pacman --config /etc/pacman.conf -U --overwrite '*' --noconfirm -- "${targets[@]}" 2>&1 | tee /tmp/frozen-install.log
! grep -q '^error:' /tmp/frozen-install.log
pacman --config /etc/pacman.conf -Q | LC_ALL=C sort > /result/inventory
cp "/inputs/$OPR_MAKEPKG" /etc/makepkg.conf
ln -sf /usr/share/zoneinfo/UTC /etc/localtime
rm -f /etc/machine-id
`

func decodeCanonicalDocument(data []byte, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("frozen input JSON has trailing data")
	}
	encoded, err := encodeJSON(target)
	if err != nil {
		return err
	}
	var canonical any
	if err := json.Unmarshal(encoded, &canonical); err != nil {
		return err
	}
	encoded, err = encodeJSON(canonical)
	if err != nil || string(encoded) != string(data) {
		return errors.New("frozen input JSON must use exact canonical fields")
	}
	return nil
}

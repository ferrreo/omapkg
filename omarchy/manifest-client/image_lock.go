package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type imageLockRef struct {
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	Signature       string `json:"signature"`
	SignatureSHA256 string `json:"signatureSha256,omitempty"`
	SignatureURL    string `json:"signatureUrl,omitempty"`
}

type imageLockPackage struct {
	ReleaseID       string `json:"releaseId"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Architecture    string `json:"architecture"`
	Repository      string `json:"repository"`
	Filename        string `json:"filename"`
	URL             string `json:"url"`
	SignatureURL    string `json:"signatureUrl"`
	SHA256          string `json:"sha256"`
	SignatureSHA256 string `json:"signatureSha256"`
	Install         bool   `json:"install"`
}

type imageLockRepository struct {
	Name            string `json:"name"`
	Architecture    string `json:"architecture"`
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
	Signature       string `json:"signature"`
	SignatureSHA256 string `json:"signatureSha256"`
	PackageBaseURL  string `json:"packageBaseUrl"`
}

type imageLock struct {
	SchemaVersion      int                   `json:"schemaVersion"`
	Authority          string                `json:"authority"`
	TransactionSHA256  string                `json:"transactionSha256"`
	Transaction        imageLockRef          `json:"transaction"`
	SystemManifest     imageLockRef          `json:"systemManifest"`
	OPRManifest        imageLockRef          `json:"oprManifest"`
	Repositories       []imageLockRepository `json:"repositories"`
	PackageChunks      []imageLockRef        `json:"packageChunks"`
	Packages           []imageLockPackage    `json:"packages"`
	PackageCount       int                   `json:"packageCount"`
	SourcePackageCount int                   `json:"sourcePackageCount"`
	PackageSetSHA256   string                `json:"packageSetSha256"`
	Architecture       string                `json:"architecture"`
	SystemVersion      string                `json:"systemVersion"`
	OPRGeneration      string                `json:"oprGeneration"`
	SourceDateEpoch    int64                 `json:"sourceDateEpoch"`
}

func runImageLock(args []string) int {
	fs := flag.NewFlagSet("image-lock", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	manifest := fs.String("manifest", "", "immutable resolved transaction manifest URL")
	signature := fs.String("signature", "", "detached transaction signature URL")
	key := fs.String("key", "", "trusted OpenPGP public key file")
	fingerprint := fs.String("fingerprint", "", "trusted OpenPGP fingerprint")
	architecture := fs.String("arch", "", "target architecture")
	output := fs.String("output", "", "output directory")
	allowHTTP := fs.Bool("allow-http", false, "allow HTTP for local fixtures only")
	overwrite := fs.Bool("overwrite", false, "replace output files")
	if err := fs.Parse(args); err != nil || *manifest == "" || *key == "" || *fingerprint == "" || *output == "" {
		return 2
	}
	client, err := New(Options{TrustedKey: *key, TrustedFingerprint: strings.TrimSpace(*fingerprint), AllowHTTP: *allowHTTP, Architecture: *architecture, ManifestSignatureURL: *signature})
	if err != nil {
		return fail(err)
	}
	if err := writeImageLock(context.Background(), client, *manifest, *output, *overwrite); err != nil {
		return fail(err)
	}
	return 0
}

func writeImageLock(ctx context.Context, client *Client, manifestURL, output string, overwrite bool) error {
	verified, err := client.ResolveRequested(ctx, manifestURL, "")
	if err != nil {
		return err
	}
	ref, err := client.resolveRequestedRef(ctx, manifestURL, client.rootSignatureURL)
	if err != nil {
		return err
	}
	root, err := client.fetchSignedAt(ctx, ref.ManifestURL, ref.SignatureURL, maxManifestBytes)
	if err != nil {
		return err
	}
	tx, err := parseTransaction(root)
	if err != nil {
		return err
	}
	tx.Digest = root.Document.Digest
	if err := selectArchitecture(client.architecture, &tx); err != nil {
		return err
	}
	if tx.Digest != verified.Digest {
		return errors.New("verified transaction changed while retaining image inputs")
	}
	system, err := client.fetchReference(ctx, tx.SystemRef, "system")
	if err != nil {
		return err
	}
	opr, err := client.fetchReference(ctx, tx.OPRRef, "opr")
	if err != nil {
		return err
	}
	if err := validateChild(tx, system, opr); err != nil {
		return err
	}
	if err := client.validateTransactionURL(ref.ManifestURL, tx); err != nil {
		return err
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	write := func(name string, data []byte) (string, error) {
		path := filepath.Join(output, name)
		if !overwrite {
			if _, statErr := os.Lstat(path); statErr == nil {
				return "", fmt.Errorf("refusing to replace %s", path)
			}
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return "", err
		}
		return name, nil
	}
	rootPath, err := write("transaction.json", root.Document.Canonical)
	if err != nil {
		return err
	}
	rootSig, err := write("transaction.json.sig", root.Signature)
	if err != nil {
		return err
	}
	systemPath, err := write("system.json", system.Document.Canonical)
	if err != nil {
		return err
	}
	systemSig, err := write("system.json.sig", system.Signature)
	if err != nil {
		return err
	}
	oprPath, err := write("opr.json", opr.Document.Canonical)
	if err != nil {
		return err
	}
	oprSig, err := write("opr.json.sig", opr.Signature)
	if err != nil {
		return err
	}
	lock := imageLock{SchemaVersion: 1, Authority: "omarchy-manifest-client-v1", TransactionSHA256: root.Document.Digest,
		Transaction:    imageLockRef{Path: rootPath, SHA256: root.Document.Digest, Signature: rootSig, SignatureSHA256: sha256Hex(root.Signature), SignatureURL: root.SignatureURL},
		SystemManifest: imageLockRef{Path: systemPath, SHA256: system.Document.Digest, Signature: systemSig, SignatureSHA256: sha256Hex(system.Signature), SignatureURL: system.SignatureURL},
		OPRManifest:    imageLockRef{Path: oprPath, SHA256: opr.Document.Digest, Signature: oprSig, SignatureSHA256: sha256Hex(opr.Signature), SignatureURL: opr.SignatureURL},
		Architecture:   tx.Architecture, SystemVersion: tx.Identity.Version, OPRGeneration: tx.Identity.Generation, SourceDateEpoch: tx.CreatedAt}
	for _, repository := range tx.Repositories {
		if err := validateSameOrigin(ref.ManifestURL, repository.DBURL); err != nil {
			return err
		}
		if err := validateSameOrigin(ref.ManifestURL, repository.SignatureURL); err != nil {
			return err
		}
		database, err := client.fetch(ctx, repository.DBURL, maxRepositoryDatabaseBytes)
		if err != nil {
			return err
		}
		if sha256Hex(database) != strings.ToLower(repository.SnapshotDigest) {
			return fmt.Errorf("%s repository database digest mismatch", repository.Name)
		}
		signature, err := client.fetch(ctx, repository.SignatureURL, maxSignatureBytes)
		if err != nil {
			return err
		}
		if err := verifyOpenPGP(client.key, client.fingerprint, database, signature); err != nil {
			return fmt.Errorf("verify %s repository signature: %w", repository.Name, err)
		}
		name := strings.ReplaceAll(repository.Name, "_", "-")
		dbPath, err := write("repo-"+name+".db", database)
		if err != nil {
			return err
		}
		sigPath, err := write("repo-"+name+".db.sig", signature)
		if err != nil {
			return err
		}
		lock.Repositories = append(lock.Repositories, imageLockRepository{Name: repository.Name, Architecture: repository.Architecture, Path: dbPath, SHA256: repository.SnapshotDigest, Signature: sigPath, SignatureSHA256: sha256Hex(signature), PackageBaseURL: repository.PackageBaseURL})
	}
	allPackageCount := 0
	selectedPackages := make(map[string]imageLockPackage)
	for index, chunk := range tx.PackageChunks {
		if err := validateSameOrigin(ref.ManifestURL, chunk.URL); err != nil {
			return err
		}
		data, err := client.fetch(ctx, chunk.URL, maxManifestBytes*32)
		if err != nil {
			return err
		}
		if sha256Hex(data) != strings.ToLower(chunk.Digest) {
			return fmt.Errorf("package chunk %d digest mismatch", index)
		}
		var object struct {
			SchemaVersion int              `json:"schemaVersion"`
			Index         int              `json:"index"`
			Count         int              `json:"count"`
			Packages      []map[string]any `json:"packages"`
		}
		if err := json.Unmarshal(data, &object); err != nil || object.SchemaVersion != 1 || object.Index != chunk.Index || object.Count != chunk.Count || len(object.Packages) != chunk.PackageCount {
			return fmt.Errorf("package chunk %d contract is invalid", index)
		}
		allPackageCount += len(object.Packages)
		path, err := write(fmt.Sprintf("package-chunk-%04d.json", index), data)
		if err != nil {
			return err
		}
		lock.PackageChunks = append(lock.PackageChunks, imageLockRef{Path: path, SHA256: chunk.Digest})
		for _, item := range object.Packages {
			allPackage, err := imagePackage(item)
			if err != nil {
				return fmt.Errorf("package chunk %d: %w", index, err)
			}
			if err := validateSameOrigin(ref.ManifestURL, allPackage.URL); err != nil {
				return fmt.Errorf("package chunk %d package URL: %w", index, err)
			}
			if err := validateSameOrigin(ref.ManifestURL, allPackage.SignatureURL); err != nil {
				return fmt.Errorf("package chunk %d package signature URL: %w", index, err)
			}
			pkg, selected, err := selectedImagePackage(item, tx.Architecture, tx.Repositories)
			if err != nil {
				return fmt.Errorf("package chunk %d: %w", index, err)
			}
			if !selected {
				continue
			}
			if prior, exists := selectedPackages[pkg.Filename]; exists {
				if prior != pkg {
					return fmt.Errorf("selected package filename %s has conflicting identities", pkg.Filename)
				}
				continue
			}
			selectedPackages[pkg.Filename] = pkg
		}
	}
	if allPackageCount != tx.PackageCount {
		return fmt.Errorf("source package chunk count %d does not match transaction count %d", allPackageCount, tx.PackageCount)
	}
	for _, pkg := range selectedPackages {
		lock.Packages = append(lock.Packages, pkg)
	}
	if len(lock.Packages) == 0 && allPackageCount > 0 {
		return fmt.Errorf("no package chunk entries support target architecture %s", tx.Architecture)
	}
	lock.PackageCount = len(lock.Packages)
	lock.SourcePackageCount = allPackageCount
	sort.Slice(lock.Packages, func(i, j int) bool {
		a, b := lock.Packages[i], lock.Packages[j]
		return strings.Join([]string{a.Name, a.Architecture, a.Version, a.SHA256}, "\x00") < strings.Join([]string{b.Name, b.Architecture, b.Version, b.SHA256}, "\x00")
	})
	packageBytes, err := canonicalPackageSet(lock.Packages)
	if err != nil {
		return err
	}
	lock.PackageSetSHA256 = sha256Hex(packageBytes)
	bytes, err := canonicalMarshal(lock)
	if err != nil {
		return err
	}
	_, err = write("release-lock.json", bytes)
	return err
}

func canonicalPackageSet(packages []imageLockPackage) ([]byte, error) {
	values := make([]map[string]any, 0, len(packages))
	for _, item := range packages {
		values = append(values, map[string]any{
			"architecture": item.Architecture, "filename": item.Filename, "install": item.Install,
			"name": item.Name, "releaseId": item.ReleaseID, "repository": item.Repository,
			"sha256": item.SHA256, "signatureSha256": item.SignatureSHA256, "signatureUrl": item.SignatureURL,
			"url": item.URL, "version": item.Version,
		})
	}
	return canonicalMarshal(values)
}

func imagePackage(item map[string]any) (imageLockPackage, error) {
	textValue := func(key string) (string, error) {
		value, ok := item[key].(string)
		if !ok || value == "" {
			return "", fmt.Errorf("package is missing %s", key)
		}
		return value, nil
	}
	release, err := textValue("releaseId")
	if err != nil {
		return imageLockPackage{}, err
	}
	name, err := textValue("name")
	if err != nil {
		return imageLockPackage{}, err
	}
	version, err := textValue("version")
	if err != nil {
		return imageLockPackage{}, err
	}
	architecture, err := textValue("architecture")
	if err != nil {
		return imageLockPackage{}, err
	}
	if architecture != "x86_64" && architecture != "aarch64" && architecture != "any" {
		return imageLockPackage{}, errors.New("package architecture is invalid")
	}
	urlValue, err := textValue("artifactUrl")
	if err != nil {
		return imageLockPackage{}, err
	}
	signatureURL, err := textValue("artifactSignatureUrl")
	if err != nil {
		return imageLockPackage{}, err
	}
	digestValue, err := textValue("artifactSha256")
	if err != nil {
		return imageLockPackage{}, err
	}
	signatureDigest, err := textValue("artifactSignatureSha256")
	if err != nil {
		return imageLockPackage{}, err
	}
	if !sha256Pattern.MatchString(strings.ToLower(digestValue)) || !sha256Pattern.MatchString(strings.ToLower(signatureDigest)) {
		return imageLockPackage{}, errors.New("package digest is invalid")
	}
	if err := validateURL(urlValue, false); err != nil {
		return imageLockPackage{}, fmt.Errorf("package URL: %w", err)
	}
	if err := validateURL(signatureURL, false); err != nil {
		return imageLockPackage{}, fmt.Errorf("package signature URL: %w", err)
	}
	parsed, err := url.Parse(urlValue)
	if err != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return imageLockPackage{}, errors.New("package URL is invalid")
	}
	filename := filepath.Base(parsed.Path)
	if filename == "." || filename == "/" || strings.Contains(filename, "\\") {
		return imageLockPackage{}, errors.New("package URL has no safe filename")
	}
	repository := "omapkg"
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for i, part := range parts {
		if part == "releases" && i+2 < len(parts) {
			repository = parts[i+2]
			break
		}
	}
	return imageLockPackage{ReleaseID: release, Name: name, Version: version, Architecture: architecture, Repository: repository, Filename: filename, URL: urlValue, SignatureURL: signatureURL, SHA256: digestValue, SignatureSHA256: signatureDigest, Install: true}, nil
}

func selectedImagePackage(item map[string]any, architecture string, repositories []Repository) (imageLockPackage, bool, error) {
	pkg, err := imagePackage(item)
	if err != nil {
		return imageLockPackage{}, false, err
	}
	if pkg.Architecture != architecture && pkg.Architecture != "any" {
		return imageLockPackage{}, false, nil
	}
	repository, err := packageRepository(pkg.URL, repositories)
	if err != nil {
		if pkg.Architecture == "any" && strings.Contains(err.Error(), "matches=0") {
			return imageLockPackage{}, false, nil
		}
		return imageLockPackage{}, false, err
	}
	pkg.Repository = repository.Name
	return pkg, true, nil
}

func packageRepository(packageURL string, repositories []Repository) (Repository, error) {
	parsed, err := url.Parse(packageURL)
	if err != nil {
		return Repository{}, errors.New("package URL is invalid")
	}
	found := Repository{}
	count := 0
	for _, repository := range repositories {
		base, parseErr := url.Parse(repository.PackageBaseURL)
		if parseErr != nil || parsed.Scheme != base.Scheme || parsed.Host != base.Host || parsed.User != nil || base.User != nil {
			continue
		}
		basePath := strings.TrimRight(base.Path, "/")
		if basePath == "" || !strings.HasPrefix(parsed.Path, basePath+"/") {
			continue
		}
		found = repository
		count++
	}
	if count != 1 {
		return Repository{}, fmt.Errorf("package URL does not belong to exactly one selected repository (matches=%d)", count)
	}
	return found, nil
}

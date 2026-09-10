package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxCatalogDatabase = 32 << 20

type catalogSource struct {
	ID         string `json:"id"`
	URL        string `json:"url"`
	Collection string `json:"collection"`
	Target     string `json:"target"`
	Format     string `json:"format,omitempty"`
}
type catalogSourceResult struct {
	catalogSource
	Status          string  `json:"status"`
	SHA256          *string `json:"sha256"`
	Entries         int     `json:"entries"`
	Signature       string  `json:"signature"`
	SignatureSHA256 *string `json:"signatureSha256"`
	Error           *string `json:"error"`
}
type catalogEntry struct {
	SourceID          string   `json:"sourceId"`
	Name              string   `json:"name"`
	PackageBase       string   `json:"pkgbase"`
	Version           string   `json:"version"`
	Architecture      string   `json:"architecture"`
	Target            string   `json:"target"`
	Collection        string   `json:"collection"`
	Filename          string   `json:"filename"`
	SHA256            string   `json:"sha256"`
	Size              int64    `json:"size"`
	InstalledSize     int64    `json:"installedSize"`
	Description       string   `json:"description"`
	UpstreamURL       *string  `json:"upstreamUrl"`
	Licenses          []string `json:"licenses"`
	Dependencies      []string `json:"dependencies"`
	MakeDependencies  []string `json:"makeDependencies"`
	CheckDependencies []string `json:"checkDependencies"`
	Provides          []string `json:"provides"`
	Conflicts         []string `json:"conflicts"`
	Replaces          []string `json:"replaces"`
	PackageSignature  *string  `json:"packageSignature"`
	Surface           string   `json:"surface,omitempty"`
	RecipeURL         string   `json:"recipeUrl,omitempty"`
}

func catalogSources(kind, channel string, architectures []string, origin, layout string) ([]catalogSource, error) {
	sources := []catalogSource{}
	for _, architecture := range architectures {
		if kind == "opr" {
			if origin == "" {
				return nil, errors.New("OPR capture requires a public origin")
			}
			address := strings.TrimRight(origin, "/")
			collection := "omapkg"
			if layout == "omarchy" {
				address += "/" + channel + "/" + architecture + "/omarchy.db"
				collection = "omarchy"
			} else {
				address += "/repo"
				if channel == "dev" {
					address += "/dev"
				}
				address += "/" + architecture + "/opr.db"
			}
			sources = append(sources, catalogSource{ID: "opr-" + channel + "-" + architecture, URL: address, Collection: collection, Target: architecture})
			if layout == "omapkg" {
				address = strings.TrimRight(origin, "/") + "/api/catalog?" + url.Values{"channel": {channel}, "architecture": {architecture}, "surface": {"recipe"}, "limit": {"100"}}.Encode()
				sources = append(sources, catalogSource{ID: "opr-" + channel + "-recipes-" + architecture, URL: address, Collection: collection, Target: architecture, Format: "recipe-catalog"})
			}
			continue
		}
		repositories := []string{"core", "extra"}
		if architecture == "x86_64" {
			repositories = append(repositories, "multilib")
		}
		for _, repository := range repositories {
			address := "https://geo.mirror.pkgbuild.com/" + repository + "/os/" + architecture + "/" + repository + ".db"
			if kind == "arch" && architecture == "aarch64" {
				address = "https://fl.us.mirror.archlinuxarm.org/aarch64/" + repository + "/" + repository + ".db"
			}
			if kind == "omarchy" {
				host := "mirror.omarchy.org"
				if channel != "edge" {
					host = channel + "-" + host
				}
				address = "https://" + host + "/" + repository + "/os/" + architecture + "/" + repository + ".db"
			}
			sources = append(sources, catalogSource{ID: kind + "-" + channel + "-" + repository + "-" + architecture, URL: address, Collection: repository, Target: architecture})
		}
		if kind == "omarchy" {
			sources = append(sources, catalogSource{ID: "omarchy-" + channel + "-packages-" + architecture,
				URL: "https://pkgs.omarchy.org/" + channel + "/" + architecture + "/omarchy.db", Collection: "omarchy", Target: architecture})
		}
	}
	return sources, nil
}

var sensitiveCatalogParameter = regexp.MustCompile(`(?i)token|secret|password|authorization|credential|signature`)

func catalogURL(address string) error {
	if err := validateSourceURL(address); err != nil {
		return err
	}
	parsed, _ := url.Parse(address)
	if parsed.Port() != "" || strings.HasSuffix(parsed.Hostname(), ".") {
		return errors.New("catalog URL cannot contain a port or trailing hostname dot")
	}
	for key := range parsed.Query() {
		if sensitiveCatalogParameter.MatchString(key) {
			return errors.New("catalog URL cannot contain credentials or signed query parameters")
		}
	}
	return nil
}

type catalogHTTPError int

func (status catalogHTTPError) Error() string {
	return fmt.Sprintf("repository HTTP status %d", status)
}

func downloadCatalog(ctx context.Context, client *http.Client, address string, limit int64) ([]byte, error) {
	if err := catalogURL(address); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "omapkg-catalog-capture/2")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, catalogHTTPError(response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("repository object exceeds capture limit")
	}
	return data, nil
}

func parseCatalogTar(reader io.Reader, source catalogSource) ([]catalogEntry, error) {
	archive := tar.NewReader(reader)
	packages, members := map[string]map[string][]string{}, map[string]bool{}
	expanded := int64(0)
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header.Typeflag == tar.TypeDir {
			parts := strings.Split(strings.TrimSuffix(header.Name, "/"), "/")
			if len(parts) != 1 || parts[0] == "" || parts[0] == "." || parts[0] == ".." {
				return nil, errors.New("repository archive contains an unsafe directory entry")
			}
			continue
		}
		parts := strings.Split(header.Name, "/")
		if header.Typeflag != tar.TypeReg || len(parts) != 2 || parts[0] == "" || parts[0] == "." || parts[0] == ".." ||
			(parts[1] != "desc" && parts[1] != "depends") || members[header.Name] {
			return nil, errors.New("repository archive contains an unexpected or repeated entry")
		}
		if header.Size < 0 || header.Size > 512*1024 {
			return nil, errors.New("repository metadata entry exceeds 512 KiB")
		}
		expanded += header.Size
		if expanded > 512<<20 || len(packages) >= 100_000 && packages[parts[0]] == nil {
			return nil, errors.New("expanded repository exceeds capture budget")
		}
		fields, err := scanPacmanFields(archive, 512*1024)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", header.Name, err)
		}
		if packages[parts[0]] == nil {
			packages[parts[0]] = map[string][]string{}
		}
		for key, values := range fields {
			if previous, ok := packages[parts[0]][key]; ok && strings.Join(previous, "\x00") != strings.Join(values, "\x00") {
				return nil, errors.New("conflicting repository package metadata")
			}
			packages[parts[0]][key] = values
		}
		members[header.Name] = true
	}
	entries, names := []catalogEntry{}, map[string]bool{}
	for _, fields := range packages {
		one := func(key string, fallback ...string) (string, error) {
			if len(fields[key]) == 0 && len(fallback) == 1 {
				return fallback[0], nil
			}
			if len(fields[key]) != 1 {
				return "", fmt.Errorf("package metadata needs one %s", key)
			}
			return fields[key][0], nil
		}
		values := map[string]string{}
		for _, field := range []string{"NAME", "VERSION", "ARCH", "SHA256SUM", "FILENAME", "CSIZE"} {
			value, err := one(field)
			if err != nil {
				return nil, err
			}
			values[field] = value
		}
		for field, fallback := range map[string]string{"BASE": values["NAME"], "ISIZE": "0", "DESC": "", "URL": "", "PGPSIG": ""} {
			value, err := one(field, fallback)
			if err != nil {
				return nil, err
			}
			values[field] = value
		}
		name := values["NAME"]
		if !depNamePattern.MatchString(name) || !depNamePattern.MatchString(values["BASE"]) || names[name] || !validArchVersion(values["VERSION"]) ||
			(values["ARCH"] != source.Target && values["ARCH"] != "any") || !sha256Pattern.MatchString(values["SHA256SUM"]) {
			return nil, errors.New("invalid catalog package identity, architecture, duplicate or digest")
		}
		names[name] = true
		size, err := strconv.ParseInt(values["CSIZE"], 10, 64)
		if err != nil || size < 1 || size > 1<<53-1 {
			return nil, errors.New("invalid catalog archive size")
		}
		installed, err := strconv.ParseInt(values["ISIZE"], 10, 64)
		if err != nil || installed < 0 || installed > 1<<53-1 {
			return nil, errors.New("invalid catalog installed size")
		}
		if values["PGPSIG"] != "" {
			if _, err := base64.StdEncoding.Strict().DecodeString(values["PGPSIG"]); err != nil {
				return nil, errors.New("invalid catalog signature encoding")
			}
		}
		list := func(field string) []string { return append([]string{}, fields[field]...) }
		entries = append(entries, catalogEntry{SourceID: source.ID, Name: name, PackageBase: values["BASE"], Version: values["VERSION"], Architecture: values["ARCH"], Target: source.Target,
			Collection: source.Collection, Filename: values["FILENAME"], SHA256: values["SHA256SUM"], Size: size, InstalledSize: installed, Description: values["DESC"],
			UpstreamURL: optionalString(values["URL"]), Licenses: list("LICENSE"), Dependencies: list("DEPENDS"), MakeDependencies: list("MAKEDEPENDS"), CheckDependencies: list("CHECKDEPENDS"),
			Provides: list("PROVIDES"), Conflicts: list("CONFLICTS"), Replaces: list("REPLACES"), PackageSignature: optionalString(values["PGPSIG"])})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func readCatalogDatabase(ctx context.Context, filename string, source catalogSource) ([]catalogEntry, error) {
	decodeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(decodeCtx, "bsdtar", "-cf", "-", "--format=ustar", "@"+filename)
	var diagnostic boundedBuffer
	diagnostic.limit = 4096
	command.Stderr = &diagnostic
	pipe, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	entries, scanErr := parseCatalogTar(pipe, source)
	if scanErr != nil {
		_ = command.Process.Kill()
	} else {
		_, scanErr = io.Copy(io.Discard, pipe)
	}
	waitErr := command.Wait()
	if scanErr != nil {
		return nil, scanErr
	}
	if decodeCtx.Err() != nil {
		return nil, fmt.Errorf("repository archive decode timed out: %w", decodeCtx.Err())
	}
	if waitErr != nil {
		return nil, fmt.Errorf("repository archive could not be decoded: %w", waitErr)
	}
	return entries, nil
}

// Catalog hashes share the application's canonical JSON contract. Object keys in
// this wire format are ASCII; JSON string values preserve Unicode separators.
func catalogJSON(value any) ([]byte, error) {
	data, err := encodeJSON(value)
	if err != nil {
		return nil, err
	}
	var object any
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	data, err = encodeJSON(object)
	if err != nil {
		return nil, err
	}
	var result bytes.Buffer
	for i := 0; i < len(data); i++ {
		if data[i] == '\\' && i+1 < len(data) {
			if i+6 <= len(data) && (string(data[i:i+6]) == `\u2028` || string(data[i:i+6]) == `\u2029`) {
				if data[i+5] == '8' {
					result.WriteRune('\u2028')
				} else {
					result.WriteRune('\u2029')
				}
				i += 5
				continue
			}
			result.Write(data[i : i+2])
			i++
			continue
		}
		result.WriteByte(data[i])
	}
	return result.Bytes(), nil
}

func captureCatalogCommand(args []string) error {
	flags := flag.NewFlagSet("capture-catalog", flag.ContinueOnError)
	kind, channel, target := flags.String("source", "", "arch, omarchy or opr"), flags.String("channel", "stable", "repository channel"), flags.String("arch", "all", "all, x86_64 or aarch64")
	output, origin, layout := flags.String("output", "", "capture directory"), flags.String("opr-origin", "", "public OPR origin"), flags.String("opr-layout", "omapkg", "omapkg or omarchy")
	only, keyring, describe := flags.String("only-source", "", "capture one source identity"), flags.String("keyring", "", "gpgv verification keyring"), flags.Bool("describe", false, "print source plan")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*kind != "arch" && *kind != "omarchy" && *kind != "opr") || (*output == "" && !*describe) || (*layout != "omapkg" && *layout != "omarchy") {
		return errors.New("capture requires a supported --source and --output")
	}
	if *kind == "arch" {
		*channel = "upstream"
	}
	if *kind == "omarchy" && *channel != "stable" && *channel != "rc" && *channel != "edge" ||
		*kind == "opr" && *layout == "omapkg" && *channel != "stable" && *channel != "dev" || !regexp.MustCompile(`^(upstream|stable|rc|edge|dev)$`).MatchString(*channel) {
		return errors.New("unsupported capture channel")
	}
	architectures := []string{*target}
	if *target == "all" {
		architectures = []string{"x86_64", "aarch64"}
	} else if !archPattern.MatchString(*target) {
		return errors.New("unsupported capture architecture")
	}
	sources, err := catalogSources(*kind, *channel, architectures, *origin, *layout)
	if err != nil {
		return err
	}
	if *describe {
		data, err := catalogJSON(sources)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	if *only != "" {
		filtered := []catalogSource{}
		for _, source := range sources {
			if source.ID == *only {
				filtered = append(filtered, source)
			}
		}
		if len(filtered) != 1 {
			return errors.New("unknown catalog source identity")
		}
		sources = filtered
	}
	if err := os.MkdirAll(*output, 0o700); err != nil {
		return err
	}
	client := safeSourceHTTPClient()
	client.Timeout = time.Minute
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("catalog redirect limit exceeded")
		}
		return catalogURL(request.URL.String())
	}
	ctx := context.Background()
	results, entries := []catalogSourceResult{}, []catalogEntry{}
	for _, source := range sources {
		result, captured := captureCatalogSource(ctx, client, source, *output, *keyring)
		results, entries = append(results, result), append(entries, captured...)
		data, _ := catalogJSON(map[string]any{"source": source.ID, "status": result.Status, "entries": result.Entries})
		fmt.Println(string(data))
	}
	return writeCatalogCapture(*output, *kind, *channel, results, entries)
}

func captureCatalogSource(ctx context.Context, client *http.Client, source catalogSource, output, keyring string) (catalogSourceResult, []catalogEntry) {
	result := catalogSourceResult{catalogSource: source, Status: "unavailable", Signature: "unverified"}
	var data []byte
	var entries []catalogEntry
	var err error
	if source.Format == "recipe-catalog" {
		data, entries, err = captureRecipeCatalog(ctx, client, source, output)
	} else {
		data, err = downloadCatalog(ctx, client, source.URL, maxCatalogDatabase)
	}
	filename := filepath.Join(output, source.ID+".db")
	if err == nil {
		err = os.WriteFile(filename, data, 0o600)
		digest := hashBytes(data)
		result.SHA256 = &digest
	}
	if err == nil && source.Format != "recipe-catalog" {
		entries, err = readCatalogDatabase(ctx, filename, source)
	}
	if err != nil {
		message := compactErrorText(err.Error())
		if len(message) > 2000 {
			message = message[:2000]
		}
		result.Error = &message
		return result, nil
	}
	result.Status, result.Entries = "captured", len(entries)
	if source.Format == "recipe-catalog" {
		result.Signature = "missing"
		return result, entries
	}
	signature, err := downloadCatalog(ctx, client, source.URL+".sig", 1<<20)
	if err != nil {
		var status catalogHTTPError
		if errors.As(err, &status) && status == http.StatusNotFound {
			result.Signature = "missing"
		}
		return result, entries
	}
	signaturePath := filename + ".sig"
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		return result, entries
	}
	digest := hashBytes(signature)
	result.SignatureSHA256 = &digest
	if keyring != "" {
		verification, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := exec.CommandContext(verification, "gpgv", "--keyring", keyring, signaturePath, filename).Run(); err == nil {
			result.Signature = "verified"
		} else {
			result.Signature = "failed"
		}
	}
	return result, entries
}

func writeCatalogCapture(output, kind, channel string, sources []catalogSourceResult, entries []catalogEntry) error {
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].SourceID != entries[j].SourceID {
			return entries[i].SourceID < entries[j].SourceID
		}
		return entries[i].Name < entries[j].Name
	})
	index := make([][]string, 0, len(entries))
	for _, entry := range entries {
		data, err := catalogJSON(entry)
		if err != nil {
			return err
		}
		index = append(index, []string{entry.SourceID, entry.Name, hashBytes(data)})
	}
	data, err := catalogJSON(index)
	if err != nil {
		return err
	}
	manifest := map[string]any{"schemaVersion": 1, "kind": kind, "channel": channel, "sources": sources, "entriesSha256": hashBytes(data)}
	documents := map[string]any{"manifest.json": manifest, "index.json": index, "capture.json": map[string]any{"manifest": manifest, "entries": entries}}
	for offset := 0; offset < len(entries); offset += 100 {
		documents[fmt.Sprintf("entries-%05d.json", offset/100)] = entries[offset:min(offset+100, len(entries))]
	}
	for name, document := range documents {
		data, err := catalogJSON(document)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(output, name), append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	unavailable := 0
	for _, source := range sources {
		if source.Status != "captured" {
			unavailable++
		}
	}
	data, _ = catalogJSON(map[string]any{"capture": filepath.Join(output, "capture.json"), "packages": len(entries), "unavailableSources": unavailable})
	fmt.Println(string(data))
	return nil
}

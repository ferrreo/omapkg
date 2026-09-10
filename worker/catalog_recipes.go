package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

type recipeCatalogItem struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Channel      string `json:"channel"`
	Surface      string `json:"surface"`
	RecipeURL    string `json:"recipeUrl"`
	Description  string `json:"description"`
	License      string `json:"license"`
	Source       struct {
		UpstreamURL *string `json:"upstreamUrl"`
	} `json:"source"`
}

func captureRecipeCatalog(ctx context.Context, client *http.Client, source catalogSource, output string) ([]byte, []catalogEntry, error) {
	origin, err := url.Parse(source.URL)
	if err != nil {
		return nil, nil, err
	}
	channel := origin.Query().Get("channel")
	if channel == "" {
		return nil, nil, errors.New("recipe catalog source has no channel")
	}
	address := source.URL
	pages, entries := []json.RawMessage{}, []catalogEntry{}
	cursors, names := map[string]bool{}, map[string]bool{}
	total := 0
	for address != "" {
		data, err := downloadCatalog(ctx, client, address, maxCatalogDatabase)
		if err != nil {
			return nil, nil, err
		}
		total += len(data)
		if total > maxCatalogDatabase || len(pages) >= 1000 {
			return nil, nil, errors.New("recipe catalog exceeds capture budget")
		}
		if !utf8.Valid(data) {
			return nil, nil, errors.New("recipe catalog page is not valid UTF-8")
		}
		var page struct {
			Items      []recipeCatalogItem `json:"items"`
			NextCursor *string             `json:"nextCursor"`
		}
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, nil, err
		}
		if page.Items == nil || len(page.Items) > 100 {
			return nil, nil, errors.New("invalid OPR recipe catalog page")
		}
		pages = append(pages, data)
		for _, item := range page.Items {
			if item.Surface != "recipe" || item.Channel != channel || item.Architecture != source.Target || !depNamePattern.MatchString(item.Name) || !validArchVersion(item.Version) || names[item.Name] || item.ID == "" {
				return nil, nil, errors.New("OPR recipe identity or target mismatch")
			}
			ref, err := url.Parse(item.RecipeURL)
			if err != nil || ref.Scheme != origin.Scheme || ref.Host != origin.Host || !strings.HasSuffix(ref.Path, "/PKGBUILD") {
				return nil, nil, errors.New("OPR recipe is outside its captured origin")
			}
			recipe, err := downloadCatalog(ctx, client, item.RecipeURL, 2<<20)
			if err != nil {
				return nil, nil, err
			}
			digest := hashBytes(recipe)
			if err := os.WriteFile(filepath.Join(output, "recipe-"+digest+".PKGBUILD"), recipe, 0o600); err != nil {
				return nil, nil, err
			}
			detailsURL := origin.Scheme + "://" + origin.Host + "/api/catalog/" + url.PathEscape(item.Name) + "?" + url.Values{"channel": {item.Channel}}.Encode()
			details, err := downloadCatalog(ctx, client, detailsURL, maxCatalogDatabase)
			if err != nil {
				return nil, nil, err
			}
			if !utf8.Valid(details) {
				return nil, nil, errors.New("recipe catalog details are not valid UTF-8")
			}
			var versions struct {
				Versions []struct {
					ID           string   `json:"id"`
					Dependencies []string `json:"dependencies"`
				} `json:"versions"`
			}
			if err := json.Unmarshal(details, &versions); err != nil {
				return nil, nil, err
			}
			found, dependencies := false, []string{}
			for _, version := range versions.Versions {
				if version.ID == item.ID {
					if found {
						return nil, nil, errors.New("recipe release identity is duplicated")
					}
					found = true
					dependencies = append(dependencies, version.Dependencies...)
				}
			}
			if !found {
				return nil, nil, errors.New("recipe changed while its catalog was captured")
			}
			license := item.License
			if license == "" {
				license = "unknown"
			}
			entries = append(entries, catalogEntry{SourceID: source.ID, Name: item.Name, PackageBase: item.Name, Version: item.Version, Architecture: source.Target, Target: source.Target,
				Collection: source.Collection, Filename: "PKGBUILD", SHA256: digest, Size: int64(len(recipe)), Description: item.Description, UpstreamURL: item.Source.UpstreamURL,
				Licenses: []string{license}, Dependencies: dependencies, MakeDependencies: []string{}, CheckDependencies: []string{}, Provides: []string{}, Conflicts: []string{}, Replaces: []string{}, Surface: "recipe", RecipeURL: item.RecipeURL})
			names[item.Name] = true
		}
		if page.NextCursor == nil || *page.NextCursor == "" {
			break
		}
		cursor := *page.NextCursor
		if len(cursor) > 2048 || cursors[cursor] {
			return nil, nil, errors.New("invalid or cyclic recipe catalog pagination")
		}
		cursors[cursor] = true
		address = source.URL + "&" + url.Values{"cursor": {cursor}}.Encode()
	}
	data, err := catalogJSON(map[string]any{"pages": pages})
	if len(data) > maxCatalogDatabase {
		return nil, nil, errors.New("recipe catalog exceeds capture budget")
	}
	return data, entries, err
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

const maxABIDocument = 512 * 1024

func readABIObject(directory string, ref inputObject) ([]byte, error) {
	if !validInputObject(ref, maxABIDocument) {
		return nil, errors.New("invalid ABI evidence reference")
	}
	filename := filepath.Join(directory, ref.SHA256+".json")
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() || info.Size() != ref.Size {
		return nil, errors.New("ABI evidence file is missing or changed")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, ref.Size+1))
	if err != nil || int64(len(data)) != ref.Size || hashBytes(data) != ref.SHA256 {
		return nil, errors.New("ABI evidence checksum changed")
	}
	return data, nil
}

func (c *Client) uploadABI(ctx context.Context, job Job, result BuildResult) error {
	for _, output := range result.Outputs {
		var ref *inputObject
		for _, test := range result.RuntimeTests {
			for _, analysis := range test.Analyses {
				if analysis.Name != output.PackageMetadata.Name {
					continue
				}
				if analysis.RuntimeAnalysis == nil || analysis.RuntimeAnalysis.ABIInventory == nil {
					return errors.New("ABI output inventory is missing")
				}
				current := analysis.RuntimeAnalysis.ABIInventory
				if ref != nil && *ref != *current {
					return errors.New("ABI inventory differs between installation groups")
				}
				ref = current
			}
		}
		if ref == nil {
			return errors.New("ABI output inventory is missing")
		}
		directory := output.Path + ".abi"
		root, err := readABIObject(directory, *ref)
		if err != nil {
			return err
		}
		var manifest struct {
			SchemaVersion  int           `json:"schemaVersion"`
			Kind           string        `json:"kind"`
			ArtifactSHA256 string        `json:"artifactSha256"`
			Chunks         []inputObject `json:"chunks"`
		}
		if json.Unmarshal(root, &manifest) != nil || manifest.SchemaVersion != 1 || manifest.Kind != "abi-inventory" ||
			manifest.ArtifactSHA256 != output.ArtifactSHA256 || len(manifest.Chunks) == 0 || len(manifest.Chunks) > 2048 {
			return errors.New("invalid ABI inventory manifest")
		}
		for _, object := range append(manifest.Chunks, *ref) {
			data, err := readABIObject(directory, object)
			if err != nil {
				return err
			}
			resp, err := c.signedRequest(ctx, http.MethodPut, "/api/worker/jobs/"+job.ID+"/evidence/"+object.SHA256+"?leaseToken="+url.QueryEscape(job.LeaseToken), data)
			if err != nil {
				return err
			}
			var saved inputObject
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				err = readHTTPError(resp)
			} else {
				err = decodeJSON(resp.Body, &saved)
			}
			resp.Body.Close()
			if err != nil {
				return err
			}
			if saved != object {
				return errors.New("ABI upload response differs from retained bytes")
			}
		}
	}
	return nil
}

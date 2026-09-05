package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	Origin     *url.URL
	WorkerID   string
	PrivateKey ed25519.PrivateKey
	Metadata   WorkerMetadata
	HTTP       *http.Client
}

const maxUploadPartSize int64 = 8 << 20

const maxHTTPErrorBodyBytes int64 = 64 << 10

type uploadStartRequest struct {
	LeaseToken string `json:"leaseToken"`
	Filename   string `json:"filename"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
}

type uploadStartResponse struct {
	UploadID  string            `json:"uploadId"`
	PartSize  int64             `json:"partSize"`
	MaxSize   int64             `json:"maxSize"`
	Filename  string            `json:"filename"`
	Size      int64             `json:"size"`
	SHA256    string            `json:"sha256"`
	Parts     []UploadPart      `json:"parts"`
	Completed *ArtifactResponse `json:"completed,omitempty"`
}

type uploadPartResponse struct {
	PartNumber int    `json:"partNumber"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	ETag       string `json:"etag"`
}

func newClient(cfg Config) (*Client, error) {
	origin, err := url.Parse(cfg.Origin)
	if err != nil {
		return nil, fmt.Errorf("parse origin: %w", err)
	}
	key, err := decodePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	if !idPattern.MatchString(cfg.WorkerID) {
		return nil, errors.New("invalid worker ID")
	}
	metadata, err := daemonMetadata(cfg.Runtime)
	if err != nil {
		return nil, err
	}
	return &Client{
		Origin:     origin,
		WorkerID:   cfg.WorkerID,
		PrivateKey: key,
		Metadata:   metadata,
		HTTP:       &http.Client{Timeout: 10 * time.Minute},
	}, nil
}

func (c *Client) endpoint(requestPath string) (*url.URL, error) {
	if requestPath == "" || requestPath[0] != '/' || strings.ContainsAny(requestPath, "\r\n") {
		return nil, errors.New("request path must be an absolute path")
	}
	base := *c.Origin
	base.Path = path.Join(strings.TrimSuffix(c.Origin.Path, "/"), requestPath)
	if strings.HasSuffix(requestPath, "/") && !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}
	base.RawQuery = ""
	if q := strings.IndexByte(requestPath, '?'); q >= 0 {
		base.Path = path.Join(strings.TrimSuffix(c.Origin.Path, "/"), requestPath[:q])
		base.RawQuery = requestPath[q+1:]
	}
	base.Fragment = ""
	return &base, nil
}

func (c *Client) signedRequest(ctx context.Context, method, requestPath string, body []byte) (*http.Response, error) {
	u, err := c.endpoint(requestPath)
	if err != nil {
		return nil, err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	bodyHash := hashBytes(body)
	signature := ed25519.Sign(c.PrivateKey, makeSignaturePayload(method, canonicalRequestPath(u), timestamp, nonce, bodyHash))
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	setSignedHeaders(req, c.WorkerID, timestamp, nonce, signature, bodyHash)
	return c.signedHTTP(req)
}

func (c *Client) signedHTTP(req *http.Request) (*http.Response, error) {
	client := *c.HTTP
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client.Do(req)
}

func setSignedHeaders(req *http.Request, workerID, timestamp, nonce string, signature []byte, bodyHash string) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-OPR-Worker", workerID)
	req.Header.Set("X-OPR-Timestamp", timestamp)
	req.Header.Set("X-OPR-Nonce", nonce)
	req.Header.Set("X-OPR-Signature", base64.StdEncoding.EncodeToString(signature))
	req.Header.Set("X-OPR-Body-SHA256", bodyHash)
}

func (c *Client) doJSON(ctx context.Context, method, requestPath string, request any, response any) error {
	body, err := encodeJSON(request)
	if err != nil {
		return err
	}
	resp, err := c.signedRequest(ctx, method, requestPath, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readHTTPError(resp)
	}
	if response == nil {
		return nil
	}
	if err := decodeJSON(resp.Body, response); err != nil {
		return fmt.Errorf("decode %s response: %w", requestPath, err)
	}
	return nil
}

func readHTTPError(resp *http.Response) error {
	var body []byte
	if resp.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(resp.Body, maxHTTPErrorBodyBytes+1))
	}
	message := httpErrorMessage(body, resp.Header.Get("Content-Type"))
	if message == "" {
		message = resp.Status
	}
	return fmt.Errorf("worker API %s: %s", resp.Status, compactErrorText(message))
}

func httpErrorMessage(body []byte, contentType string) string {
	if message := jsonErrorMessage(body); message != "" {
		return message
	}
	text := string(body)
	lower := strings.ToLower(text)
	if strings.Contains(strings.ToLower(contentType), "html") || strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
		return htmlErrorTitle(text)
	}
	return text
}

func jsonErrorMessage(body []byte) string {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		return ""
	}
	for _, field := range []string{"error", "message", "detail"} {
		if message := jsonRawErrorMessage(object[field]); message != "" {
			return message
		}
	}
	return ""
}

func jsonRawErrorMessage(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return text
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return ""
	}
	for _, field := range []string{"message", "error", "detail"} {
		if message := jsonRawErrorMessage(object[field]); message != "" {
			return message
		}
	}
	return ""
}

func htmlErrorTitle(text string) string {
	lower := strings.ToLower(text)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	openEnd := strings.IndexByte(lower[start:], '>')
	if openEnd < 0 {
		return ""
	}
	contentStart := start + openEnd + 1
	closeRelative := strings.Index(lower[contentStart:], "</title>")
	if closeRelative < 0 {
		return ""
	}
	return html.UnescapeString(text[contentStart : contentStart+closeRelative])
}

func (c *Client) enroll(ctx context.Context, request Enrollment) (EnrollmentResponse, error) {
	body, err := encodeJSON(request)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	u, err := c.endpoint("/api/workers/enroll")
	if err != nil {
		return EnrollmentResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return EnrollmentResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.signedHTTP(req)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return EnrollmentResponse{}, readHTTPError(resp)
	}
	var result EnrollmentResponse
	if err := decodeJSON(resp.Body, &result); err != nil {
		return EnrollmentResponse{}, err
	}
	if !idPattern.MatchString(result.ID) {
		return EnrollmentResponse{}, errors.New("enrollment response contains invalid worker ID")
	}
	return result, nil
}

func (c *Client) claim(ctx context.Context) (*Job, error) {
	var result ClaimResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/worker/claim", c.Metadata, &result); err != nil {
		return nil, err
	}
	return result.Job, nil
}

func (c *Client) registryCredentials(ctx context.Context, jobID, leaseToken string) (RegistryCredentials, error) {
	if !idPattern.MatchString(jobID) {
		return RegistryCredentials{}, errors.New("invalid job ID")
	}
	var result RegistryCredentials
	if err := c.doJSON(ctx, http.MethodPost, "/api/worker/jobs/"+url.PathEscape(jobID)+"/registry-credentials", HeartbeatRequest{LeaseToken: leaseToken}, &result); err != nil {
		return RegistryCredentials{}, err
	}
	if result.Registry != "registry.cloudflare.com" || len(result.Username) > 256 || len(result.Password) > 4096 || len(result.ExpiresAt) > 128 || result.Username == "" || result.Password == "" || strings.ContainsAny(result.Registry+result.Username+result.Password, "\x00\r\n") {
		return RegistryCredentials{}, errors.New("registry credential response is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil || !expiresAt.After(time.Now()) {
		return RegistryCredentials{}, errors.New("registry credential response is expired")
	}
	return result, nil
}

func (c *Client) heartbeat(ctx context.Context, jobID, leaseToken string) (HeartbeatResponse, error) {
	if !idPattern.MatchString(jobID) {
		return HeartbeatResponse{}, errors.New("invalid job ID")
	}
	var result HeartbeatResponse
	err := c.doJSON(ctx, http.MethodPost, "/api/worker/jobs/"+url.PathEscape(jobID)+"/heartbeat", HeartbeatRequest{LeaseToken: leaseToken, WorkerMetadata: c.Metadata}, &result)
	return result, err
}

func (c *Client) appendLog(ctx context.Context, jobID string, request LogRequest) error {
	if !idPattern.MatchString(jobID) || request.Sequence < 0 || len(request.Text) > maxLogChunk {
		return errors.New("invalid log request")
	}
	return c.doJSON(ctx, http.MethodPost, "/api/worker/jobs/"+url.PathEscape(jobID)+"/logs", request, nil)
}

func (c *Client) uploadArtifact(ctx context.Context, jobID, leaseToken, filename string, file *os.File, size int64, bodyHash string) (ArtifactResponse, error) {
	if !idPattern.MatchString(jobID) {
		return ArtifactResponse{}, errors.New("invalid job ID")
	}
	if err := validateArtifactFilename(filename); err != nil {
		return ArtifactResponse{}, err
	}
	if file == nil || size <= 0 || !sha256Pattern.MatchString(bodyHash) {
		return ArtifactResponse{}, errors.New("invalid artifact size or checksum")
	}
	var start uploadStartResponse
	startPath := "/api/worker/jobs/" + url.PathEscape(jobID) + "/uploads"
	if err := c.doJSON(ctx, http.MethodPost, startPath, uploadStartRequest{LeaseToken: leaseToken, Filename: filename, Size: size, SHA256: bodyHash}, &start); err != nil {
		return ArtifactResponse{}, err
	}
	if start.Completed != nil {
		if start.Completed.SHA256 != bodyHash || start.Completed.Size != size || start.Completed.Filename != filename || start.Completed.Key == "" {
			return ArtifactResponse{}, errors.New("completed artifact does not match source bytes")
		}
		return *start.Completed, nil
	}
	if !idPattern.MatchString(start.UploadID) || start.PartSize <= 0 || start.PartSize > maxUploadPartSize || start.Filename != filename || start.Size != size || start.SHA256 != bodyHash {
		return ArtifactResponse{}, errors.New("invalid upload session")
	}
	if start.MaxSize > 0 && size > start.MaxSize {
		_ = c.abortUpload(ctx, jobID, start.UploadID, leaseToken)
		return ArtifactResponse{}, errors.New("artifact exceeds upload session size limit")
	}
	totalParts := int((size + start.PartSize - 1) / start.PartSize)
	existingParts := make(map[int]UploadPart, len(start.Parts))
	for _, part := range start.Parts {
		if part.PartNumber < 1 || part.PartNumber > totalParts || part.Size <= 0 || !sha256Pattern.MatchString(part.SHA256) || part.ETag == "" {
			_ = c.abortUpload(ctx, jobID, start.UploadID, leaseToken)
			return ArtifactResponse{}, errors.New("upload session contains an invalid part")
		}
		if _, exists := existingParts[part.PartNumber]; exists {
			_ = c.abortUpload(ctx, jobID, start.UploadID, leaseToken)
			return ArtifactResponse{}, errors.New("upload session contains duplicate parts")
		}
		existingParts[part.PartNumber] = part
	}
	for index := 0; index < totalParts; index++ {
		partNumber := index + 1
		offset := int64(index) * start.PartSize
		partSize := start.PartSize
		if remaining := size - offset; remaining < partSize {
			partSize = remaining
		}
		partHash, err := hashFileRange(file, offset, partSize)
		if err != nil {
			_ = c.abortUpload(ctx, jobID, start.UploadID, leaseToken)
			return ArtifactResponse{}, err
		}
		if previous, exists := existingParts[partNumber]; exists {
			if previous.SHA256 != partHash || previous.Size != partSize {
				_ = c.abortUpload(ctx, jobID, start.UploadID, leaseToken)
				return ArtifactResponse{}, errors.New("existing upload part does not match source bytes")
			}
			continue
		}
		var partResult uploadPartResponse
		partPath := startPath + "/" + url.PathEscape(start.UploadID) + "/" + strconv.Itoa(partNumber) + "?leaseToken=" + url.QueryEscape(leaseToken)
		if err := c.uploadPart(ctx, partPath, file, offset, partSize, partHash, &partResult); err != nil {
			_ = c.abortUpload(ctx, jobID, start.UploadID, leaseToken)
			return ArtifactResponse{}, err
		}
		if partResult.PartNumber != partNumber || partResult.SHA256 != partHash || partResult.Size != partSize || partResult.ETag == "" {
			_ = c.abortUpload(ctx, jobID, start.UploadID, leaseToken)
			return ArtifactResponse{}, errors.New("upload part response does not match source bytes")
		}
	}
	var result ArtifactResponse
	completePath := startPath + "/" + url.PathEscape(start.UploadID) + "/complete"
	if err := c.doJSON(ctx, http.MethodPost, completePath, HeartbeatRequest{LeaseToken: leaseToken}, &result); err != nil {
		_ = c.abortUpload(ctx, jobID, start.UploadID, leaseToken)
		return ArtifactResponse{}, err
	}
	if result.SHA256 != bodyHash || result.Size != size || result.Filename != filename || result.Key == "" {
		return ArtifactResponse{}, errors.New("completed artifact does not match source bytes")
	}
	return result, nil
}

func hashFileRange(file *os.File, offset, size int64) (string, error) {
	if file == nil || offset < 0 || size <= 0 {
		return "", errors.New("invalid upload part range")
	}
	section := io.NewSectionReader(file, offset, size)
	hash := sha256.New()
	if n, err := io.CopyN(hash, section, size); err != nil || n != size {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func (c *Client) uploadPart(ctx context.Context, requestPath string, file *os.File, offset, size int64, bodyHash string, response *uploadPartResponse) error {
	u, err := c.endpoint(requestPath)
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	signature := ed25519.Sign(c.PrivateKey, makeSignaturePayload(http.MethodPut, canonicalRequestPath(u), timestamp, nonce, bodyHash))
	body := io.NewSectionReader(file, offset, size)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	setSignedHeaders(req, c.WorkerID, timestamp, nonce, signature, bodyHash)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.signedHTTP(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readHTTPError(resp)
	}
	return decodeJSON(resp.Body, response)
}

func (c *Client) abortUpload(ctx context.Context, jobID, uploadID, leaseToken string) error {
	if !idPattern.MatchString(jobID) || !idPattern.MatchString(uploadID) {
		return errors.New("invalid upload identity")
	}
	requestPath := "/api/worker/jobs/" + url.PathEscape(jobID) + "/uploads/" + url.PathEscape(uploadID) + "?leaseToken=" + url.QueryEscape(leaseToken)
	resp, err := c.signedRequest(ctx, http.MethodDelete, requestPath, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return readHTTPError(resp)
	}
	return nil
}

func (c *Client) complete(ctx context.Context, jobID string, request CompleteRequest) error {
	if !idPattern.MatchString(jobID) {
		return errors.New("invalid job ID")
	}
	return c.doJSON(ctx, http.MethodPost, "/api/worker/jobs/"+url.PathEscape(jobID)+"/complete", request, nil)
}

func (c *Client) postEnrollment(ctx context.Context, token, name, architecture string, publicKey ed25519.PublicKey, metadata WorkerMetadata) (string, error) {
	result, err := c.enroll(ctx, Enrollment{Token: token, Name: name, Architecture: architecture, PublicKey: encodeStandardBase64(publicKey), WorkerMetadata: metadata})
	return result.ID, err
}

func encodeStandardBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

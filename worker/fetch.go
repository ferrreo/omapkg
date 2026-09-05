package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMaxSourceBytes = 512 << 20
	maxRedirects          = 5
)

var blockedNetworks = func() []*net.IPNet {
	var result []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::/128",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	} {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			result = append(result, network)
		}
	}
	return result
}()

var platformSourcePattern = regexp.MustCompile(`^/sources/([0-9a-f]{64})\.tar$`)

func safeSourceHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext:           safeDialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("source URL exceeded redirect limit")
			}
			return validateSourceURL(req.URL.String())
		},
		Timeout: 10 * time.Minute,
	}
}

func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid source address: %w", err)
	}
	if ip := net.ParseIP(host); ip != nil {
		if blockedIP(ip) {
			return nil, errors.New("source address is private or local")
		}
		return (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	if !validDNSName(host) {
		return nil, errors.New("source hostname is invalid")
	}
	resolver := net.DefaultResolver
	addresses, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve source host: %w", err)
	}
	dialer := &net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, address := range addresses {
		if blockedIP(address.IP) {
			return nil, errors.New("source hostname resolves to a private or local address")
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("source host has no usable address")
	}
	return nil, lastErr
}

func validDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /\\\t\r\n") {
		return false
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	return lower != "localhost" && !strings.HasSuffix(lower, ".localhost") && !strings.HasSuffix(lower, ".local") && !strings.HasSuffix(lower, ".internal")
}

func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, network := range blockedNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func fetchSources(ctx context.Context, sources []Source, destination string, maxBytes int64, timeout time.Duration) ([]fetchedSource, error) {
	return fetchSourcesForClient(ctx, sources, destination, maxBytes, timeout, nil)
}

func fetchSourcesForClient(ctx context.Context, sources []Source, destination string, maxBytes int64, timeout time.Duration, coordinator *Client) ([]fetchedSource, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxSourceBytes
	}
	if maxBytes > 2<<30 {
		return nil, errors.New("max source size cannot exceed 2 GiB")
	}
	if err := os.MkdirAll(destination, 0o700); err != nil {
		return nil, fmt.Errorf("create source directory: %w", err)
	}
	client := safeSourceHTTPClient()
	if timeout > 0 {
		client.Timeout = timeout
	}
	result := make([]fetchedSource, 0, len(sources))
	seen := make(map[string]struct{}, len(sources))
	for _, source := range sources {
		if !namePattern.MatchString(source.Name) || source.Name == "." || source.Name == ".." {
			return nil, fmt.Errorf("unsafe source name %q", source.Name)
		}
		if _, ok := seen[source.Name]; ok {
			return nil, fmt.Errorf("duplicate source name %q", source.Name)
		}
		seen[source.Name] = struct{}{}
		if err := validateSourceURL(source.URL); err != nil {
			return nil, fmt.Errorf("source %q: %w", source.Name, err)
		}
		if !sha256Pattern.MatchString(source.SHA256) {
			return nil, fmt.Errorf("source %q has invalid SHA256", source.Name)
		}
		filename := filepath.Join(destination, source.Name)
		requester, err := requestSource(coordinator, client, source)
		if err != nil {
			return nil, err
		}
		if err := fetchSourceWithRequester(ctx, source, filename, maxBytes, requester); err != nil {
			return nil, err
		}
		result = append(result, fetchedSource{Source: source, Path: filename})
	}
	return result, nil
}

func fetchSource(ctx context.Context, client *http.Client, source Source, filename string, maxBytes int64) error {
	return fetchSourceWithRequester(ctx, source, filename, maxBytes, func(request *http.Request) (*http.Response, error) {
		return client.Do(request)
	})
}

type sourceRequester func(*http.Request) (*http.Response, error)

func sourceRequesterForCoordinator(coordinator *Client, source Source) (sourceRequester, error) {
	if coordinator == nil {
		return nil, nil
	}
	u, err := url.Parse(source.URL)
	if err != nil {
		return nil, err
	}
	if !sameOrigin(u, coordinator.Origin) {
		return nil, nil
	}
	prefix := strings.TrimSuffix(coordinator.Origin.EscapedPath(), "/")
	requestPath := u.EscapedPath()
	if prefix != "" {
		if !strings.HasPrefix(requestPath, prefix+"/") {
			return nil, errors.New("same-origin source is outside configured origin path")
		}
		requestPath = strings.TrimPrefix(requestPath, prefix)
	}
	match := platformSourcePattern.FindStringSubmatch(requestPath)
	if len(match) != 2 || match[1] != source.SHA256 || u.RawQuery != "" {
		return nil, errors.New("same-origin source must be its declared private source object")
	}
	return func(request *http.Request) (*http.Response, error) {
		return coordinator.signedRequest(request.Context(), http.MethodGet, requestPath, nil)
	}, nil
}

func requestSource(coordinator *Client, external *http.Client, source Source) (sourceRequester, error) {
	if coordinator != nil {
		private, err := sourceRequesterForCoordinator(coordinator, source)
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", source.Name, err)
		}
		if private != nil {
			return private, nil
		}
		if sameOriginURL(source.URL, coordinator.Origin) {
			return nil, fmt.Errorf("source %q: same-origin source is not a private source object", source.Name)
		}
	}
	return external.Do, nil
}

func sameOriginURL(raw string, origin *url.URL) bool {
	u, err := url.Parse(raw)
	return err == nil && sameOrigin(u, origin)
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil && strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func fetchSourceWithRequester(ctx context.Context, source Source, filename string, maxBytes int64, requestSource sourceRequester) error {
	if requestSource == nil {
		return errors.New("source requester is required")
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxSourceBytes
	}
	if err := validateSourceURL(source.URL); err != nil {
		return fmt.Errorf("source %q: %w", source.Name, err)
	}
	if !sha256Pattern.MatchString(source.SHA256) {
		return fmt.Errorf("source %q has invalid SHA256", source.Name)
	}
	if filepath.Base(filename) != source.Name || !namePattern.MatchString(source.Name) {
		return fmt.Errorf("source %q has an unsafe destination", source.Name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return fmt.Errorf("source %q: create request: %w", source.Name, err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "opr-worker/1")
	resp, err := requestSource(req)
	if err != nil {
		return fmt.Errorf("source %q: fetch: %w", source.Name, err)
	}
	if resp == nil || resp.Body == nil {
		return fmt.Errorf("source %q: fetch returned no body", source.Name)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("source %q: upstream returned %s", source.Name, resp.Status)
	}
	if encoding := strings.TrimSpace(strings.ToLower(resp.Header.Get("Content-Encoding"))); encoding != "" && encoding != "identity" {
		return fmt.Errorf("source %q: compressed response is not accepted", source.Name)
	}
	if resp.ContentLength > maxBytes {
		return fmt.Errorf("source %q: content length %s exceeds limit", source.Name, strconv.FormatInt(maxBytes, 10))
	}
	tmp, err := os.CreateTemp(filepath.Dir(filename), ".source-*")
	if err != nil {
		return fmt.Errorf("source %q: create temporary file: %w", source.Name, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("source %q: chmod temporary file: %w", source.Name, err)
	}
	reader := io.LimitReader(resp.Body, maxBytes+1)
	hash := newHashWriter(tmp)
	n, err := io.Copy(hash, reader)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("source %q: save: %w", source.Name, err)
	}
	if n > maxBytes {
		tmp.Close()
		return fmt.Errorf("source %q: response exceeds %d bytes", source.Name, maxBytes)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("source %q: sync: %w", source.Name, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("source %q: close: %w", source.Name, err)
	}
	got := hash.sum()
	if got != source.SHA256 {
		return fmt.Errorf("source %q: SHA256 mismatch (got %s)", source.Name, got)
	}
	if err := os.Rename(tmpName, filename); err != nil {
		return fmt.Errorf("source %q: install: %w", source.Name, err)
	}
	return nil
}

type hashWriter struct {
	file io.Writer
	hash hash.Hash
}

func newHashWriter(file io.Writer) *hashWriter {
	return &hashWriter{file: file, hash: sha256.New()}
}

func (w *hashWriter) Write(p []byte) (int, error) {
	if _, err := w.hash.Write(p); err != nil {
		return 0, err
	}
	return w.file.Write(p)
}

func (w *hashWriter) sum() string {
	return fmt.Sprintf("%x", w.hash.Sum(nil))
}

// Package npm is a minimal client for the npm registry endpoints used by
// secspec to audit trusted publisher configurations.
package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultRegistry is the public npm registry.
const DefaultRegistry = "https://registry.npmjs.org"

// maxOTPAttempts bounds how many times a single request is retried after a 2FA
// challenge, so a mistyped or expired code can be corrected without looping
// forever.
const maxOTPAttempts = 3

// ErrOTPRequired is returned when the registry demands a one-time password and
// none can be obtained (for example in non-interactive mode).
var ErrOTPRequired = errors.New("npm 2FA required")

// Client talks to the npm registry API.
type Client struct {
	Registry string
	Token    string
	OTP      string
	HTTP     *http.Client

	// OnOTPRequired, when non-nil, is called to obtain a fresh one-time
	// password whenever the registry issues a 2FA challenge. It may be called
	// more than once for a single request (for example after a mistyped or
	// expired code). When nil, a 2FA challenge surfaces as ErrOTPRequired.
	OnOTPRequired func(ctx context.Context) (string, error)
}

// NewClient returns a client authenticated with token. otp, when non-empty, is
// sent as the npm-otp header required by the trust endpoints for 2FA accounts.
func NewClient(token, otp string) *Client {
	return &Client{
		Registry: DefaultRegistry,
		Token:    token,
		OTP:      otp,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError is returned for non-2xx responses that are not 2FA challenges.
type APIError struct {
	StatusCode int
	Method     string
	URL        string
	Body       string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("npm: %s %s: HTTP %d", e.Method, e.URL, e.StatusCode)
	}
	return fmt.Sprintf("npm: %s %s: HTTP %d: %s", e.Method, e.URL, e.StatusCode, e.Body)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// get performs a GET request. path may already include a query string.
func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// do performs a request, transparently answering 2FA challenges via
// OnOTPRequired by retrying with a fresh npm-otp header. body, when non-nil, is
// JSON-encoded and resent unchanged on each attempt.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	u := strings.TrimRight(c.Registry, "/") + path

	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}

	for attempt := 0; ; attempt++ {
		var reader io.Reader
		if payload != nil {
			reader = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, reader)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		if c.OTP != "" {
			req.Header.Set("npm-otp", c.OTP)
		}

		resp, err := c.httpClient().Do(req)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out == nil {
				return nil
			}
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.UseNumber()
			return dec.Decode(out)
		}

		challenge := needsOTP(resp.StatusCode, resp.Header, data)
		if challenge && c.OnOTPRequired != nil && attempt < maxOTPAttempts {
			otp, err := c.OnOTPRequired(ctx)
			if err != nil {
				return err
			}
			otp = strings.TrimSpace(otp)
			if otp == "" {
				return fmt.Errorf("%w for %s %s", ErrOTPRequired, method, u)
			}
			c.OTP = otp
			continue
		}
		if challenge {
			return fmt.Errorf("%w for %s %s; set NPM_OTP or drop --non-interactive", ErrOTPRequired, method, u)
		}

		return &APIError{StatusCode: resp.StatusCode, Method: method, URL: u, Body: strings.TrimSpace(string(data))}
	}
}

// AddTrust creates a single trusted publisher configuration for a package. The
// API expects an array of configurations, so config is wrapped in one.
func (c *Client) AddTrust(ctx context.Context, pkg string, config map[string]any) error {
	return c.do(ctx, http.MethodPost, "/-/package/"+escapePackage(pkg)+"/trust", []map[string]any{config}, nil)
}

// needsOTP reports whether a response is the registry asking for a one-time
// password. npm uses 401/403 with a body (or WWW-Authenticate header) that
// mentions the one-time pass, OTP, or the interactive web-auth flow.
func needsOTP(status int, header http.Header, body []byte) bool {
	if status != http.StatusUnauthorized && status != http.StatusForbidden {
		return false
	}
	if strings.Contains(strings.ToLower(header.Get("WWW-Authenticate")), "otp") {
		return true
	}
	text := strings.ToLower(string(body))
	for _, marker := range []string{
		"one-time pass", "one time pass", "e_otp_required",
		"otp", "2fa", "two-factor", "two factor", "authurl", "doneurl",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

// escapePackage escapes a package name for use in a URL path. Scoped names keep
// their leading "@" but have the separating slash encoded.
func escapePackage(name string) string {
	return strings.ReplaceAll(name, "/", "%2F")
}

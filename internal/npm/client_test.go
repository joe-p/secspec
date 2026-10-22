package npm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDoPromptsOnOTPChallenge(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if r.Header.Get("npm-otp") != "123456" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"You must provide a one-time pass"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"1"}]`))
	}))
	defer srv.Close()

	var prompts int32
	c := NewClient("tok", "")
	c.Registry = srv.URL
	c.OnOTPRequired = func(context.Context) (string, error) {
		atomic.AddInt32(&prompts, 1)
		return "123456", nil
	}

	if _, err := c.ListTrust(context.Background(), "@scope/pkg"); err != nil {
		t.Fatalf("ListTrust: %v", err)
	}
	if got := atomic.LoadInt32(&prompts); got != 1 {
		t.Errorf("prompts = %d, want 1", got)
	}
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Errorf("requests = %d, want 2", got)
	}
	if c.OTP != "123456" {
		t.Errorf("cached OTP = %q, want 123456", c.OTP)
	}
}

func TestDoRetriesWrongOTP(t *testing.T) {
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if r.Header.Get("npm-otp") != "good" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"otp required"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"1"}]`))
	}))
	defer srv.Close()

	codes := []string{"bad", "good"}
	var calls int32
	c := NewClient("tok", "")
	c.Registry = srv.URL
	c.OnOTPRequired = func(context.Context) (string, error) {
		i := atomic.AddInt32(&calls, 1) - 1
		return codes[i], nil
	}

	if _, err := c.ListTrust(context.Background(), "@scope/pkg"); err != nil {
		t.Fatalf("ListTrust: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("prompt calls = %d, want 2", got)
	}
	if got := atomic.LoadInt32(&requests); got != 3 {
		t.Errorf("requests = %d, want 3", got)
	}
}

func TestDoOTPRequiredWithoutPrompt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"You must provide a one-time pass"}`))
	}))
	defer srv.Close()

	c := NewClient("tok", "")
	c.Registry = srv.URL
	// OnOTPRequired left nil (non-interactive).

	_, err := c.ListTrust(context.Background(), "@scope/pkg")
	if !errors.Is(err, ErrOTPRequired) {
		t.Fatalf("err = %v, want ErrOTPRequired", err)
	}
}

func TestDoExhaustsOTPAttempts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"2fa required"}`))
	}))
	defer srv.Close()

	var prompts int32
	c := NewClient("tok", "")
	c.Registry = srv.URL
	c.OnOTPRequired = func(context.Context) (string, error) {
		atomic.AddInt32(&prompts, 1)
		return "always-wrong", nil
	}

	_, err := c.ListTrust(context.Background(), "@scope/pkg")
	if !errors.Is(err, ErrOTPRequired) {
		t.Fatalf("err = %v, want ErrOTPRequired", err)
	}
	if got := atomic.LoadInt32(&prompts); got != maxOTPAttempts {
		t.Errorf("prompts = %d, want %d", got, maxOTPAttempts)
	}
}

func TestDoNoPromptOnOtherErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer srv.Close()

	var prompts int32
	c := NewClient("tok", "")
	c.Registry = srv.URL
	c.OnOTPRequired = func(context.Context) (string, error) {
		atomic.AddInt32(&prompts, 1)
		return "123456", nil
	}

	_, err := c.ListTrust(context.Background(), "@scope/pkg")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("err = %v, want 404 APIError", err)
	}
	if got := atomic.LoadInt32(&prompts); got != 0 {
		t.Errorf("prompts = %d, want 0", got)
	}
}

func TestAddTrustPostsArray(t *testing.T) {
	var method, uri string
	var body []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, uri = r.Method, r.URL.RequestURI()
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient("tok", "")
	c.Registry = srv.URL
	config := map[string]any{
		"type":        "github",
		"claims":      map[string]any{"repository": "o/r"},
		"permissions": []any{"createPackage"},
	}
	if err := c.AddTrust(context.Background(), "@s/p", config); err != nil {
		t.Fatalf("AddTrust: %v", err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %s, want POST", method)
	}
	if uri != "/-/package/@s%2Fp/trust" {
		t.Errorf("uri = %s", uri)
	}
	if len(body) != 1 || body[0]["type"] != "github" {
		t.Fatalf("body = %+v, want a one-element array", body)
	}
}

func TestAddTrustResendsBodyOnOTPChallenge(t *testing.T) {
	var bodies []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		bodies = append(bodies, len(body))
		if r.Header.Get("npm-otp") != "123456" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"one-time pass required"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient("tok", "")
	c.Registry = srv.URL
	c.OnOTPRequired = func(context.Context) (string, error) { return "123456", nil }

	config := map[string]any{"type": "github", "claims": map[string]any{"repository": "o/r"}, "permissions": []any{}}
	if err := c.AddTrust(context.Background(), "@s/p", config); err != nil {
		t.Fatalf("AddTrust: %v", err)
	}
	if len(bodies) != 2 {
		t.Fatalf("requests = %d, want 2", len(bodies))
	}
	for i, n := range bodies {
		if n != 1 {
			t.Errorf("request %d body length = %d, want 1 (body must be resent)", i, n)
		}
	}
}

func TestNeedsOTP(t *testing.T) {
	tests := []struct {
		name   string
		status int
		header http.Header
		body   string
		want   bool
	}{
		{name: "401 one-time pass", status: 401, body: `{"error":"You must provide a one-time pass"}`, want: true},
		{name: "401 authurl flow", status: 401, body: `{"authUrl":"https://npmjs.com/...","doneUrl":"..."}`, want: true},
		{name: "403 2fa", status: 403, body: `{"error":"2fa required"}`, want: true},
		{name: "403 insufficient permissions", status: 403, body: `{"error":"insufficient permissions"}`, want: false},
		{name: "404", status: 404, body: `{"error":"not found"}`, want: false},
		{name: "www-authenticate", status: 401, header: http.Header{"Www-Authenticate": {"OTP"}}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := tt.header
			if header == nil {
				header = http.Header{}
			}
			if got := needsOTP(tt.status, header, []byte(tt.body)); got != tt.want {
				t.Errorf("needsOTP = %v, want %v", got, tt.want)
			}
		})
	}
}

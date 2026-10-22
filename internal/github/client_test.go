package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateAndUpdateRuleset(t *testing.T) {
	var method, path string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		body = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient("t")
	c.BaseURL = srv.URL
	desired := map[string]any{"name": "protect main", "enforcement": "active"}

	if err := c.CreateRuleset(context.Background(), "my-org", "repo", desired); err != nil {
		t.Fatalf("CreateRuleset: %v", err)
	}
	if method != http.MethodPost || path != "/repos/my-org/repo/rulesets" {
		t.Fatalf("create: method=%s path=%s", method, path)
	}
	if body["name"] != "protect main" {
		t.Fatalf("create body = %+v", body)
	}

	if err := c.UpdateRuleset(context.Background(), "my-org", "repo", 42, desired); err != nil {
		t.Fatalf("UpdateRuleset: %v", err)
	}
	if method != http.MethodPut || path != "/repos/my-org/repo/rulesets/42" {
		t.Fatalf("update: method=%s path=%s", method, path)
	}
}

func TestRulesetMatches(t *testing.T) {
	desired := decodeObject(t, `{"name":"x","enforcement":"active"}`)
	match := Ruleset{Name: "x", Raw: decodeObject(t, `{"id":1,"name":"x","enforcement":"active"}`)}
	mismatch := Ruleset{Name: "x", Raw: decodeObject(t, `{"id":1,"name":"x","enforcement":"disabled"}`)}
	if !RulesetMatches(desired, match) {
		t.Error("expected match")
	}
	if RulesetMatches(desired, mismatch) {
		t.Error("expected mismatch")
	}
}

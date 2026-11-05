package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joe-p/secspec/internal/report"
	"github.com/joe-p/secspec/internal/spec"
)

func loadSpec(t *testing.T, body string) *spec.Spec {
	t.Helper()
	var s spec.Spec
	dec := json.NewDecoder(strings.NewReader(body))
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("decode spec: %v", err)
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("validate spec: %v", err)
	}
	return &s
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func TestRunGitHub(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/my-org/repos", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[{"full_name":"my-org/repo-a"},{"full_name":"my-org/repo-b"}]`)
	})
	mux.HandleFunc("/repos/my-org/repo-a/rulesets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[{"id":1,"name":"protect main","enforcement":"active","source_type":"Repository"}]`)
	})
	mux.HandleFunc("/repos/my-org/repo-a/rulesets/1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"id":1,"name":"protect main","enforcement":"active","source_type":"Repository","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"deletion"},{"type":"pull_request","parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true}}]}`)
	})
	mux.HandleFunc("/repos/my-org/repo-b/rulesets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[]`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := loadSpec(t, `{"github":[{"include_repos":["my-org/*"],"rulesets":[{"name":"protect main","enforcement":"active","rules":[{"type":"deletion"},{"type":"pull_request","parameters":{"required_approving_review_count":0}}]}]}]}`)

	rep, err := Run(context.Background(), s, Options{GitHubToken: "t", GitHubBaseURL: srv.URL})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.TargetsScanned != 2 {
		t.Fatalf("targets scanned = %d, want 2", rep.TargetsScanned)
	}
	assertChanges(t, rep, map[string]int{"my-org/repo-a": 1, "my-org/repo-b": 1})
}

func TestRunNPM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/-/v1/search":
			writeJSON(w, `{"objects":[{"package":{"name":"@my-scope/pkg-a"}},{"package":{"name":"@my-scope/pkg-b"}}],"total":2}`)
		case strings.HasPrefix(path, "/-/package/") && strings.HasSuffix(path, "/trust"):
			pkg := strings.TrimSuffix(strings.TrimPrefix(path, "/-/package/"), "/trust")
			switch pkg {
			case "@my-scope/pkg-a":
				writeJSON(w, `[{"id":"1","type":"github","claims":{"repository":"my-org/pkg-a","workflow_ref":{"file":"release.yml"},"environment":"release"},"permissions":["createStagedPackage"]}]`)
			case "@my-scope/pkg-b":
				writeJSON(w, `[]`)
			default:
				http.NotFound(w, r)
			}
		case path == "/@my-scope/pkg-a":
			writeJSON(w, `{"repository":{"type":"git","url":"git+https://github.com/my-org/pkg-a.git"}}`)
		case path == "/@my-scope/pkg-b":
			writeJSON(w, `{"repository":{"type":"git","url":"git+https://github.com/my-org/pkg-b.git"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := loadSpec(t, `{"npm":[{"include_packages":["@my-scope/*"],"trust":[{"type":"github","claims":{"workflow_ref":{"file":"release.yml"},"environment":"release"},"permissions":["createStagedPackage"]}]}]}`)

	rep, err := Run(context.Background(), s, Options{NPMToken: "t", NPMRegistry: srv.URL})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if rep.TargetsScanned != 2 {
		t.Fatalf("targets scanned = %d, want 2", rep.TargetsScanned)
	}
	assertChanges(t, rep, map[string]int{"@my-scope/pkg-a": 0, "@my-scope/pkg-b": 1})
}

func TestRunNPMOTPPrompt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/-/v1/search":
			writeJSON(w, `{"objects":[{"package":{"name":"@s/p"}}],"total":1}`)
		case r.URL.Path == "/-/package/@s/p/trust":
			if r.Header.Get("npm-otp") != "654321" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"You must provide a one-time pass"}`))
				return
			}
			writeJSON(w, `[{"id":"1","type":"github","claims":{"repository":"o/p"},"permissions":["createPackage"]}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := loadSpec(t, `{"npm":[{"include_packages":["@s/p"],"trust":[{"type":"github","claims":{"repository":"o/p"},"permissions":["createPackage"]}]}]}`)

	var prompts int
	rep, err := Run(context.Background(), s, Options{
		NPMToken:    "t",
		NPMRegistry: srv.URL,
		NPMOTPPrompt: func(context.Context) (string, error) {
			prompts++
			return "654321", nil
		},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("expected no mismatches, got %+v", rep.Changes)
	}
	if prompts != 1 {
		t.Fatalf("prompts = %d, want 1", prompts)
	}
}

func TestApplyGitHub(t *testing.T) {
	var createdBody, updatedBody map[string]any
	var updatePath string

	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/my-org/repos", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[{"full_name":"my-org/repo-a"},{"full_name":"my-org/repo-b"},{"full_name":"my-org/repo-c"}]`)
	})
	mux.HandleFunc("/repos/my-org/repo-a/rulesets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[{"id":1,"name":"protect main","enforcement":"active","source_type":"Repository"}]`)
	})
	mux.HandleFunc("/repos/my-org/repo-a/rulesets/1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"id":1,"name":"protect main","enforcement":"active","source_type":"Repository","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"deletion"}]}`)
	})
	mux.HandleFunc("/repos/my-org/repo-b/rulesets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			createdBody = decodeBody(t, r)
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, `{"id":2}`)
			return
		}
		writeJSON(w, `[]`)
	})
	mux.HandleFunc("/repos/my-org/repo-c/rulesets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[{"id":7,"name":"protect main","enforcement":"disabled","source_type":"Repository"}]`)
	})
	mux.HandleFunc("/repos/my-org/repo-c/rulesets/7", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, `{"id":7,"name":"protect main","enforcement":"disabled","source_type":"Repository","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[{"type":"deletion"}]}`)
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		updatePath = r.URL.Path
		updatedBody = decodeBody(t, r)
		writeJSON(w, `{}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := loadSpec(t, `{"github":[{"include_repos":["my-org/*"],"rulesets":[{"name":"protect main","enforcement":"active","rules":[{"type":"deletion"}]}]}]}`)
	wr, err := Apply(context.Background(), s, Options{GitHubToken: "t", GitHubBaseURL: srv.URL})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	created, updated, unchanged := wr.Counts()
	if created != 1 || updated != 1 || unchanged != 1 {
		t.Fatalf("counts = %d/%d/%d, want 1/1/1 (%+v)", created, updated, unchanged, wr.Actions)
	}
	if updatePath != "/repos/my-org/repo-c/rulesets/7" {
		t.Fatalf("update path = %q", updatePath)
	}
	if createdBody["enforcement"] != "active" || updatedBody["enforcement"] != "active" {
		t.Fatalf("bodies not sent as desired: created=%+v updated=%+v", createdBody, updatedBody)
	}
}

func TestApplyGitHubOrgRulesetErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/my-org/repos", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[{"full_name":"my-org/repo"}]`)
	})
	mux.HandleFunc("/repos/my-org/repo/rulesets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `[{"id":1,"name":"protect main","enforcement":"disabled","source_type":"Organization"}]`)
	})
	mux.HandleFunc("/repos/my-org/repo/rulesets/1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"id":1,"name":"protect main","enforcement":"disabled","source_type":"Organization","conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},"rules":[]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := loadSpec(t, `{"github":[{"include_repos":["my-org/*"],"rulesets":[{"name":"protect main","enforcement":"active","rules":[]}]}]}`)
	if _, err := Apply(context.Background(), s, Options{GitHubToken: "t", GitHubBaseURL: srv.URL}); err == nil {
		t.Fatal("expected error for organization-level ruleset")
	}
}

func TestApplyNPM(t *testing.T) {
	var postedPkg string
	var postedBody []map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/-/v1/search":
			writeJSON(w, `{"objects":[{"package":{"name":"@s/pkg-a"}},{"package":{"name":"@s/pkg-b"}}],"total":2}`)
		case r.URL.Path == "/-/package/@s/pkg-b/trust" && r.Method == http.MethodPost:
			postedPkg = "@s/pkg-b"
			_ = json.NewDecoder(r.Body).Decode(&postedBody)
			writeJSON(w, `{}`)
		case r.URL.Path == "/-/package/@s/pkg-a/trust":
			writeJSON(w, `[{"id":"1","type":"github","claims":{"repository":"my-org/pkg-a","environment":"release"},"permissions":["createPackage"]}]`)
		case r.URL.Path == "/-/package/@s/pkg-b/trust":
			writeJSON(w, `[]`)
		case r.URL.Path == "/@s/pkg-a":
			writeJSON(w, `{"repository":{"url":"git+https://github.com/my-org/pkg-a.git"}}`)
		case r.URL.Path == "/@s/pkg-b":
			writeJSON(w, `{"repository":{"url":"git+https://github.com/my-org/pkg-b.git"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := loadSpec(t, `{"npm":[{"include_packages":["@s/*"],"trust":[{"type":"github","claims":{"environment":"release"},"permissions":["createPackage"]}]}]}`)
	wr, err := Apply(context.Background(), s, Options{NPMToken: "t", NPMRegistry: srv.URL})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	created, updated, unchanged := wr.Counts()
	if created != 1 || updated != 0 || unchanged != 1 {
		t.Fatalf("counts = %d/%d/%d, want 1/0/1 (%+v)", created, updated, unchanged, wr.Actions)
	}
	if postedPkg != "@s/pkg-b" || len(postedBody) != 1 {
		t.Fatalf("posted pkg=%q body=%+v", postedPkg, postedBody)
	}
	claims, _ := postedBody[0]["claims"].(map[string]any)
	if claims["repository"] != "my-org/pkg-b" {
		t.Fatalf("repository not resolved from package.json: %+v", claims)
	}
}

func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	defer r.Body.Close()
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return m
}

func TestRunMissingToken(t *testing.T) {
	s := loadSpec(t, `{"github":[{"include_repos":["my-org/repo"],"rulesets":[{"name":"x"}]}]}`)
	if _, err := Run(context.Background(), s, Options{}); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func assertChanges(t *testing.T, rep *report.Report, want map[string]int) {
	t.Helper()
	got := map[string]int{}
	for _, c := range rep.Changes {
		got[c.Target]++
	}
	for target, n := range want {
		if got[target] != n {
			t.Errorf("target %s: got %d changes, want %d (%+v)", target, got[target], n, rep.Changes)
		}
	}
	for target := range got {
		if _, ok := want[target]; !ok {
			t.Errorf("unexpected changes for target %s", target)
		}
	}
}

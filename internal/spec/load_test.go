package spec

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secspec.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	path := write(t, `{
	  "github": [{"include_repos": ["my-org/*"], "rulesets": [{"name": "protect main", "enforcement": "active"}]}],
	  "npm": [{"include_packages": ["@scope/*"], "trust": [{"type": "github", "claims": {}, "permissions": ["createStagedPackage"]}]}]
	}`)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.GitHub) != 1 || len(s.NPM) != 1 {
		t.Fatalf("unexpected spec: %+v", s)
	}
}

func TestLoadUnknownField(t *testing.T) {
	path := write(t, `{"github": [{"include_repos": ["my-org/*"], "rulesets": [{"name": "x"}], "typo": true}]}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadExample(t *testing.T) {
	s, err := Load(filepath.Join("..", "..", "examples", "gh_npm.json"))
	if err != nil {
		t.Fatalf("loading example spec: %v", err)
	}
	if len(s.GitHub) != 1 || len(s.NPM) != 1 {
		t.Fatalf("unexpected example spec: %+v", s)
	}
}

func TestValidateErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty", body: `{}`},
		{name: "missing include_repos", body: `{"github":[{"rulesets":[{"name":"x"}]}]}`},
		{name: "bad github pattern", body: `{"github":[{"include_repos":["*/*"],"rulesets":[{"name":"x"}]}]}`},
		{name: "ruleset without name", body: `{"github":[{"include_repos":["o/r"],"rulesets":[{"enforcement":"active"}]}]}`},
		{name: "npm without scope", body: `{"npm":[{"include_packages":["pkg"],"trust":[{"type":"github","claims":{},"permissions":[]}]}]}`},
		{name: "trust without type", body: `{"npm":[{"include_packages":["@s/p"],"trust":[{"claims":{},"permissions":[]}]}]}`},
		{name: "trust without claims", body: `{"npm":[{"include_packages":["@s/p"],"trust":[{"type":"github","permissions":[]}]}]}`},
		{name: "trust without permissions", body: `{"npm":[{"include_packages":["@s/p"],"trust":[{"type":"github","claims":{}}]}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := write(t, tt.body)
			if _, err := Load(path); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

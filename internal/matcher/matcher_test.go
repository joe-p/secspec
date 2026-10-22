package matcher

import "testing"

func TestParseGitHub(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantNS  string
		wantNm  string
		wantWld bool
		wantErr bool
	}{
		{name: "wildcard", raw: "my-org/*", wantNS: "my-org", wantNm: "*", wantWld: true},
		{name: "literal", raw: "another-org/specific-repo", wantNS: "another-org", wantNm: "specific-repo"},
		{name: "partial wildcard", raw: "my-org/api-*", wantNS: "my-org", wantNm: "api-*", wantWld: true},
		{name: "wildcard namespace", raw: "*/repo", wantErr: true},
		{name: "no slash", raw: "my-org", wantErr: true},
		{name: "too many slashes", raw: "my-org/a/b", wantErr: true},
		{name: "empty", raw: "", wantErr: true},
		{name: "scope in github", raw: "@scope/pkg", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParseGitHub(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", p)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Namespace != tt.wantNS || p.Name != tt.wantNm || p.Wildcard != tt.wantWld {
				t.Fatalf("got %+v, want ns=%q name=%q wildcard=%v", p, tt.wantNS, tt.wantNm, tt.wantWld)
			}
		})
	}
}

func TestParseNPM(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "wildcard", raw: "@my-scope/*"},
		{name: "literal", raw: "@another-scope/specific-package"},
		{name: "no scope", raw: "my-scope/*", wantErr: true},
		{name: "wildcard scope", raw: "@*/pkg", wantErr: true},
		{name: "no slash", raw: "@my-scope", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseNPM(tt.raw)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for %q", tt.raw)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.raw, err)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern string
		full    string
		want    bool
	}{
		{"my-org/*", "my-org/repo", true},
		{"my-org/*", "other/repo", false},
		{"my-org/*", "my-org/sub/repo", false},
		{"my-org/api-*", "my-org/api-server", true},
		{"my-org/api-*", "my-org/web", false},
		{"my-org/specific-repo", "my-org/specific-repo", true},
		{"my-org/specific-repo", "my-org/other", false},
		{"@scope/*", "@scope/pkg", true},
		{"@scope/*-cli", "@scope/foo-cli", true},
		{"@scope/*-cli", "@scope/foo", false},
		{"@scope/*", "@other/pkg", false},
	}
	for _, tt := range tests {
		var p Pattern
		var err error
		if len(tt.pattern) > 0 && tt.pattern[0] == '@' {
			p, err = ParseNPM(tt.pattern)
		} else {
			p, err = ParseGitHub(tt.pattern)
		}
		if err != nil {
			t.Fatalf("parse %q: %v", tt.pattern, err)
		}
		if got := p.Match(tt.full); got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.pattern, tt.full, got, tt.want)
		}
	}
}

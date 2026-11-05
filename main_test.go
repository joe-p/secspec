package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestGithubHost(t *testing.T) {
	tests := []struct {
		name   string
		apiURL string
		want   string
	}{
		{name: "default", apiURL: "", want: "github.com"},
		{name: "github.com", apiURL: "https://api.github.com", want: "github.com"},
		{name: "enterprise", apiURL: "https://ghe.example.com/api/v3", want: "ghe.example.com"},
		{name: "invalid", apiURL: "://bad", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := githubHost(tt.apiURL); got != tt.want {
				t.Errorf("githubHost(%q) = %q, want %q", tt.apiURL, got, tt.want)
			}
		})
	}
}

func TestGhAuthToken(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gh")
	body := `#!/bin/sh
if [ "$1" != "auth" ] || [ "$2" != "token" ] || [ "$3" != "--hostname" ] || [ "$4" != "github.com" ]; then
	exit 1
fi
printf '  tok123\n'
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if got := ghAuthToken(context.Background(), "github.com"); got != "tok123" {
		t.Errorf("ghAuthToken() = %q, want %q", got, "tok123")
	}
}

func TestGhAuthTokenUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if got := ghAuthToken(context.Background(), "github.com"); got != "" {
		t.Errorf("ghAuthToken() = %q, want empty when gh is unavailable", got)
	}
}

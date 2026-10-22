package npm

import (
	"encoding/json"
	"strings"
	"testing"
)

func decodeObject(t *testing.T, s string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return m
}

func TestDiffTrustMatchWithDefaultRepo(t *testing.T) {
	desired := []map[string]any{decodeObject(t, `{"type":"github","claims":{"workflow_ref":{"file":"release.yml"},"environment":"release"},"permissions":["createStagedPackage"]}`)}
	actual := []map[string]any{decodeObject(t, `{"id":"uuid","type":"github","claims":{"repository":"my-org/pkg","workflow_ref":{"file":"release.yml"},"environment":"release"},"permissions":["createStagedPackage"]}`)}
	if changes := DiffTrust("@scope/pkg", desired, actual, "my-org/pkg"); len(changes) != 0 {
		t.Fatalf("expected no changes, got %+v", changes)
	}
}

func TestDiffTrustMissing(t *testing.T) {
	desired := []map[string]any{decodeObject(t, `{"type":"github","claims":{"repository":"my-org/pkg"},"permissions":["createStagedPackage"]}`)}
	changes := DiffTrust("@scope/pkg", desired, nil, "")
	if len(changes) != 1 || !changes[0].Missing {
		t.Fatalf("expected one missing change, got %+v", changes)
	}
}

func TestDiffTrustUnresolvedRepository(t *testing.T) {
	desired := []map[string]any{decodeObject(t, `{"type":"github","claims":{"environment":"release"},"permissions":["createStagedPackage"]}`)}
	changes := DiffTrust("@scope/pkg", desired, nil, "")
	if len(changes) != 1 || changes[0].Path != "claims.repository" {
		t.Fatalf("expected unresolved repository change, got %+v", changes)
	}
}

func TestDiffTrustExtraPermission(t *testing.T) {
	desired := []map[string]any{decodeObject(t, `{"type":"github","claims":{"repository":"my-org/pkg"},"permissions":["createStagedPackage"]}`)}
	actual := []map[string]any{decodeObject(t, `{"type":"github","claims":{"repository":"my-org/pkg"},"permissions":["createStagedPackage","manageDistTags"]}`)}
	changes := DiffTrust("@scope/pkg", desired, actual, "")
	if len(changes) != 1 {
		t.Fatalf("expected one change, got %+v", changes)
	}
	if changes[0].Path != "permissions[1]" {
		t.Fatalf("unexpected path %q", changes[0].Path)
	}
}

func TestNormalizeRepoURL(t *testing.T) {
	tests := map[string]string{
		"git+https://github.com/my-org/pkg.git":   "my-org/pkg",
		"https://github.com/my-org/pkg":           "my-org/pkg",
		"git@github.com:my-org/pkg.git":           "my-org/pkg",
		"github:my-org/pkg":                       "my-org/pkg",
		"my-org/pkg":                              "my-org/pkg",
		"git+ssh://git@github.com/my-org/pkg.git": "my-org/pkg",
		"": "",
	}
	for in, want := range tests {
		if got := normalizeRepoURL(in); got != want {
			t.Errorf("normalizeRepoURL(%q) = %q, want %q", in, got, want)
		}
	}
}

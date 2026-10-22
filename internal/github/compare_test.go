package github

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/joe-p/secspec/internal/report"
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

func TestDiffRulesetsMatch(t *testing.T) {
	desired := []map[string]any{decodeObject(t, `{"name":"protect main","enforcement":"active","rules":[{"type":"deletion"},{"type":"pull_request","parameters":{"required_approving_review_count":0}}]}`)}
	actual := []Ruleset{
		{Name: "protect main", Raw: decodeObject(t, `{"id":1,"name":"protect main","enforcement":"active","source_type":"Repository","rules":[{"type":"deletion"},{"type":"pull_request","parameters":{"required_approving_review_count":0,"dismiss_stale_reviews_on_push":true}}]}`)},
	}
	if changes := DiffRulesets("my-org/repo", desired, actual); len(changes) != 0 {
		t.Fatalf("expected no changes, got %+v", changes)
	}
}

func TestDiffRulesetsMismatch(t *testing.T) {
	desired := []map[string]any{decodeObject(t, `{"name":"protect main","enforcement":"active","rules":[{"type":"pull_request","parameters":{"required_approving_review_count":0}}]}`)}
	actual := []Ruleset{
		{Name: "protect main", Raw: decodeObject(t, `{"name":"protect main","enforcement":"active","rules":[{"type":"pull_request","parameters":{"required_approving_review_count":1}}]}`)},
	}
	changes := DiffRulesets("my-org/repo", desired, actual)
	if len(changes) != 1 {
		t.Fatalf("expected one change, got %+v", changes)
	}
	want := report.Change{Provider: "github", Target: "my-org/repo", Setting: `ruleset "protect main"`, Path: "rules[type=pull_request].parameters.required_approving_review_count"}
	got := changes[0]
	if got.Provider != want.Provider || got.Target != want.Target || got.Setting != want.Setting || got.Path != want.Path {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDiffRulesetsMissing(t *testing.T) {
	desired := []map[string]any{decodeObject(t, `{"name":"protect main","enforcement":"active","rules":[]}`)}
	changes := DiffRulesets("my-org/repo", desired, nil)
	if len(changes) != 1 || !changes[0].Missing {
		t.Fatalf("expected one missing change, got %+v", changes)
	}
}

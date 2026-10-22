package github

import (
	"fmt"

	"github.com/joe-p/secspec/internal/jsonutil"
	"github.com/joe-p/secspec/internal/report"
)

// RulesetMatches reports whether a live ruleset already satisfies a desired
// ruleset: every field the desired ruleset specifies must match.
func RulesetMatches(desired map[string]any, actual Ruleset) bool {
	return len(jsonutil.SubsetDiff(desired, actual.Raw)) == 0
}

// DiffRulesets compares desired rulesets (decoded spec entries) against the
// rulesets that currently exist on a repository. Rulesets are matched by name.
func DiffRulesets(repo string, desired []map[string]any, actual []Ruleset) []report.Change {
	byName := make(map[string]Ruleset, len(actual))
	for _, a := range actual {
		byName[a.Name] = a
	}

	var out []report.Change
	for _, d := range desired {
		name, _ := d["name"].(string)
		setting := fmt.Sprintf("ruleset %q", name)

		a, ok := byName[name]
		if !ok {
			out = append(out, report.Change{
				Provider: "github",
				Target:   repo,
				Setting:  setting,
				Missing:  true,
				Expected: d,
			})
			continue
		}
		for _, diff := range jsonutil.SubsetDiff(d, a.Raw) {
			out = append(out, report.Change{
				Provider: "github",
				Target:   repo,
				Setting:  setting,
				Path:     diff.Path,
				Expected: diff.Expected,
				Actual:   diff.Actual,
				Missing:  diff.Missing,
			})
		}
	}
	return out
}

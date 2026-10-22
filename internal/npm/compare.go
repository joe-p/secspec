package npm

import (
	"fmt"

	"github.com/joe-p/secspec/internal/jsonutil"
	"github.com/joe-p/secspec/internal/report"
)

// DiffTrust compares desired trusted publisher configurations (decoded spec
// entries) against the configurations that currently exist for a package.
//
// When a desired configuration omits claims.repository, defaultRepo (read from
// the package's package.json) is substituted. Configurations are matched by
// type first, then by their claims and permissions.
func DiffTrust(pkg string, desired []map[string]any, actual []map[string]any, defaultRepo string) []report.Change {
	var out []report.Change
	for i, d := range desired {
		typ, _ := d["type"].(string)
		setting := fmt.Sprintf("trust[%d] (%s)", i, typ)

		config, ok := PrepareTrustConfig(d, defaultRepo)
		if !ok {
			out = append(out, report.Change{
				Provider: "npm",
				Target:   pkg,
				Setting:  setting,
				Path:     "claims.repository",
				Missing:  true,
				Expected: "repository.url from package.json",
			})
			continue
		}

		var best []jsonutil.Diff
		matched := false
		for _, a := range actual {
			if at, _ := a["type"].(string); at != typ {
				continue
			}
			diffs := jsonutil.SubsetDiff(config, a)
			if len(diffs) == 0 {
				matched = true
				break
			}
			if best == nil || len(diffs) < len(best) {
				best = diffs
			}
		}
		if matched {
			continue
		}
		if best == nil {
			out = append(out, report.Change{
				Provider: "npm",
				Target:   pkg,
				Setting:  setting,
				Missing:  true,
				Expected: config,
			})
			continue
		}
		for _, diff := range best {
			out = append(out, report.Change{
				Provider: "npm",
				Target:   pkg,
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

// TrustMatches reports whether a desired configuration is already satisfied by
// an actual one: the types must be equal and every field the desired
// configuration specifies must match.
func TrustMatches(desired, actual map[string]any) bool {
	dt, _ := desired["type"].(string)
	at, _ := actual["type"].(string)
	if dt != at {
		return false
	}
	return len(jsonutil.SubsetDiff(desired, actual)) == 0
}

// PrepareTrustConfig returns a shallow copy of config whose claims.repository
// is filled in from defaultRepo when it is missing (the npm API requires it).
// It returns false when the repository claim is missing and no default is
// available.
func PrepareTrustConfig(config map[string]any, defaultRepo string) (map[string]any, bool) {
	claims, _ := config["claims"].(map[string]any)
	if _, ok := claims["repository"]; ok {
		return config, true
	}
	if defaultRepo == "" {
		return nil, false
	}
	copiedClaims := make(map[string]any, len(claims)+1)
	for k, v := range claims {
		copiedClaims[k] = v
	}
	copiedClaims["repository"] = defaultRepo

	copied := make(map[string]any, len(config))
	for k, v := range config {
		copied[k] = v
	}
	copied["claims"] = copiedClaims
	return copied, true
}

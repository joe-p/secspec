// Package engine resolves spec targets against live services and applies or
// audits the desired settings.
package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/joe-p/secspec/internal/github"
	"github.com/joe-p/secspec/internal/matcher"
	"github.com/joe-p/secspec/internal/npm"
	"github.com/joe-p/secspec/internal/report"
	"github.com/joe-p/secspec/internal/spec"
)

// Options configures a run.
type Options struct {
	GitHubToken string
	NPMToken    string
	NPMOTP      string

	// NPMOTPPrompt, when non-nil, is called to obtain a fresh npm one-time
	// password whenever the registry issues a 2FA challenge. When nil, such a
	// challenge is reported as an error.
	NPMOTPPrompt func(ctx context.Context) (string, error)

	// GitHubBaseURL and NPMRegistry override the service endpoints. They are
	// primarily useful for tests.
	GitHubBaseURL string
	NPMRegistry   string
}

// Run audits every target in the spec and returns a report of the mismatches.
// It fails fast when the spec references a provider whose token is missing.
func Run(ctx context.Context, s *spec.Spec, opts Options) (*report.Report, error) {
	rep := &report.Report{}

	if len(s.GitHub) > 0 {
		client, err := githubClient(opts)
		if err != nil {
			return nil, err
		}
		targets, err := resolveGitHub(ctx, client, s.GitHub)
		if err != nil {
			return nil, err
		}
		for _, repo := range targets.repos {
			owner, name, _ := strings.Cut(repo, "/")
			actual, err := client.ListRulesets(ctx, owner, name)
			if err != nil {
				return nil, fmt.Errorf("list rulesets for %s: %w", repo, err)
			}
			rep.TargetsScanned++
			rep.Add(github.DiffRulesets(repo, mapValues(targets.byRepo[repo]), actual)...)
		}
	}

	if len(s.NPM) > 0 {
		client, err := npmClient(opts)
		if err != nil {
			return nil, err
		}
		targets, err := resolveNPM(ctx, client, s.NPM)
		if err != nil {
			return nil, err
		}
		for _, pkg := range targets.pkgs {
			actual, err := client.ListTrust(ctx, pkg)
			if err != nil {
				return nil, fmt.Errorf("list trust for %s: %w", pkg, err)
			}
			defaultRepo, err := defaultRepoFor(ctx, client, pkg, targets.byPkg[pkg])
			if err != nil {
				return nil, err
			}
			rep.TargetsScanned++
			rep.Add(npm.DiffTrust(pkg, targets.byPkg[pkg], actual, defaultRepo)...)
		}
	}

	return rep, nil
}

// Apply writes the spec to the live services. It creates settings that are
// missing and updates those that do not match, but never deletes settings that
// are absent from the spec.
func Apply(ctx context.Context, s *spec.Spec, opts Options) (*report.WriteReport, error) {
	wr := &report.WriteReport{}

	if len(s.GitHub) > 0 {
		client, err := githubClient(opts)
		if err != nil {
			return nil, err
		}
		targets, err := resolveGitHub(ctx, client, s.GitHub)
		if err != nil {
			return nil, err
		}
		if err := applyGitHub(ctx, client, targets, wr); err != nil {
			return nil, err
		}
	}

	if len(s.NPM) > 0 {
		client, err := npmClient(opts)
		if err != nil {
			return nil, err
		}
		targets, err := resolveNPM(ctx, client, s.NPM)
		if err != nil {
			return nil, err
		}
		if err := applyNPM(ctx, client, targets, wr); err != nil {
			return nil, err
		}
	}

	return wr, nil
}

func applyGitHub(ctx context.Context, client *github.Client, targets *githubTargets, wr *report.WriteReport) error {
	for _, repo := range targets.repos {
		owner, name, _ := strings.Cut(repo, "/")
		actual, err := client.ListRulesets(ctx, owner, name)
		if err != nil {
			return fmt.Errorf("list rulesets for %s: %w", repo, err)
		}
		byName := make(map[string]github.Ruleset, len(actual))
		for _, a := range actual {
			byName[a.Name] = a
		}

		for _, desired := range mapValues(targets.byRepo[repo]) {
			rsName, _ := desired["name"].(string)
			setting := fmt.Sprintf("ruleset %q", rsName)

			a, exists := byName[rsName]
			switch {
			case !exists:
				if err := client.CreateRuleset(ctx, owner, name, desired); err != nil {
					return fmt.Errorf("create ruleset %q on %s: %w", rsName, repo, err)
				}
				wr.Add(report.Action{Provider: "github", Target: repo, Setting: setting, Action: "created"})
			case a.SourceType != "" && a.SourceType != "Repository":
				return fmt.Errorf("ruleset %q on %s is defined at the %s level and cannot be managed here", rsName, repo, a.SourceType)
			case github.RulesetMatches(desired, a):
				wr.Add(report.Action{Provider: "github", Target: repo, Setting: setting, Action: "unchanged"})
			default:
				if err := client.UpdateRuleset(ctx, owner, name, a.ID, desired); err != nil {
					return fmt.Errorf("update ruleset %q on %s: %w", rsName, repo, err)
				}
				wr.Add(report.Action{Provider: "github", Target: repo, Setting: setting, Action: "updated"})
			}
		}
	}
	return nil
}

func applyNPM(ctx context.Context, client *npm.Client, targets *npmTargets, wr *report.WriteReport) error {
	for _, pkg := range targets.pkgs {
		actual, err := client.ListTrust(ctx, pkg)
		if err != nil {
			return fmt.Errorf("list trust for %s: %w", pkg, err)
		}
		defaultRepo, err := defaultRepoFor(ctx, client, pkg, targets.byPkg[pkg])
		if err != nil {
			return err
		}

		for i, desired := range targets.byPkg[pkg] {
			typ, _ := desired["type"].(string)
			setting := fmt.Sprintf("trust[%d] (%s)", i, typ)

			config, ok := npm.PrepareTrustConfig(desired, defaultRepo)
			if !ok {
				return fmt.Errorf("trust[%d] (%s) on %s omits claims.repository and %s has no usable repository url", i, typ, pkg, pkg)
			}

			matched := false
			for _, a := range actual {
				if npm.TrustMatches(config, a) {
					matched = true
					break
				}
			}
			if matched {
				wr.Add(report.Action{Provider: "npm", Target: pkg, Setting: setting, Action: "unchanged"})
				continue
			}
			if err := client.AddTrust(ctx, pkg, config); err != nil {
				return fmt.Errorf("add %s on %s: %w", setting, pkg, err)
			}
			wr.Add(report.Action{Provider: "npm", Target: pkg, Setting: setting, Action: "created"})
		}
	}
	return nil
}

func githubClient(opts Options) (*github.Client, error) {
	if opts.GitHubToken == "" {
		return nil, errors.New("spec defines github settings but no GitHub token is set (use GH_TOKEN, GITHUB_TOKEN, --github-token, or `gh auth login`)")
	}
	client := github.NewClient(opts.GitHubToken)
	if opts.GitHubBaseURL != "" {
		client.BaseURL = opts.GitHubBaseURL
	}
	return client, nil
}

func npmClient(opts Options) (*npm.Client, error) {
	if opts.NPMToken == "" {
		return nil, errors.New("spec defines npm settings but no npm token is set (use NPM_TOKEN or --npm-token)")
	}
	client := npm.NewClient(opts.NPMToken, opts.NPMOTP)
	client.OnOTPRequired = opts.NPMOTPPrompt
	if opts.NPMRegistry != "" {
		client.Registry = opts.NPMRegistry
	}
	return client, nil
}

// githubTargets is the resolved set of repositories and the rulesets to apply
// to each.
type githubTargets struct {
	repos  []string
	byRepo map[string]map[string]map[string]any // repo -> ruleset name -> ruleset
}

func resolveGitHub(ctx context.Context, client *github.Client, groups []spec.GitHubGroup) (*githubTargets, error) {
	byRepo := map[string]map[string]map[string]any{}
	var order []string

	for _, g := range groups {
		repos, err := resolveGitHubTargets(ctx, client, g.IncludeRepos)
		if err != nil {
			return nil, err
		}
		rulesets, err := decodeObjects(g.Rulesets)
		if err != nil {
			return nil, fmt.Errorf("github rulesets: %w", err)
		}
		for _, repo := range repos {
			if _, ok := byRepo[repo]; !ok {
				byRepo[repo] = map[string]map[string]any{}
				order = append(order, repo)
			}
			for _, rs := range rulesets {
				name, _ := rs["name"].(string)
				if existing, ok := byRepo[repo][name]; ok {
					if canonical(existing) != canonical(rs) {
						return nil, fmt.Errorf("conflicting definitions for ruleset %q on %s", name, repo)
					}
					continue
				}
				byRepo[repo][name] = rs
			}
		}
	}

	sort.Strings(order)
	return &githubTargets{repos: order, byRepo: byRepo}, nil
}

func resolveGitHubTargets(ctx context.Context, client *github.Client, patterns []string) ([]string, error) {
	found := map[string]bool{}
	for _, raw := range patterns {
		p, err := matcher.ParseGitHub(raw)
		if err != nil {
			return nil, err
		}
		if !p.Wildcard {
			found[p.Raw] = true
			continue
		}
		repos, err := client.ListOrgRepos(ctx, p.Namespace)
		if err != nil {
			return nil, fmt.Errorf("list repos for %s: %w", p.Namespace, err)
		}
		for _, r := range repos {
			if p.Match(r) {
				found[r] = true
			}
		}
	}
	return sortedKeys(found), nil
}

// npmTargets is the resolved set of packages and the trust configurations to
// apply to each.
type npmTargets struct {
	pkgs  []string
	byPkg map[string][]map[string]any
}

func resolveNPM(ctx context.Context, client *npm.Client, groups []spec.NPMGroup) (*npmTargets, error) {
	byPkg := map[string][]map[string]any{}
	var order []string

	for _, g := range groups {
		pkgs, err := resolveNPMTargets(ctx, client, g.IncludePackages)
		if err != nil {
			return nil, err
		}
		trust, err := decodeObjects(g.Trust)
		if err != nil {
			return nil, fmt.Errorf("npm trust: %w", err)
		}
		for _, pkg := range pkgs {
			if _, ok := byPkg[pkg]; !ok {
				order = append(order, pkg)
			}
			byPkg[pkg] = appendUnique(byPkg[pkg], trust)
		}
	}

	sort.Strings(order)
	return &npmTargets{pkgs: order, byPkg: byPkg}, nil
}

func resolveNPMTargets(ctx context.Context, client *npm.Client, patterns []string) ([]string, error) {
	found := map[string]bool{}
	for _, raw := range patterns {
		p, err := matcher.ParseNPM(raw)
		if err != nil {
			return nil, err
		}
		if !p.Wildcard {
			found[p.Raw] = true
			continue
		}
		scope := strings.TrimPrefix(p.Namespace, "@")
		names, err := client.SearchScope(ctx, scope)
		if err != nil {
			return nil, fmt.Errorf("search scope %s: %w", p.Namespace, err)
		}
		for _, n := range names {
			if p.Match(n) {
				found[n] = true
			}
		}
	}
	return sortedKeys(found), nil
}

// defaultRepoFor returns the "owner/repo" to use for trust configs that omit
// claims.repository. It is only fetched when at least one config needs it.
func defaultRepoFor(ctx context.Context, client *npm.Client, pkg string, desired []map[string]any) (string, error) {
	if !needsDefaultRepo(desired) {
		return "", nil
	}
	repo, err := client.PackageRepo(ctx, pkg)
	if err != nil {
		return "", fmt.Errorf("read package.json for %s: %w", pkg, err)
	}
	return repo, nil
}

func needsDefaultRepo(desired []map[string]any) bool {
	for _, d := range desired {
		claims, _ := d["claims"].(map[string]any)
		if _, ok := claims["repository"]; !ok {
			return true
		}
	}
	return false
}

func decodeObjects(raw []json.RawMessage) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(raw))
	for i, r := range raw {
		dec := json.NewDecoder(bytes.NewReader(r))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// appendUnique appends entries from add that are not already present, comparing
// by canonical JSON.
func appendUnique(dst, add []map[string]any) []map[string]any {
	seen := make(map[string]bool, len(dst))
	for _, d := range dst {
		seen[canonical(d)] = true
	}
	for _, a := range add {
		key := canonical(a)
		if seen[key] {
			continue
		}
		seen[key] = true
		dst = append(dst, a)
	}
	return dst
}

func canonical(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Sprint(m)
	}
	return string(b)
}

func mapValues(m map[string]map[string]any) []map[string]any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Package engine resolves spec targets against live services and produces a
// report of every setting that does not match.
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
		if opts.GitHubToken == "" {
			return nil, errors.New("spec defines github settings but no GitHub token is set (use GH_TOKEN, GITHUB_TOKEN, or --github-token)")
		}
		client := github.NewClient(opts.GitHubToken)
		if opts.GitHubBaseURL != "" {
			client.BaseURL = opts.GitHubBaseURL
		}
		if err := runGitHub(ctx, client, s.GitHub, rep); err != nil {
			return nil, err
		}
	}

	if len(s.NPM) > 0 {
		if opts.NPMToken == "" {
			return nil, errors.New("spec defines npm settings but no npm token is set (use NPM_TOKEN or --npm-token)")
		}
		client := npm.NewClient(opts.NPMToken, opts.NPMOTP)
		client.OnOTPRequired = opts.NPMOTPPrompt
		if opts.NPMRegistry != "" {
			client.Registry = opts.NPMRegistry
		}
		if err := runNPM(ctx, client, s.NPM, rep); err != nil {
			return nil, err
		}
	}

	return rep, nil
}

func runGitHub(ctx context.Context, client *github.Client, groups []spec.GitHubGroup, rep *report.Report) error {
	desired := map[string]map[string]map[string]any{}
	var order []string

	for _, g := range groups {
		repos, err := resolveGitHubTargets(ctx, client, g.IncludeRepos)
		if err != nil {
			return err
		}
		rulesets, err := decodeObjects(g.Rulesets)
		if err != nil {
			return fmt.Errorf("github rulesets: %w", err)
		}
		for _, repo := range repos {
			if _, ok := desired[repo]; !ok {
				desired[repo] = map[string]map[string]any{}
				order = append(order, repo)
			}
			for _, rs := range rulesets {
				name, _ := rs["name"].(string)
				if existing, ok := desired[repo][name]; ok {
					if canonical(existing) != canonical(rs) {
						return fmt.Errorf("conflicting definitions for ruleset %q on %s", name, repo)
					}
					continue
				}
				desired[repo][name] = rs
			}
		}
	}

	sort.Strings(order)
	for _, repo := range order {
		owner, name, ok := strings.Cut(repo, "/")
		if !ok {
			return fmt.Errorf("invalid repository %q", repo)
		}
		actual, err := client.ListRulesets(ctx, owner, name)
		if err != nil {
			return fmt.Errorf("list rulesets for %s: %w", repo, err)
		}
		rep.TargetsScanned++
		rep.Add(github.DiffRulesets(repo, mapValues(desired[repo]), actual)...)
	}
	return nil
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

func runNPM(ctx context.Context, client *npm.Client, groups []spec.NPMGroup, rep *report.Report) error {
	desired := map[string][]map[string]any{}
	var order []string

	for _, g := range groups {
		pkgs, err := resolveNPMTargets(ctx, client, g.IncludePackages)
		if err != nil {
			return err
		}
		trust, err := decodeObjects(g.Trust)
		if err != nil {
			return fmt.Errorf("npm trust: %w", err)
		}
		for _, pkg := range pkgs {
			if _, ok := desired[pkg]; !ok {
				order = append(order, pkg)
			}
			desired[pkg] = appendUnique(desired[pkg], trust)
		}
	}

	sort.Strings(order)
	for _, pkg := range order {
		actual, err := client.ListTrust(ctx, pkg)
		if err != nil {
			return fmt.Errorf("list trust for %s: %w", pkg, err)
		}
		defaultRepo := ""
		if needsDefaultRepo(desired[pkg]) {
			defaultRepo, err = client.PackageRepo(ctx, pkg)
			if err != nil {
				return fmt.Errorf("read package.json for %s: %w", pkg, err)
			}
		}
		rep.TargetsScanned++
		rep.Add(npm.DiffTrust(pkg, desired[pkg], actual, defaultRepo)...)
	}
	return nil
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

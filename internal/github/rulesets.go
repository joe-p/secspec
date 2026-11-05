package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// Ruleset is a repository ruleset as returned by the GitHub API.
type Ruleset struct {
	ID         int64
	Name       string
	SourceType string
	Raw        map[string]any
}

// ListOrgRepos returns the full names ("owner/repo") of every repository in an
// organization, following pagination.
func (c *Client) ListOrgRepos(ctx context.Context, org string) ([]string, error) {
	var all []string
	for page := 1; ; page++ {
		var repos []struct {
			FullName string `json:"full_name"`
		}
		q := url.Values{
			"per_page": {"100"},
			"page":     {strconv.Itoa(page)},
		}
		if err := c.get(ctx, "/orgs/"+url.PathEscape(org)+"/repos", q, &repos); err != nil {
			return nil, err
		}
		if len(repos) == 0 {
			break
		}
		for _, r := range repos {
			if r.FullName != "" {
				all = append(all, r.FullName)
			}
		}
		if len(repos) < 100 {
			break
		}
	}
	return all, nil
}

// ListRulesets returns every ruleset visible on a repository. The list
// endpoint only returns summaries, so each ruleset's details are fetched to
// populate conditions and rules.
func (c *Client) ListRulesets(ctx context.Context, owner, repo string) ([]Ruleset, error) {
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/rulesets"
	var raw []map[string]any
	if err := c.get(ctx, path, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]Ruleset, 0, len(raw))
	for _, m := range raw {
		rs := newRuleset(m)
		// Some list responses may already include full details, so only fetch
		// when the summary is missing what the comparison needs.
		if rs.ID != 0 && (!hasKey(m, "conditions") || !hasKey(m, "rules")) {
			detail, err := c.GetRuleset(ctx, owner, repo, rs.ID)
			if err != nil {
				return nil, err
			}
			rs = detail
		}
		out = append(out, rs)
	}
	return out, nil
}

// GetRuleset returns a repository ruleset by id, including its conditions and
// rules.
func (c *Client) GetRuleset(ctx context.Context, owner, repo string, id int64) (Ruleset, error) {
	path := fmt.Sprintf("/repos/%s/%s/rulesets/%d", url.PathEscape(owner), url.PathEscape(repo), id)
	var raw map[string]any
	if err := c.get(ctx, path, nil, &raw); err != nil {
		return Ruleset{}, err
	}
	return newRuleset(raw), nil
}

func newRuleset(m map[string]any) Ruleset {
	rs := Ruleset{Raw: m}
	if n, ok := m["name"].(string); ok {
		rs.Name = n
	}
	if s, ok := m["source_type"].(string); ok {
		rs.SourceType = s
	}
	if id, ok := m["id"].(json.Number); ok {
		if v, err := id.Int64(); err == nil {
			rs.ID = v
		}
	}
	return rs
}

func hasKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}

// CreateRuleset creates a repository ruleset from the given body.
func (c *Client) CreateRuleset(ctx context.Context, owner, repo string, body map[string]any) error {
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/rulesets"
	return c.do(ctx, http.MethodPost, path, nil, body, nil)
}

// UpdateRuleset replaces a repository ruleset by id with the given body.
func (c *Client) UpdateRuleset(ctx context.Context, owner, repo string, id int64, body map[string]any) error {
	path := fmt.Sprintf("/repos/%s/%s/rulesets/%d", url.PathEscape(owner), url.PathEscape(repo), id)
	return c.do(ctx, http.MethodPut, path, nil, body, nil)
}

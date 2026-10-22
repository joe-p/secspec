package npm

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// SearchScope returns the names of every package the registry search index
// associates with a scope (for example "@my-scope"). The scope is passed
// without its leading "@".
func (c *Client) SearchScope(ctx context.Context, scope string) ([]string, error) {
	text := "scope:" + scope
	var names []string
	from := 0
	const size = 250
	for {
		q := url.Values{
			"text": {text},
			"size": {strconv.Itoa(size)},
			"from": {strconv.Itoa(from)},
		}
		var resp struct {
			Objects []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
			} `json:"objects"`
			Total int `json:"total"`
		}
		if err := c.get(ctx, "/-/v1/search?"+q.Encode(), &resp); err != nil {
			return nil, err
		}
		for _, o := range resp.Objects {
			if o.Package.Name != "" {
				names = append(names, o.Package.Name)
			}
		}
		from += len(resp.Objects)
		if len(resp.Objects) == 0 || from >= resp.Total {
			break
		}
	}
	return names, nil
}

// ListTrust returns the trusted publisher configurations for a package.
func (c *Client) ListTrust(ctx context.Context, pkg string) ([]map[string]any, error) {
	var out []map[string]any
	if err := c.get(ctx, "/-/package/"+escapePackage(pkg)+"/trust", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PackageRepo returns the "owner/repo" repository for a package, read from its
// packument (the package.json repository field). It returns an empty string
// when the package has no usable repository URL.
func (c *Client) PackageRepo(ctx context.Context, pkg string) (string, error) {
	var pack map[string]any
	if err := c.get(ctx, "/"+escapePackage(pkg), &pack); err != nil {
		return "", err
	}
	return normalizeRepoURL(repositoryURL(pack)), nil
}

func repositoryURL(pack map[string]any) string {
	if u, ok := repoURLFrom(pack["repository"]); ok {
		return u
	}
	if distTags, ok := pack["dist-tags"].(map[string]any); ok {
		if latest, ok := distTags["latest"].(string); ok {
			if versions, ok := pack["versions"].(map[string]any); ok {
				if v, ok := versions[latest].(map[string]any); ok {
					if u, ok := repoURLFrom(v["repository"]); ok {
						return u
					}
				}
			}
		}
	}
	return ""
}

func repoURLFrom(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, t != ""
	case map[string]any:
		if u, ok := t["url"].(string); ok && u != "" {
			return u, true
		}
	}
	return "", false
}

// normalizeRepoURL reduces a repository URL to "owner/repo". It understands the
// common forms found in package.json: "owner/repo", "github:owner/repo",
// "git+https://github.com/owner/repo.git", "git@github.com:owner/repo.git".
func normalizeRepoURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "git+")
	if strings.HasPrefix(s, "github:") {
		s = strings.TrimPrefix(s, "github:")
	}
	if strings.HasPrefix(s, "git@") {
		s = strings.TrimPrefix(s, "git@")
		if i := strings.Index(s, ":"); i >= 0 {
			s = s[:i] + "/" + s[i+1:]
		}
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		if slash := strings.Index(s, "/"); slash < 0 || i < slash {
			s = s[i+1:]
		}
	}
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimSuffix(s, "/")

	parts := make([]string, 0, 3)
	for _, p := range strings.Split(s, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2] + "/" + parts[len(parts)-1]
}

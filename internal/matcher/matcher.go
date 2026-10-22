// Package matcher parses and matches the include patterns used in a sec spec.
//
// Patterns are always "namespace/name" where the namespace (a GitHub org or an
// npm scope) must be fully specified and only the name may contain "*".
package matcher

import (
	"fmt"
	"strings"
)

// Pattern is a parsed include pattern.
type Pattern struct {
	Raw       string // the original pattern, e.g. "my-org/*"
	Namespace string // org or @scope, always literal
	Name      string // repository or package name, may contain "*"
	Wildcard  bool   // whether Name contains "*"
}

// ParseGitHub parses an "owner/repo" pattern. The owner must be literal.
func ParseGitHub(raw string) (Pattern, error) {
	return parse(raw, "github include_repos", false)
}

// ParseNPM parses an "@scope/package" pattern. The scope must be literal.
func ParseNPM(raw string) (Pattern, error) {
	return parse(raw, "npm include_packages", true)
}

func parse(raw, what string, requireScope bool) (Pattern, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Pattern{}, fmt.Errorf("%s: empty pattern", what)
	}
	ns, name, ok := strings.Cut(trimmed, "/")
	if !ok || ns == "" || name == "" {
		return Pattern{}, fmt.Errorf("%s: %q must be in namespace/name form", what, raw)
	}
	if strings.Contains(name, "/") {
		return Pattern{}, fmt.Errorf("%s: %q must contain exactly one %q", what, raw, "/")
	}
	if strings.Contains(ns, "*") {
		return Pattern{}, fmt.Errorf("%s: %q must fully specify the namespace (no %q before %q)", what, raw, "*", "/")
	}
	if requireScope && !strings.HasPrefix(ns, "@") {
		return Pattern{}, fmt.Errorf("%s: %q must use a scope (start with %q)", what, raw, "@")
	}
	if !requireScope && strings.HasPrefix(ns, "@") {
		return Pattern{}, fmt.Errorf("%s: %q must not start with %q", what, raw, "@")
	}
	return Pattern{
		Raw:       trimmed,
		Namespace: ns,
		Name:      name,
		Wildcard:  strings.Contains(name, "*"),
	}, nil
}

// Match reports whether the fully qualified name (for example "my-org/repo" or
// "@scope/pkg") matches the pattern. Names must contain exactly one "/".
func (p Pattern) Match(full string) bool {
	ns, name, ok := strings.Cut(full, "/")
	if !ok || strings.Contains(name, "/") {
		return false
	}
	if ns != p.Namespace {
		return false
	}
	return wildcardMatch(p.Name, name)
}

// wildcardMatch matches s against pattern where "*" matches any run of
// characters (including none). Only "*" is treated as a metacharacter.
func wildcardMatch(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		idx := strings.Index(s, part)
		if idx < 0 {
			return false
		}
		s = s[idx+len(part):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}

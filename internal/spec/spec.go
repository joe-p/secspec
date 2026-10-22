// Package spec defines the sec spec document and loads it from disk.
package spec

import "encoding/json"

// Spec is the top-level secspec document.
type Spec struct {
	GitHub []GitHubGroup `json:"github"`
	NPM    []NPMGroup    `json:"npm"`
}

// GitHubGroup applies a set of rulesets to a set of repositories.
type GitHubGroup struct {
	IncludeRepos []string          `json:"include_repos"`
	Rulesets     []json.RawMessage `json:"rulesets"`
}

// NPMGroup applies a set of trusted publisher configurations to a set of
// packages.
type NPMGroup struct {
	IncludePackages []string          `json:"include_packages"`
	Trust           []json.RawMessage `json:"trust"`
}

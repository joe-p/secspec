package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/joe-p/secspec/internal/matcher"
)

// Load reads and validates a sec spec from path.
func Load(path string) (*Spec, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var s Spec
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// Validate checks that the spec is well-formed.
func (s *Spec) Validate() error {
	if len(s.GitHub) == 0 && len(s.NPM) == 0 {
		return errors.New("spec defines no github or npm settings")
	}
	for i, g := range s.GitHub {
		if len(g.IncludeRepos) == 0 {
			return fmt.Errorf("github[%d]: include_repos is required", i)
		}
		for _, p := range g.IncludeRepos {
			if _, err := matcher.ParseGitHub(p); err != nil {
				return fmt.Errorf("github[%d]: %w", i, err)
			}
		}
		if len(g.Rulesets) == 0 {
			return fmt.Errorf("github[%d]: rulesets is required", i)
		}
		for j, raw := range g.Rulesets {
			m, err := decodeObject(raw)
			if err != nil {
				return fmt.Errorf("github[%d].rulesets[%d]: %w", i, j, err)
			}
			if name, _ := m["name"].(string); name == "" {
				return fmt.Errorf("github[%d].rulesets[%d]: name is required", i, j)
			}
		}
	}
	for i, g := range s.NPM {
		if len(g.IncludePackages) == 0 {
			return fmt.Errorf("npm[%d]: include_packages is required", i)
		}
		for _, p := range g.IncludePackages {
			if _, err := matcher.ParseNPM(p); err != nil {
				return fmt.Errorf("npm[%d]: %w", i, err)
			}
		}
		if len(g.Trust) == 0 {
			return fmt.Errorf("npm[%d]: trust is required", i)
		}
		for j, raw := range g.Trust {
			m, err := decodeObject(raw)
			if err != nil {
				return fmt.Errorf("npm[%d].trust[%d]: %w", i, j, err)
			}
			if typ, _ := m["type"].(string); typ == "" {
				return fmt.Errorf("npm[%d].trust[%d]: type is required", i, j)
			}
			if _, ok := m["claims"].(map[string]any); !ok {
				return fmt.Errorf("npm[%d].trust[%d]: claims is required", i, j)
			}
			if _, ok := m["permissions"].([]any); !ok {
				return fmt.Errorf("npm[%d].trust[%d]: permissions is required", i, j)
			}
		}
	}
	return nil
}

func decodeObject(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

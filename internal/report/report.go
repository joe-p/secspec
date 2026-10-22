// Package report collects and renders the differences found while comparing a
// sec spec against live service settings.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Change is a single setting that does not match the spec.
type Change struct {
	Provider string `json:"provider"`
	Target   string `json:"target"`
	Setting  string `json:"setting"`
	Path     string `json:"path,omitempty"`
	Expected any    `json:"expected,omitempty"`
	Actual   any    `json:"actual,omitempty"`
	Missing  bool   `json:"missing,omitempty"`
}

// Report is the result of a run.
type Report struct {
	Changes        []Change
	TargetsScanned int
}

// OK reports whether every scanned target matched the spec.
func (r *Report) OK() bool { return len(r.Changes) == 0 }

// Add appends changes to the report.
func (r *Report) Add(changes ...Change) { r.Changes = append(r.Changes, changes...) }

// WriteText renders the report in a human-readable form.
func (r *Report) WriteText(w io.Writer) {
	changes := r.sorted()
	for _, c := range changes {
		fmt.Fprintf(w, "MISMATCH %s %s  %s\n", c.Provider, c.Target, c.Setting)
		if c.Path != "" {
			fmt.Fprintf(w, "  %s\n", c.Path)
		}
		if c.Missing {
			fmt.Fprintf(w, "    missing: %s\n", jsonish(c.Expected))
		} else {
			fmt.Fprintf(w, "    expected: %s\n", jsonish(c.Expected))
			fmt.Fprintf(w, "    actual:   %s\n", jsonish(c.Actual))
		}
	}
	if len(changes) == 0 {
		fmt.Fprintf(w, "OK: %d target(s) match the spec\n", r.TargetsScanned)
		return
	}
	fmt.Fprintf(w, "\n%d mismatch(es) across %d target(s)\n", len(changes), countTargets(changes))
}

// WriteJSON renders the report as JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	changes := r.sorted()
	if changes == nil {
		changes = []Change{}
	}
	payload := struct {
		OK             bool     `json:"ok"`
		TargetsScanned int      `json:"targets_scanned"`
		Mismatches     []Change `json:"mismatches"`
	}{
		OK:             r.OK(),
		TargetsScanned: r.TargetsScanned,
		Mismatches:     changes,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func (r *Report) sorted() []Change {
	out := make([]Change, len(r.Changes))
	copy(out, r.Changes)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.Setting != b.Setting {
			return a.Setting < b.Setting
		}
		return a.Path < b.Path
	})
	return out
}

func countTargets(changes []Change) int {
	seen := map[string]bool{}
	for _, c := range changes {
		seen[c.Provider+"\x00"+c.Target] = true
	}
	return len(seen)
}

func jsonish(v any) string {
	if v == nil {
		return "null"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

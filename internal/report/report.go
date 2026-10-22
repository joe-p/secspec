// Package report collects and renders the differences found while comparing a
// sec spec against live service settings.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
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

// Action records what write did to a single setting.
type Action struct {
	Provider string `json:"provider"`
	Target   string `json:"target"`
	Setting  string `json:"setting"`
	Action   string `json:"action"` // created, updated, or unchanged
}

// WriteReport is the result of a write run.
type WriteReport struct {
	Actions []Action
}

// Add appends actions to the report.
func (r *WriteReport) Add(actions ...Action) { r.Actions = append(r.Actions, actions...) }

// Counts returns the number of created, updated, and unchanged settings.
func (r *WriteReport) Counts() (created, updated, unchanged int) {
	for _, a := range r.Actions {
		switch a.Action {
		case "created":
			created++
		case "updated":
			updated++
		case "unchanged":
			unchanged++
		}
	}
	return created, updated, unchanged
}

// WriteText renders the report in a human-readable form. Only changes are
// listed; unchanged settings are summarised.
func (r *WriteReport) WriteText(w io.Writer) {
	actions := r.sortedActions()
	for _, a := range actions {
		if a.Action == "unchanged" {
			continue
		}
		fmt.Fprintf(w, "%s %s %s  %s\n", strings.ToUpper(a.Action), a.Provider, a.Target, a.Setting)
	}
	created, updated, unchanged := r.Counts()
	if created == 0 && updated == 0 {
		fmt.Fprintf(w, "no changes (%d unchanged)\n", unchanged)
		return
	}
	fmt.Fprintf(w, "\n%d created, %d updated, %d unchanged\n", created, updated, unchanged)
}

// WriteJSON renders the report as JSON.
func (r *WriteReport) WriteJSON(w io.Writer) error {
	actions := r.sortedActions()
	if actions == nil {
		actions = []Action{}
	}
	created, updated, unchanged := r.Counts()
	payload := struct {
		Created   int      `json:"created"`
		Updated   int      `json:"updated"`
		Unchanged int      `json:"unchanged"`
		Actions   []Action `json:"actions"`
	}{
		Created:   created,
		Updated:   updated,
		Unchanged: unchanged,
		Actions:   actions,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func (r *WriteReport) sortedActions() []Action {
	out := make([]Action, len(r.Actions))
	copy(out, r.Actions)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Setting < b.Setting
	})
	return out
}

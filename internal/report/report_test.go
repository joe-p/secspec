package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteTextOK(t *testing.T) {
	rep := &Report{TargetsScanned: 3}
	var buf bytes.Buffer
	rep.WriteText(&buf)
	if !strings.Contains(buf.String(), "OK: 3 target(s)") {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}

func TestWriteTextMismatch(t *testing.T) {
	rep := &Report{TargetsScanned: 1}
	rep.Add(Change{Provider: "github", Target: "my-org/repo", Setting: `ruleset "protect main"`, Path: "rules.x", Expected: 0, Actual: 1})
	var buf bytes.Buffer
	rep.WriteText(&buf)
	out := buf.String()
	for _, want := range []string{"MISMATCH github my-org/repo", "ruleset", "expected: 0", "actual:   1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q missing %q", out, want)
		}
	}
}

func TestWriteReportText(t *testing.T) {
	wr := &WriteReport{}
	wr.Add(
		Action{Provider: "github", Target: "o/r", Setting: `ruleset "x"`, Action: "created"},
		Action{Provider: "github", Target: "o/r", Setting: `ruleset "y"`, Action: "updated"},
		Action{Provider: "github", Target: "o/r", Setting: `ruleset "z"`, Action: "unchanged"},
	)
	var buf bytes.Buffer
	wr.WriteText(&buf)
	out := buf.String()
	for _, want := range []string{"CREATED github o/r", "UPDATED github o/r", "1 created, 1 updated, 1 unchanged"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q missing %q", out, want)
		}
	}
	if strings.Contains(out, "UNCHANGED") {
		t.Fatalf("unchanged settings should be summarised, not listed: %q", out)
	}
}

func TestWriteReportNoChanges(t *testing.T) {
	wr := &WriteReport{}
	wr.Add(Action{Provider: "npm", Target: "@s/p", Setting: "trust[0] (github)", Action: "unchanged"})
	var buf bytes.Buffer
	wr.WriteText(&buf)
	if !strings.Contains(buf.String(), "no changes (1 unchanged)") {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}

func TestWriteReportJSON(t *testing.T) {
	wr := &WriteReport{}
	wr.Add(
		Action{Provider: "npm", Target: "@s/p", Setting: "trust[0] (github)", Action: "created"},
		Action{Provider: "npm", Target: "@s/p", Setting: "trust[1] (github)", Action: "unchanged"},
	)
	var buf bytes.Buffer
	if err := wr.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Created   int      `json:"created"`
		Updated   int      `json:"updated"`
		Unchanged int      `json:"unchanged"`
		Actions   []Action `json:"actions"`
	}
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if payload.Created != 1 || payload.Unchanged != 1 || len(payload.Actions) != 2 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

func TestWriteJSON(t *testing.T) {
	rep := &Report{TargetsScanned: 1}
	rep.Add(Change{Provider: "npm", Target: "@scope/pkg", Setting: "trust[0] (github)", Missing: true, Expected: map[string]any{"type": "github"}})
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		OK             bool     `json:"ok"`
		TargetsScanned int      `json:"targets_scanned"`
		Mismatches     []Change `json:"mismatches"`
	}
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if payload.OK || len(payload.Mismatches) != 1 || payload.TargetsScanned != 1 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

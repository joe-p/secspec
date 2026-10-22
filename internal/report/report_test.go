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

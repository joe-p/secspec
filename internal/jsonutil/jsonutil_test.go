package jsonutil

import (
	"bytes"
	"encoding/json"
	"testing"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return v
}

func TestSubsetMap(t *testing.T) {
	desired := decode(t, `{"a":1,"nested":{"x":true}}`)
	actual := decode(t, `{"a":1,"nested":{"x":true,"y":2},"extra":"ignored"}`)
	if diffs := SubsetDiff(desired, actual); len(diffs) != 0 {
		t.Fatalf("expected no diffs, got %+v", diffs)
	}
}

func TestSubsetMismatch(t *testing.T) {
	desired := decode(t, `{"a":2}`)
	actual := decode(t, `{"a":1}`)
	diffs := SubsetDiff(desired, actual)
	if len(diffs) != 1 || diffs[0].Path != "a" {
		t.Fatalf("expected one diff at a, got %+v", diffs)
	}
}

func TestSubsetMissingKey(t *testing.T) {
	desired := decode(t, `{"a":1}`)
	actual := decode(t, `{}`)
	diffs := SubsetDiff(desired, actual)
	if len(diffs) != 1 || !diffs[0].Missing || diffs[0].Path != "a" {
		t.Fatalf("expected missing diff at a, got %+v", diffs)
	}
}

func TestNumberEquality(t *testing.T) {
	if diffs := SubsetDiff(decode(t, `{"a":0}`), decode(t, `{"a":0.0}`)); len(diffs) != 0 {
		t.Fatalf("expected numeric equality, got %+v", diffs)
	}
}

func TestTypeArrayMatchesByType(t *testing.T) {
	desired := decode(t, `{"rules":[{"type":"deletion"},{"type":"pull_request","parameters":{"count":0}}]}`)
	actual := decode(t, `{"rules":[{"type":"deletion"},{"type":"pull_request","parameters":{"count":1,"other":true}},{"type":"non_fast_forward"}]}`)
	diffs := SubsetDiff(desired, actual)
	if len(diffs) != 1 {
		t.Fatalf("expected one diff, got %+v", diffs)
	}
	if diffs[0].Path != "rules[type=pull_request].parameters.count" {
		t.Fatalf("unexpected path %q", diffs[0].Path)
	}
}

func TestTypeArrayMissingRule(t *testing.T) {
	desired := decode(t, `{"rules":[{"type":"required_signatures"}]}`)
	actual := decode(t, `{"rules":[{"type":"deletion"}]}`)
	diffs := SubsetDiff(desired, actual)
	if len(diffs) != 1 || !diffs[0].Missing || diffs[0].Path != "rules[type=required_signatures]" {
		t.Fatalf("expected missing rule diff, got %+v", diffs)
	}
}

func TestExactArraySet(t *testing.T) {
	desired := decode(t, `{"permissions":["a","b"]}`)
	actual := decode(t, `{"permissions":["b","a","c"]}`)
	diffs := SubsetDiff(desired, actual)
	if len(diffs) != 1 || diffs[0].Missing {
		t.Fatalf("expected one extra-element diff, got %+v", diffs)
	}
	if diffs[0].Path != "permissions[2]" {
		t.Fatalf("unexpected path %q", diffs[0].Path)
	}
}

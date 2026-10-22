// Package jsonutil compares decoded JSON documents (map[string]any trees with
// json.Number leaves) using subset semantics.
//
// A desired document is considered a subset of an actual document when every
// field the desired document specifies is present and equal in the actual
// document. Extra fields in the actual document are ignored. This mirrors how
// service APIs return server-populated fields (ids, timestamps, defaults) that
// a spec never mentions.
//
// Arrays get special treatment:
//
//   - Arrays whose elements are all objects carrying a string "type" field
//     (for example GitHub ruleset rules) are matched by "type". Each desired
//     element must have a matching actual element, and extra actual elements
//     are ignored.
//   - Every other array is compared as an unordered exact set. Extra elements
//     on either side are reported.
package jsonutil

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// Diff describes a single difference that prevents a desired value from
// matching the actual value.
type Diff struct {
	Path     string
	Expected any
	Actual   any
	Missing  bool
}

// SubsetDiff returns the differences that prevent desired from being a subset
// of actual. An empty result means desired matches.
func SubsetDiff(desired, actual any) []Diff {
	return subsetDiff(desired, actual, "")
}

func subsetDiff(desired, actual any, path string) []Diff {
	switch d := desired.(type) {
	case map[string]any:
		a, ok := actual.(map[string]any)
		if !ok {
			return []Diff{{Path: path, Expected: desired, Actual: actual}}
		}
		var out []Diff
		for _, k := range sortedKeys(d) {
			p := join(path, k)
			av, ok := a[k]
			if !ok {
				out = append(out, Diff{Path: p, Expected: d[k], Missing: true})
				continue
			}
			out = append(out, subsetDiff(d[k], av, p)...)
		}
		return out
	case []any:
		a, ok := actual.([]any)
		if !ok {
			return []Diff{{Path: path, Expected: desired, Actual: actual}}
		}
		if isTypeArray(d) && isTypeArray(a) {
			return typeArrayDiff(d, a, path)
		}
		return exactArrayDiff(d, a, path)
	default:
		if !scalarEqual(desired, actual) {
			return []Diff{{Path: path, Expected: desired, Actual: actual}}
		}
		return nil
	}
}

// typeArrayDiff matches arrays of objects by their "type" discriminator.
func typeArrayDiff(desired, actual []any, path string) []Diff {
	var out []Diff
	for _, d := range desired {
		dm, _ := d.(map[string]any)
		dt, _ := dm["type"].(string)

		var match map[string]any
		for _, a := range actual {
			am, _ := a.(map[string]any)
			if at, _ := am["type"].(string); at == dt {
				match = am
				break
			}
		}
		elemPath := path + "[type=" + dt + "]"
		if match == nil {
			out = append(out, Diff{Path: elemPath, Expected: d, Missing: true})
			continue
		}
		out = append(out, subsetDiff(d, match, elemPath)...)
	}
	return out
}

// exactArrayDiff compares arrays as unordered exact sets.
func exactArrayDiff(desired, actual []any, path string) []Diff {
	matchedActual := make([]bool, len(actual))
	matchedDesired := make([]bool, len(desired))
	for i, d := range desired {
		for j, a := range actual {
			if matchedActual[j] {
				continue
			}
			if equal(d, a) {
				matchedActual[j] = true
				matchedDesired[i] = true
				break
			}
		}
	}
	var out []Diff
	for i, d := range desired {
		if !matchedDesired[i] {
			out = append(out, Diff{Path: elem(path, i), Expected: d, Missing: true})
		}
	}
	for j, a := range actual {
		if !matchedActual[j] {
			out = append(out, Diff{Path: elem(path, j), Actual: a})
		}
	}
	return out
}

// equal reports deep equality, ignoring array order and comparing numbers by
// value rather than by literal representation.
func equal(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			bvv, ok := bv[k]
			if !ok || !equal(v, bvv) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		used := make([]bool, len(bv))
		for _, x := range av {
			found := false
			for i, y := range bv {
				if !used[i] && equal(x, y) {
					used[i] = true
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	default:
		return scalarEqual(a, b)
	}
}

func scalarEqual(a, b any) bool {
	an, aok := a.(json.Number)
	bn, bok := b.(json.Number)
	if aok && bok {
		af, err1 := an.Float64()
		bf, err2 := bn.Float64()
		if err1 == nil && err2 == nil {
			return af == bf
		}
		return an.String() == bn.String()
	}
	return reflect.DeepEqual(a, b)
}

func isTypeArray(v []any) bool {
	if len(v) == 0 {
		return false
	}
	for _, e := range v {
		m, ok := e.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := m["type"].(string); !ok {
			return false
		}
	}
	return true
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func elem(path string, i int) string {
	return fmt.Sprintf("%s[%d]", path, i)
}

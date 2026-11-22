// Package util provides small shared helpers: JSON path extraction and
// safe JSON decoding used across parsing, verification and evidence.
package util

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// GetPath resolves a dot-separated path in decoded JSON: "user.id",
// "data.items.0.id" (numeric segments are array indices). Returns
// (value, true) when the path resolves.
func GetPath(v any, path string) (any, bool) {
	if path == "" {
		return v, true
	}
	cur := v
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			nv, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = nv
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// DecodeJSON decodes bytes into a generic value, tolerant of trailing data
// but strict about total garbage. Numbers decode as float64.
func DecodeJSON(b []byte) (any, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// DecodeJSONLoose attempts JSON decode; on failure returns nil (no error).
func DecodeJSONLoose(b []byte) any {
	v, err := DecodeJSON(b)
	if err != nil {
		return nil
	}
	return v
}

// FirstString renders a decoded scalar as a string.
func FirstString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return string(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return ""
	}
}

// WalkStrings yields every string value in a decoded JSON tree.
func WalkStrings(v any, fn func(path string, s string)) {
	var walk func(prefix string, node any)
	walk = func(prefix string, node any) {
		switch t := node.(type) {
		case map[string]any:
			for k, val := range t {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, val)
			}
		case []any:
			for i, val := range t {
				p := prefix + "." + strconv.Itoa(i)
				if prefix == "" {
					p = strconv.Itoa(i)
				}
				walk(p, val)
			}
		case string:
			fn(prefix, t)
		}
	}
	walk("", v)
}

// Clamp truncates a string to n bytes without splitting a UTF-8 rune.
func Clamp(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for i := 0; i < 4 && len(cut) > 0; i++ {
		if r := []rune(cut[len(cut)-1:]); len(r) > 0 && r[0] != 0xFFFD {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return cut + "…[truncated]"
}

package airlock

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CanonicalizeJSON produces an RFC 8785 (JCS) canonical form of a JSON string.
// Orders object keys lexicographically and normalizes number representations.
func CanonicalizeJSON(input string) (string, error) {
	var parsed interface{}
	if err := json.Unmarshal([]byte(input), &parsed); err != nil {
		return "", fmt.Errorf("canonicalize: invalid json: %w", err)
	}
	result, err := canonicalValue(parsed)
	if err != nil {
		return "", err
	}
	return result, nil
}

// HashCanonicalJSON computes the SHA-256 hex hash of the canonical JSON form.
func HashCanonicalJSON(input string) (string, error) {
	canonical, err := CanonicalizeJSON(input)
	if err != nil {
		return "", err
	}
	return SHA256Hex(canonical), nil
}

func canonicalValue(v interface{}) (string, error) {
	switch val := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case float64:
		return canonicalNumber(val), nil
	case string:
		// Use json.Marshal for proper escaping
		b, _ := json.Marshal(val)
		return string(b), nil
	case []interface{}:
		parts := make([]string, len(val))
		for i, elem := range val {
			s, err := canonicalValue(elem)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]interface{}:
		// Sort keys lexicographically (by Unicode code point)
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		parts := make([]string, len(keys))
		for i, k := range keys {
			keyJSON, _ := json.Marshal(k)
			valJSON, err := canonicalValue(val[k])
			if err != nil {
				return "", err
			}
			parts[i] = string(keyJSON) + ":" + valJSON
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		return "", fmt.Errorf("unsupported type: %T", v)
	}
}

func canonicalNumber(f float64) string {
	// RFC 8785: integers should not have decimal points
	if f == float64(int64(f)) && f >= -1e15 && f <= 1e15 {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'E', -1, 64)
}

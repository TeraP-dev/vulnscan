// Package semver compares semantic versions as used by Go modules.
package semver

import (
	"strconv"
	"strings"
)

type version struct {
	core [3]int
	pre  []string
}

// Compare returns -1, 0 or 1. A leading "v" and "+build" metadata are ignored.
// Strings that are not valid versions fall back to plain string comparison.
func Compare(a, b string) int {
	va, okA := parse(a)
	vb, okB := parse(b)
	if !okA || !okB {
		return strings.Compare(a, b)
	}
	for i := range va.core {
		if va.core[i] != vb.core[i] {
			return sign(va.core[i] - vb.core[i])
		}
	}
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return 0
	case len(va.pre) == 0:
		return 1 // a release is newer than its pre-releases
	case len(vb.pre) == 0:
		return -1
	}
	for i := 0; i < len(va.pre) && i < len(vb.pre); i++ {
		if c := cmpIdent(va.pre[i], vb.pre[i]); c != 0 {
			return c
		}
	}
	return sign(len(va.pre) - len(vb.pre))
}

func parse(s string) (version, bool) {
	s = strings.TrimPrefix(s, "v")
	s, _, _ = strings.Cut(s, "+")
	core, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(core, ".")
	if len(parts) > 3 {
		return version{}, false
	}
	var v version
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return version{}, false
		}
		v.core[i] = n
	}
	if hasPre {
		if pre == "" {
			return version{}, false
		}
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

// cmpIdent compares pre-release identifiers: numbers numerically, and before text.
func cmpIdent(a, b string) int {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		return sign(ai - bi)
	case aerr == nil:
		return -1
	case berr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

// Package debver compares Debian package versions using dpkg's rules.
package debver

import "strings"

// Compare returns -1, 0 or 1 as a is older than, equal to, or newer than b.
func Compare(a, b string) int {
	ea, ua, ra := split(a)
	eb, ub, rb := split(b)
	if c := cmpPart(ea, eb); c != 0 {
		return c
	}
	if c := cmpPart(ua, ub); c != 0 {
		return c
	}
	return cmpPart(ra, rb)
}

// split breaks "[epoch:]upstream[-revision]" into its parts.
func split(v string) (epoch, upstream, revision string) {
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, v = v[:i], v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		v, revision = v[:i], v[i+1:]
	}
	return epoch, v, revision
}

// cmpPart compares alternating non-digit and digit runs, as dpkg's verrevcmp does.
func cmpPart(a, b string) int {
	for len(a) > 0 || len(b) > 0 {
		for (len(a) > 0 && !isDigit(a[0])) || (len(b) > 0 && !isDigit(b[0])) {
			ac, bc := order(a), order(b)
			if ac != bc {
				if ac < bc {
					return -1
				}
				return 1
			}
			a, b = a[1:], b[1:]
		}
		for len(a) > 0 && a[0] == '0' {
			a = a[1:]
		}
		for len(b) > 0 && b[0] == '0' {
			b = b[1:]
		}
		diff := 0
		for len(a) > 0 && len(b) > 0 && isDigit(a[0]) && isDigit(b[0]) {
			if diff == 0 {
				diff = int(a[0]) - int(b[0])
			}
			a, b = a[1:], b[1:]
		}
		if len(a) > 0 && isDigit(a[0]) {
			return 1
		}
		if len(b) > 0 && isDigit(b[0]) {
			return -1
		}
		if diff != 0 {
			if diff < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}

// order is the sort weight of the first character: '~' sorts before everything,
// even the end of the string; letters sort before other characters.
func order(s string) int {
	if s == "" {
		return 0
	}
	c := s[0]
	switch {
	case isDigit(c):
		return 0
	case isLetter(c):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

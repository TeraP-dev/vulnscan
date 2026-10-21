package pep440

import (
	"regexp"
	"strconv"
	"strings"
)

var re = regexp.MustCompile(`(?i)^\s*v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d+)?)?` +
	`(?:(?:-(\d+))|(?:[-_.]?(post|rev|r)[-_.]?(\d+)?))?` +
	`(?:[-_.]?(dev)[-_.]?(\d+)?)?` +
	`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?\s*$`)

type version struct {
	epoch   int
	release []int
	pre     int // 0 none, 1 alpha, 2 beta, 3 rc
	preNum  int
	post    int // -1 = none
	dev     int // -1 = none
	local   []string
}

// Compare returns -1, 0 or 1 as a is older than, equal to, or newer than b.
// Strings that are not valid PEP 440 versions fall back to plain string comparison.
func Compare(a, b string) int {
	va, okA := parse(a)
	vb, okB := parse(b)
	if !okA || !okB {
		return strings.Compare(a, b)
	}
	if c := sign(va.epoch - vb.epoch); c != 0 {
		return c
	}
	n := len(va.release)
	if len(vb.release) > n {
		n = len(vb.release)
	}
	for i := 0; i < n; i++ { // missing segments count as 0, so 1.0 == 1.0.0
		if c := sign(at(va.release, i) - at(vb.release, i)); c != 0 {
			return c
		}
	}
	ak, an := va.preKey()
	bk, bn := vb.preKey()
	if c := sign(ak - bk); c != 0 {
		return c
	}
	if c := sign(an - bn); c != 0 {
		return c
	}
	if c := sign(va.post - vb.post); c != 0 { // no post (-1) sorts before any post release
		return c
	}
	if c := sign(va.devKey() - vb.devKey()); c != 0 {
		return c
	}
	return cmpLocal(va.local, vb.local)
}

func parse(s string) (version, bool) {
	m := re.FindStringSubmatch(s)
	if m == nil {
		return version{}, false
	}
	v := version{post: -1, dev: -1}
	if m[1] != "" {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return version{}, false
		}
		v.epoch = n
	}
	for _, part := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return version{}, false
		}
		v.release = append(v.release, n)
	}
	if m[3] != "" {
		switch strings.ToLower(m[3]) {
		case "alpha", "a":
			v.pre = 1
		case "beta", "b":
			v.pre = 2
		default:
			v.pre = 3
		}
		v.preNum = atoi(m[4])
	}
	switch {
	case m[5] != "":
		v.post = atoi(m[5])
	case m[6] != "":
		v.post = atoi(m[7])
	}
	if m[8] != "" {
		v.dev = atoi(m[9])
	}
	if m[10] != "" {
		v.local = strings.FieldsFunc(strings.ToLower(m[10]), func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		})
	}
	return v, true
}

// preKey orders: dev-only releases < alpha < beta < rc < final.
func (v version) preKey() (int, int) {
	switch {
	case v.pre == 0 && v.post < 0 && v.dev >= 0:
		return 0, 0
	case v.pre == 0:
		return 4, 0
	default:
		return v.pre, v.preNum
	}
}

// devKey makes a release without ".devN" sort after the same release with it.
func (v version) devKey() int {
	if v.dev < 0 {
		return 1 << 30
	}
	return v.dev
}

func cmpLocal(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return -1
	case len(b) == 0:
		return 1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := cmpSegment(a[i], b[i]); c != 0 {
			return c
		}
	}
	return sign(len(a) - len(b))
}

// cmpSegment: numeric segments compare numerically and sort after alphabetic ones.
func cmpSegment(a, b string) int {
	ai, aerr := strconv.Atoi(a)
	bi, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		return sign(ai - bi)
	case aerr == nil:
		return 1
	case berr == nil:
		return -1
	}
	return strings.Compare(a, b)
}

func at(s []int, i int) int {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// atoi treats an empty string as 0 (for example "1.0rc" means rc0).
func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
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

package osv

import (
	"regexp"
	"strings"
)

var pypiSeparators = regexp.MustCompile(`[-_.]+`)

// NormalizeName applies the ecosystem's package-name normalization (PEP 503 for PyPI).
func NormalizeName(ecosystem, name string) string {
	if ecosystem != "PyPI" {
		return name
	}
	return strings.ToLower(pypiSeparators.ReplaceAllString(name, "-"))
}

// FixedVersions lists fixed versions OSV reports for this source package in this ecosystem.
func (v *Vuln) FixedVersions(pkg, ecosystem string) []string {
	var out []string
	for _, a := range v.Affected {
		if NormalizeName(ecosystem, a.Package.Name) != NormalizeName(ecosystem, pkg) || a.Package.Ecosystem != ecosystem {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					out = append(out, e.Fixed)
				}
			}
		}
	}
	return out
}

// Score returns the highest CVSS base score found (v3 or v4), or -1 if none is available.
func (v *Vuln) Score() float64 {
	best := -1.0
	for _, s := range v.Severity {
		if sc, ok := baseScore(s.Type, s.Score); ok && sc > best {
			best = sc
		}
	}
	return best
}

// ScoreWithUpstream falls back to related records (e.g. DEBIAN-CVE-*) when v has no score.
func (v *Vuln) ScoreWithUpstream(all map[string]*Vuln) float64 {
	best := v.Score()
	if best >= 0 {
		return best
	}
	for _, id := range v.Upstream {
		if u, ok := all[id]; ok && u.Score() > best {
			best = u.Score()
		}
	}
	return best
}

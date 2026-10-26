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

// Score returns the highest CVSS base score found (v3 or v4). If there is none,
// it falls back to Ubuntu's own priority label. It returns -1 if neither exists.
func (v *Vuln) Score() float64 {
	best := -1.0
	for _, s := range v.Severity {
		if sc, ok := baseScore(s.Type, s.Score); ok && sc > best {
			best = sc
		}
	}
	if best >= 0 {
		return best
	}
	for _, s := range v.Severity {
		if s.Type != "Ubuntu" {
			continue
		}
		if sc, ok := ubuntuPriority(s.Score); ok && sc > best {
			best = sc
		}
	}
	return best
}

// ubuntuPriority maps Ubuntu's priority label to the lowest score of the
// equivalent CVSS band, so the severity label matches the priority.
func ubuntuPriority(label string) (float64, bool) {
	switch strings.ToLower(label) {
	case "critical":
		return 9.0, true
	case "high":
		return 7.0, true
	case "medium":
		return 4.0, true
	case "low", "negligible":
		return 0.1, true
	}
	return 0, false
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

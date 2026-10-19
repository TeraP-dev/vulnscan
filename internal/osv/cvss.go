package osv

import (
	"math"
	"strings"

	cvss40 "github.com/pandatix/go-cvss/40"
)

func cvssV3Base(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, false
		}
		m[k] = v
	}
	for _, k := range []string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"} {
		if _, ok := m[k]; !ok {
			return 0, false
		}
	}

	changed := m["S"] == "C"
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[m["PR"]]
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[m["PR"]]
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

	iss := 1 - (1-cia[m["C"]])*(1-cia[m["I"]])*(1-cia[m["A"]])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	expl := 8.22 * av * ac * pr * ui
	if changed {
		return roundUp(math.Min(1.08*(impact+expl), 10)), true
	}
	return roundUp(math.Min(impact+expl, 10)), true
}

// roundUp is the CVSS 3.1 "Roundup" function (avoids float error).
func roundUp(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}

// baseScore scores a vector by its OSV severity type.
func baseScore(typ, vector string) (float64, bool) {
	switch typ {
	case "CVSS_V3":
		return cvssV3Base(vector)
	case "CVSS_V4":
		c, err := cvss40.ParseVector(vector)
		if err != nil {
			return 0, false
		}
		return c.Score(), true
	}
	return 0, false
}

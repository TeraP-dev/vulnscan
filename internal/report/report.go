package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/TeraP-dev/vulnscan/internal/debver"
)

type Finding struct {
	Package string  `json:"package"`
	Version string  `json:"version"`
	ID      string  `json:"id"`
	Score   float64 `json:"score"` // -1 = unknown
	Fixed   string  `json:"fixed_in"`
	Summary string  `json:"summary"`
}

// PackageSummary is one line per package: what to upgrade to and why.
type PackageSummary struct {
	Package   string  `json:"package"`
	Installed string  `json:"installed"`
	UpgradeTo string  `json:"upgrade_to"` // newest fixed version; "" if none is available
	Score     float64 `json:"score"`      // highest score among findings; -1 = unknown
	Findings  int     `json:"findings"`
}

func Label(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// Sort orders by score (desc), then fixable first, then package and ID.
func Sort(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if (a.Fixed != "") != (b.Fixed != "") {
			return a.Fixed != ""
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.ID < b.ID
	})
}

// Summarize groups findings by package. Fixed versions are comma-joined in Finding.Fixed, Debian versions never contain ", ", so splitting is safe.
func Summarize(fs []Finding) []PackageSummary {
	type key struct{ pkg, ver string }
	idx := map[key]int{}
	var out []PackageSummary
	for _, f := range fs {
		k := key{f.Package, f.Version}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, PackageSummary{Package: f.Package, Installed: f.Version, Score: f.Score})
		}
		s := &out[i]
		s.Findings++
		if f.Score > s.Score {
			s.Score = f.Score
		}
		if f.Fixed == "" {
			continue
		}
		for _, v := range strings.Split(f.Fixed, ", ") {
			if s.UpgradeTo == "" || debver.Compare(v, s.UpgradeTo) > 0 {
				s.UpgradeTo = v
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Findings != b.Findings {
			return a.Findings > b.Findings
		}
		return a.Package < b.Package
	})
	return out
}

func Table(w io.Writer, fs []Finding) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tPACKAGE\tINSTALLED\tFIXED IN\tID")
	for _, f := range fs {
		fixed := f.Fixed
		if fixed == "" {
			fixed = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", Label(f.Score), f.Package, f.Version, fixed, f.ID)
	}
	tw.Flush()
}

func SummaryTable(w io.Writer, ps []PackageSummary) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tPACKAGE\tINSTALLED\tUPGRADE TO\tFINDINGS")
	for _, p := range ps {
		up := p.UpgradeTo
		if up == "" {
			up = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", Label(p.Score), p.Package, p.Installed, up, p.Findings)
	}
	tw.Flush()
}

func JSON(w io.Writer, fs []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(fs)
}

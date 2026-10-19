package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"
)

type Finding struct {
	Package string  `json:"package"`
	Version string  `json:"version"`
	ID      string  `json:"id"`
	Score   float64 `json:"score"` // -1 = unknown
	Fixed   string  `json:"fixed_in"`
	Summary string  `json:"summary"`
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

func JSON(w io.Writer, fs []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(fs)
}

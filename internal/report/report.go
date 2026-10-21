package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
)

type Finding struct {
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	ID       string   `json:"id"`
	Score    float64  `json:"score"` // -1 = unknown
	Fixed    string   `json:"fixed_in"`
	Summary  string   `json:"summary"`
	Binaries []string `json:"-"`
}

// PackageSummary is one line per package: what to upgrade to and why.
type PackageSummary struct {
	Package       string   `json:"package"`
	Installed     string   `json:"installed"`
	UpgradeTo     string   `json:"upgrade_to"` // newest fixed version; "" if none is available
	Score         float64  `json:"score"`      // highest score among findings; -1 = unknown
	Findings      int      `json:"findings"`
	Binaries      []string `json:"binaries"`
	MajorJump     bool     `json:"major_jump"`                // the full fix is on a different line than the installed version
	KeepLineTo    string   `json:"keep_line_to,omitempty"`    // best fix that stays on the installed line
	KeepLineFixes int      `json:"keep_line_fixes,omitempty"` // findings that fix resolves
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

// Summarize groups findings by package. compare orders version strings for the
// ecosystem. line maps a version to its compatibility line (for example its
// major version); it may be nil, which turns off the keep-line information.
func Summarize(fs []Finding, compare func(a, b string) int, line func(string) string) []PackageSummary {
	type key struct{ pkg, ver string }
	idx := map[key]int{}
	var out []PackageSummary
	for _, f := range fs {
		k := key{f.Package, f.Version}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, PackageSummary{Package: f.Package, Installed: f.Version, Score: f.Score, Binaries: f.Binaries})
		}
		s := &out[i]
		s.Findings++
		if f.Score > s.Score {
			s.Score = f.Score
		}
		if f.Fixed == "" {
			continue
		}
		if v := lowestFix(f, compare); s.UpgradeTo == "" || compare(v, s.UpgradeTo) > 0 {
			s.UpgradeTo = v
		}
		if line != nil {
			if v := lowestFixIn(f, compare, line); v != "" {
				s.KeepLineFixes++
				if s.KeepLineTo == "" || compare(v, s.KeepLineTo) > 0 {
					s.KeepLineTo = v
				}
			}
		}
	}
	if line != nil {
		for i := range out {
			s := &out[i]
			s.MajorJump = s.UpgradeTo != "" && line(s.Installed) != "" && line(s.UpgradeTo) != line(s.Installed)
			if !s.MajorJump {
				s.KeepLineTo, s.KeepLineFixes = "", 0
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

// lowestFixIn is like lowestFix but only considers fixed versions on the same
// line as the installed version. It returns "" if there is none.
func lowestFixIn(f Finding, compare func(a, b string) int, line func(string) string) string {
	own := line(f.Version)
	if own == "" {
		return ""
	}
	best := ""
	for _, v := range strings.Split(f.Fixed, ", ") {
		if line(v) != own || compare(v, f.Version) <= 0 {
			continue
		}
		if best == "" || compare(v, best) < 0 {
			best = v
		}
	}
	return best
}

// Notes explains packages whose full fix needs a new major version.
func Notes(ps []PackageSummary) []string {
	var out []string
	for _, p := range ps {
		if !p.MajorJump {
			continue
		}
		if p.KeepLineFixes > 0 {
			out = append(out, fmt.Sprintf(
				"note: %s %s: %s stays on the same major version and fixes %d of %d findings; the full fix (%s) is a new major version.",
				p.Package, p.Installed, p.KeepLineTo, p.KeepLineFixes, p.Findings, p.UpgradeTo))
		} else {
			out = append(out, fmt.Sprintf(
				"note: %s %s: no fix on the same major version; the full fix (%s) is a new major version.",
				p.Package, p.Installed, p.UpgradeTo))
		}
	}
	return out
}

// lowestFix returns the lowest fixed version newer than the installed one, which is the smallest upgrade that resolves this finding.
// If none is newer, it returns the highest fixed version.
func lowestFix(f Finding, compare func(a, b string) int) string {
	above, highest := "", ""
	for _, v := range strings.Split(f.Fixed, ", ") {
		if highest == "" || compare(v, highest) > 0 {
			highest = v
		}
		if compare(v, f.Version) > 0 && (above == "" || compare(v, above) < 0) {
			above = v
		}
	}
	if above != "" {
		return above
	}
	return highest
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

// Debian package names: lowercase letters, digits, "+", "-", ".", starting with a letter or digit.
var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.\-]+$`)

// FixCommand returns an apt command that upgrades the installed binary packages of every package that has a fixed version available, or "" if there are none.
// Names are validated so the result is safe to paste into a shell.
func FixCommand(ps []PackageSummary) string {
	var lines []string
	for _, p := range ps {
		if p.UpgradeTo == "" {
			continue
		}
		var names []string
		for _, n := range p.Binaries {
			if validName.MatchString(n) {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		lines = append(lines, strings.Join(names, " "))
	}
	if len(lines) == 0 {
		return ""
	}
	return "sudo apt update && sudo apt install --only-upgrade \\\n  " + strings.Join(lines, " \\\n  ")
}

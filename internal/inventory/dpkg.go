package inventory

import (
	"bufio"
	"io"
	"strings"
)

type Package struct {
	Name          string
	Source        string
	SourceVersion string // set only when the Source: field carries "(version)"
	Version       string
	Arch          string
}

// QueryVersion is the version to send to OSV, which matches on source versions.
func (p Package) QueryVersion() string {
	if p.SourceVersion != "" {
		return p.SourceVersion
	}
	return p.Version
}

// ParseDpkgStatus reads /var/lib/dpkg/status and returns installed packages.
func ParseDpkgStatus(r io.Reader) ([]Package, error) {
	var pkgs []Package
	var cur Package
	var installed bool

	flush := func() {
		if installed && cur.Name != "" {
			if cur.Source == "" {
				cur.Source = cur.Name
			}
			pkgs = append(pkgs, cur)
		}
		cur, installed = Package{}, false
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' { // continuation line (e.g. Description)
			continue
		}
		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		switch key {
		case "Package":
			cur.Name = val
		case "Version":
			cur.Version = val
		case "Architecture":
			cur.Arch = val
		case "Source":
			name, rest, _ := strings.Cut(val, " ")
			cur.Source = name
			if v, ok := strings.CutPrefix(rest, "("); ok {
				cur.SourceVersion = strings.TrimSuffix(v, ")")
			}
		case "Status":
			installed = strings.HasSuffix(val, " installed") && !strings.Contains(val, "not-installed")
		}
	}
	flush() // file may not end with a blank line
	return pkgs, sc.Err()
}

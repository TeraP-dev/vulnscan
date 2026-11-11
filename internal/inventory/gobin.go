package inventory

import (
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

type Module struct {
	Path    string
	Version string
}

// GoBinary is what a compiled Go program records about how it was built.
type GoBinary struct {
	Path      string   // file path
	Name      string   // file name
	GoVersion string   // toolchain version without the "go" prefix; "" if unusable
	PkgPath   string   // main package import path, which "go install" takes
	Main      Module   // main module; Version is "" for builds from local source
	Deps      []Module // dependencies (replacements applied; local ones skipped)
}

// ReadGoBinary reads the build information embedded in a Go executable.
func ReadGoBinary(path string) (GoBinary, error) {
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		return GoBinary{}, err
	}
	return fromBuildInfo(path, bi), nil
}

func fromBuildInfo(path string, bi *debug.BuildInfo) GoBinary {
	b := GoBinary{
		Path:      path,
		Name:      filepath.Base(path),
		GoVersion: stdlibVersion(bi.GoVersion),
		PkgPath:   bi.Path,
		Main:      Module{Path: bi.Main.Path},
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		b.Main.Version = v
	}
	for _, d := range bi.Deps {
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		if m.Version == "" || m.Version == "(devel)" {
			continue
		}
		b.Deps = append(b.Deps, Module{Path: m.Path, Version: m.Version})
	}
	return b
}

// stdlibVersion turns "go1.22.1" into "1.22.1" and "go1.22" into "1.22.0".
// It returns "" for development and pre-release toolchains.
func stdlibVersion(v string) string {
	v, _, _ = strings.Cut(v, " ") // drop suffixes such as "X:boringcrypto"
	v = strings.TrimPrefix(v, "go")
	parts := strings.Split(v, ".")
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return ""
		}
	}
	switch len(parts) {
	case 2:
		return v + ".0"
	case 3:
		return v
	}
	return ""
}

// DefaultGoBin is where "go install" puts binaries: $GOBIN, else the first
// $GOPATH entry plus "/bin", else ~/go/bin.
func DefaultGoBin() (string, error) {
	if d := os.Getenv("GOBIN"); d != "" {
		return d, nil
	}
	if gp := os.Getenv("GOPATH"); gp != "" {
		first, _, _ := strings.Cut(gp, string(os.PathListSeparator))
		return filepath.Join(first, "bin"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "go", "bin"), nil
}

// FindGoBinaries reads the given files, or the files directly inside the given
// folders (not recursive). With no paths it uses DefaultGoBin. Files that are not
// Go executables are skipped inside folders and are an error when named directly.
func FindGoBinaries(paths []string) ([]GoBinary, error) {
	if len(paths) == 0 {
		dir, err := DefaultGoBin()
		if err != nil {
			return nil, err
		}
		paths = []string{dir}
	}
	var out []GoBinary
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			b, err := ReadGoBinary(p)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			out = append(out, b)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if b, err := ReadGoBinary(filepath.Join(p, e.Name())); err == nil {
				out = append(out, b)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no Go binaries found in %s", strings.Join(paths, ", "))
	}
	return out, nil
}

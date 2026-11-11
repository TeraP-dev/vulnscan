package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
)

func TestStdlibVersion(t *testing.T) {
	cases := map[string]string{
		"go1.22.1":                "1.22.1",
		"go1.22":                  "1.22.0",
		"go1.22.1 X:boringcrypto": "1.22.1",
		"go1.23rc1":               "",
		"devel go1.24-abcdef Mon": "",
		"":                        "",
	}
	for in, want := range cases {
		if got := stdlibVersion(in); got != want {
			t.Errorf("stdlibVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFromBuildInfo(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.22.1",
		Path:      "example.com/tool/cmd/tool",
		Main:      debug.Module{Path: "example.com/tool", Version: "(devel)"},
		Deps: []*debug.Module{
			{Path: "golang.org/x/text", Version: "v0.3.5"},
			{Path: "example.com/orig", Version: "v1.0.0", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.0.1"}},
			{Path: "example.com/local", Version: "v1.0.0", Replace: &debug.Module{Path: "../local"}},
		},
	}
	b := fromBuildInfo("/x/bin/tool", bi)
	if b.Name != "tool" || b.GoVersion != "1.22.1" || b.PkgPath != "example.com/tool/cmd/tool" {
		t.Errorf("unexpected binary: %+v", b)
	}
	if b.Main.Version != "" {
		t.Errorf("a (devel) main module should have no version, got %q", b.Main.Version)
	}
	if len(b.Deps) != 2 || b.Deps[0].Version != "v0.3.5" || b.Deps[1] != (Module{Path: "example.com/fork", Version: "v1.0.1"}) {
		t.Errorf("unexpected deps: %+v", b.Deps)
	}
}

func TestFindGoBinaries(t *testing.T) {
	self, err := os.ReadFile(os.Args[0]) // the test binary is a Go executable
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tool"), self, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	bins, err := FindGoBinaries([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(bins) != 1 || bins[0].Name != "tool" {
		t.Fatalf("want only the Go binary, got %+v", bins)
	}
	if want := stdlibVersion(runtime.Version()); bins[0].GoVersion != want {
		t.Errorf("GoVersion = %q, want %q", bins[0].GoVersion, want)
	}
	if _, err := FindGoBinaries([]string{filepath.Join(dir, "notes.txt")}); err == nil {
		t.Error("naming a non-Go file directly should be an error")
	}
}

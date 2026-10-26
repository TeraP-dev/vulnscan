package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TeraP-dev/vulnscan/internal/osv"
)

func TestDetectEcosystem(t *testing.T) {
	cases := []struct{ name, osRelease, want string }{
		{"debian", "ID=debian\nVERSION_ID=\"12\"\n", "Debian:12"},
		{"ubuntu lts", "ID=ubuntu\nVERSION_ID=\"22.04\"\n", "Ubuntu:22.04:LTS"},
		{"ubuntu interim", "ID=ubuntu\nVERSION_ID=\"25.10\"\n", "Ubuntu:25.10"},
		{"odd-year april is not LTS", "ID=ubuntu\nVERSION_ID=\"23.04\"\n", "Ubuntu:23.04"},
		{"kali is not auto-detected", "ID=kali\nVERSION_ID=\"2026.3\"\n", ""},
	}
	for _, c := range cases {
		p := filepath.Join(t.TempDir(), "os-release")
		if err := os.WriteFile(p, []byte(c.osRelease), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := detectEcosystem(p)
		if c.want == "" {
			if err == nil {
				t.Errorf("%s: want an error, got %q", c.name, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

func TestSuperseded(t *testing.T) {
	parse := func(s string) *osv.Vuln {
		var v osv.Vuln
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Fatal(err)
		}
		return &v
	}
	usn := parse(`{"id":"USN-1-1","upstream":["CVE-2026-1"]}`)
	if !superseded(usn, map[string]bool{"USN-1-1": true, "UBUNTU-CVE-2026-1": true}) {
		t.Error("a USN should be superseded by its UBUNTU-CVE record")
	}
	if superseded(usn, map[string]bool{"USN-1-1": true}) {
		t.Error("a USN stands alone when no per-CVE record was returned")
	}
	pysec := parse(`{"id":"PYSEC-2023-1","aliases":["GHSA-aaaa"]}`)
	if !superseded(pysec, map[string]bool{"PYSEC-2023-1": true, "GHSA-aaaa": true}) {
		t.Error("a PYSEC record should be superseded by its GHSA alias")
	}
	dla := parse(`{"id":"DLA-1-1","upstream":["CVE-1"]}`)
	if superseded(dla, map[string]bool{"DLA-1-1": true, "UBUNTU-CVE-1": true}) {
		t.Error("only USN and PYSEC records are superseded this way")
	}
}

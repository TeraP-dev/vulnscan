package report

import (
	"bytes"
	"testing"

	"github.com/TeraP-dev/vulnscan/internal/debver"
	"github.com/TeraP-dev/vulnscan/internal/pep440"
)

func TestSortAndLabel(t *testing.T) {
	fs := []Finding{
		{Package: "b", ID: "2", Score: -1},
		{Package: "a", ID: "1", Score: 9.8},
		{Package: "c", ID: "3", Score: 5.0, Fixed: "1.0"},
		{Package: "d", ID: "4", Score: 5.0},
	}
	Sort(fs)
	order := fs[0].ID + fs[1].ID + fs[2].ID + fs[3].ID
	if order != "1342" {
		t.Errorf("got order %s, want 1342", order)
	}
	if Label(9.8) != "CRITICAL" || Label(-1) != "UNKNOWN" || Label(5) != "MEDIUM" {
		t.Error("bad labels")
	}
}

func TestSummarize(t *testing.T) {
	fs := []Finding{
		{Package: "bind9", Version: "1:9.20.23-1", ID: "1", Score: 7.5, Fixed: "1:9.20.26-1~deb13u1"},
		{Package: "bind9", Version: "1:9.20.23-1", ID: "2", Score: 8.1, Fixed: "1:9.20.29-1~deb13u1"},
		{Package: "openssl", Version: "1.1.1n-0+deb11u1", ID: "3", Score: 9.8, Fixed: "1.1.1n-0+deb11u6"},
		{Package: "openssl", Version: "1.1.1n-0+deb11u1", ID: "4", Score: 7.0, Fixed: "1.1.1w-0+deb11u5"},
		{Package: "nofix", Version: "1.0", ID: "5", Score: -1},
	}
	got := Summarize(fs, debver.Compare, nil)
	if len(got) != 3 || got[0].Package != "openssl" || got[1].Package != "bind9" || got[2].Package != "nofix" {
		t.Fatalf("unexpected order or length: %+v", got)
	}
	if got[0].UpgradeTo != "1.1.1w-0+deb11u5" {
		t.Errorf("openssl upgrade: got %q", got[0].UpgradeTo)
	}
	if b := got[1]; b.UpgradeTo != "1:9.20.29-1~deb13u1" || b.Findings != 2 || b.Score != 8.1 {
		t.Errorf("bind9 summary wrong: %+v", b)
	}
	if got[2].UpgradeTo != "" {
		t.Errorf("nofix should have no upgrade, got %q", got[2].UpgradeTo)
	}
}

func TestSummarizeBranches(t *testing.T) {
	// Installed 3.2.5 with fixes on two branches: the smallest upgrade is 3.2.12, not 4.0.2.
	fs := []Finding{{Package: "django", Version: "3.2.5", ID: "1", Score: 7.5, Fixed: "3.2.12, 4.0.2"}}
	if got := Summarize(fs, pep440.Compare, nil); got[0].UpgradeTo != "3.2.12" {
		t.Errorf("got %q, want 3.2.12", got[0].UpgradeTo)
	}
}

func TestSummarizeKeepLine(t *testing.T) {
	fs := []Finding{
		{Package: "urllib3", Version: "1.26.4", ID: "1", Score: 7, Fixed: "1.26.5"},
		{Package: "urllib3", Version: "1.26.4", ID: "2", Score: 7, Fixed: "2.0.6, 1.26.17"},
		{Package: "urllib3", Version: "1.26.4", ID: "3", Score: 7, Fixed: "2.8.0"},
		{Package: "idna", Version: "2.10", ID: "4", Score: 5, Fixed: "3.7"},
		{Package: "same", Version: "1.0", ID: "5", Score: 4, Fixed: "1.2"},
	}
	by := map[string]PackageSummary{}
	for _, s := range Summarize(fs, pep440.Compare, pep440.Line) {
		by[s.Package] = s
	}
	if u := by["urllib3"]; u.UpgradeTo != "2.8.0" || !u.MajorJump || u.KeepLineTo != "1.26.17" || u.KeepLineFixes != 2 {
		t.Errorf("urllib3: %+v", u)
	}
	if i := by["idna"]; i.UpgradeTo != "3.7" || !i.MajorJump || i.KeepLineTo != "" || i.KeepLineFixes != 0 {
		t.Errorf("idna: %+v", i)
	}
	if s := by["same"]; s.MajorJump || s.KeepLineTo != "" {
		t.Errorf("same: %+v", s)
	}
	if n := Notes([]PackageSummary{by["urllib3"], by["idna"], by["same"]}); len(n) != 2 {
		t.Errorf("want 2 notes, got %d", len(n))
	}
}

func TestFixCommand(t *testing.T) {
	ps := []PackageSummary{
		{Package: "libheif", UpgradeTo: "1.23.4-1", Binaries: []string{"libheif1", "libheif-plugin-x265"}},
		{Package: "nofix", Binaries: []string{"nofix"}},
		{Package: "evil", UpgradeTo: "1", Binaries: []string{"ok-pkg", "bad; rm -rf ~", "-oops"}},
	}
	want := "sudo apt update && sudo apt install --only-upgrade \\\n  libheif-plugin-x265 libheif1 \\\n  ok-pkg"
	if got := FixCommand(ps); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if FixCommand(nil) != "" {
		t.Error("no packages should give an empty command")
	}
}

func TestFixCommandPip(t *testing.T) {
	ps := []PackageSummary{
		{Package: "urllib3", UpgradeTo: "2.8.0"},
		{Package: "nofix"},
		{Package: "evil'; rm -rf ~", UpgradeTo: "1.0"},
		{Package: "badver", UpgradeTo: "1.0'; echo x"},
		{Package: "PyYAML", UpgradeTo: "6.0.1"},
	}
	want := "python3 -m pip install --upgrade \\\n  'urllib3>=2.8.0' \\\n  'PyYAML>=6.0.1'"
	if got := FixCommandPip(ps, "python3"); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if got := FixCommandPip(ps[1:2], "python3"); got != "" {
		t.Errorf("no fixable packages should give an empty command, got %q", got)
	}
	want = "'/my venv/bin/python' -m pip install --upgrade \\\n  'urllib3>=2.8.0'"
	if got := FixCommandPip(ps[:1], "/my venv/bin/python"); got != want {
		t.Errorf("interpreter path with a space: got %q", got)
	}
}

func TestEmptyTables(t *testing.T) {
	var b bytes.Buffer
	Table(&b, nil)
	SummaryTable(&b, nil)
	if got := b.String(); got != "No findings.\nNo findings.\n" {
		t.Errorf("got %q", got)
	}
}

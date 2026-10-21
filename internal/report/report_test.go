package report

import "testing"

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
		{Package: "openssl", Version: "1.1.1n-0+deb11u1", ID: "3", Score: 9.8, Fixed: "1.1.1n-0+deb11u6, 1.1.1w-0+deb11u5"},
		{Package: "nofix", Version: "1.0", ID: "4", Score: -1},
	}
	got := Summarize(fs)
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

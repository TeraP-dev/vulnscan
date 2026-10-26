package osv

import (
	"encoding/json"
	"testing"
)

func TestScoreWithUpstream(t *testing.T) {
	parse := func(s string) *Vuln {
		var v Vuln
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Fatal(err)
		}
		return &v
	}
	dla := parse(`{"id":"DLA-1","upstream":["CVE-1","DEBIAN-CVE-1","DEBIAN-CVE-2","DEBIAN-CVE-404"]}`)
	all := map[string]*Vuln{
		"DEBIAN-CVE-1": parse(`{"id":"DEBIAN-CVE-1","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}]}`),
		"DEBIAN-CVE-2": parse(`{"id":"DEBIAN-CVE-2","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`),
	}
	if got := dla.ScoreWithUpstream(all); got != 9.8 {
		t.Errorf("got %v, want 9.8 (max of upstream)", got)
	}
	if got := parse(`{"id":"X"}`).ScoreWithUpstream(all); got != -1 {
		t.Errorf("got %v, want -1 for no data", got)
	}
}

func TestFixedVersionsPyPIName(t *testing.T) {
	var v Vuln
	js := `{"id":"X","affected":[{"package":{"name":"Django_Test","ecosystem":"PyPI"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatal(err)
	}
	if got := v.FixedVersions("django-test", "PyPI"); len(got) != 1 || got[0] != "1.2.3" {
		t.Errorf("got %v", got)
	}
	if NormalizeName("PyPI", "Foo.Bar__baz") != "foo-bar-baz" {
		t.Error("bad normalization")
	}
}

func TestScoreUbuntuPriority(t *testing.T) {
	parse := func(s string) *Vuln {
		var v Vuln
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			t.Fatal(err)
		}
		return &v
	}
	if got := parse(`{"id":"X","severity":[{"type":"Ubuntu","score":"medium"}]}`).Score(); got != 4.0 {
		t.Errorf("priority only: got %v, want 4.0", got)
	}
	// CVSS wins over Ubuntu's label when both exist.
	both := `{"id":"Y","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},{"type":"Ubuntu","score":"high"}]}`
	if got := parse(both).Score(); got != 6.1 {
		t.Errorf("CVSS plus priority: got %v, want 6.1", got)
	}
	if got := parse(`{"id":"Z","severity":[{"type":"Ubuntu","score":"untriaged"}]}`).Score(); got != -1 {
		t.Errorf("unknown label: got %v, want -1", got)
	}
}

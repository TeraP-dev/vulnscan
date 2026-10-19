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

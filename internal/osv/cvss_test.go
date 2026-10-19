package osv

import "testing"

func TestCVSSV3Base(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
	}
	for vec, want := range cases {
		got, ok := cvssV3Base(vec)
		if !ok || got != want {
			t.Errorf("%s: got %v (ok=%v), want %v", vec, got, ok, want)
		}
	}
	if _, ok := cvssV3Base("garbage"); ok {
		t.Error("garbage should not parse")
	}
}

func TestBaseScoreV4(t *testing.T) {
	// all-high network vector with no threat or environmental metrics
	got, ok := baseScore("CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	if !ok || got != 9.3 {
		t.Errorf("got %v (ok=%v), want 9.3", got, ok)
	}
}

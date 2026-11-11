package semver

import "testing"

func TestOrdering(t *testing.T) {
	// The order from the semver spec, then plain releases.
	ordered := []string{
		"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
		"1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.9.0", "1.10.0", "2.0.0",
	}
	for i := 0; i+1 < len(ordered); i++ {
		a, b := ordered[i], ordered[i+1]
		if Compare(a, b) != -1 || Compare(b, a) != 1 {
			t.Errorf("want %s < %s", a, b)
		}
	}
}

func TestEqualAndPseudo(t *testing.T) {
	for _, p := range [][2]string{{"v1.2.3", "1.2.3"}, {"1.2.3+build5", "1.2.3"}, {"1.2", "1.2.0"}} {
		if Compare(p[0], p[1]) != 0 {
			t.Errorf("want %s == %s", p[0], p[1])
		}
	}
	if Compare("0.0.0-20210405180319-a5a99cb37ef4", "0.17.0") != -1 {
		t.Error("a pseudo-version should sort below a later release")
	}
}

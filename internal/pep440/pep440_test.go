package pep440

import "testing"

func TestOrdering(t *testing.T) {
	// Each version must be older than the next (PEP 440 ordering).
	ordered := []string{
		"1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0",
		"1.0.post1.dev1", "1.0.post1", "1.1.dev1", "1.1", "2.9", "2.10", "1!0.5",
	}
	for i := 0; i+1 < len(ordered); i++ {
		a, b := ordered[i], ordered[i+1]
		if Compare(a, b) != -1 || Compare(b, a) != 1 {
			t.Errorf("want %s < %s", a, b)
		}
	}
}

func TestEqual(t *testing.T) {
	pairs := [][2]string{
		{"1.0", "1.0.0"},
		{"1.0-1", "1.0.post1"},
		{"1.0RC1", "1.0rc1"},
		{"1.0a1", "1.0alpha1"},
		{"v1.0", "1.0"},
	}
	for _, p := range pairs {
		if Compare(p[0], p[1]) != 0 || Compare(p[1], p[0]) != 0 {
			t.Errorf("want %s == %s", p[0], p[1])
		}
	}
}

func TestLocal(t *testing.T) {
	if Compare("1.0", "1.0+abc") != -1 || Compare("1.0+abc.4", "1.0+abc.5") != -1 {
		t.Error("local version ordering is wrong")
	}
}

func TestLine(t *testing.T) {
	if Line("1.26.4") != Line("1.26.19") || Line("1.26.4") == Line("2.0.0") || Line("garbage") != "" {
		t.Error("Line groups versions incorrectly")
	}
}

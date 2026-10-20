package debver

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.9", "1.10", -1},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0+b1", -1},
		{"1.0a", "1.0+", -1}, // letters sort before non-letters
		{"1.0", "1.00", 0},
		{"1:1.0", "2.0", 1}, // epoch wins
		{"1.0-1", "1.0-1+deb11u1", -1},
		{"2.8.3-1", "2.9.0-1~deb13u1", -1},
		{"2.9.0-1~deb13u1", "2.9.0-1", -1},
		{"1.1.1n-0+deb11u6", "1.1.1w-0+deb11u5", -1},
		{"1:9.20.26-1~deb13u1", "1:9.20.29-1~deb13u1", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

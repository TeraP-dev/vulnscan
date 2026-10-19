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

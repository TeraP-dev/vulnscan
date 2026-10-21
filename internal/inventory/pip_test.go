package inventory

import (
	"strings"
	"testing"
)

func TestParsePipList(t *testing.T) {
	in := `[{"name":"requests","version":"2.25.0"},{"name":"","version":"1"},{"name":"PyYAML","version":"5.3"}]`
	pkgs, err := ParsePipList(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[0].Name != "requests" || pkgs[1].Version != "5.3" {
		t.Errorf("unexpected result: %+v", pkgs)
	}
}

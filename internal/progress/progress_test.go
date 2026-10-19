package progress

import (
	"bytes"
	"strings"
	"testing"
)

func TestBar(t *testing.T) {
	var buf bytes.Buffer
	b := New(&buf)
	b.Start("Working", 4)
	b.Inc()
	b.Inc()
	out := buf.String()
	if !strings.Contains(out, "2/4") || !strings.Contains(out, strings.Repeat("#", 12)+strings.Repeat("-", 12)) {
		t.Errorf("unexpected output %q", out)
	}
}

func TestNilBarIsSafe(t *testing.T) {
	var b *Bar
	b.Start("x", 3)
	b.Inc()
	b.Clear()
}

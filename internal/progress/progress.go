package progress

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

// Bar draws a one-line progress indicator that is redrawn in place.
// A nil *Bar is valid and does nothing, so callers can skip the checks.
type Bar struct {
	mu    sync.Mutex
	w     io.Writer
	label string
	total int
	done  int
}

func New(w io.Writer) *Bar { return &Bar{w: w} }

// Start begins a stage. total == 0 shows the label only, with no bar.
func (b *Bar) Start(label string, total int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.label, b.total, b.done = label, total, 0
	b.draw()
}

func (b *Bar) Inc() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done++
	b.draw()
}

// Clear erases the line.
func (b *Bar) Clear() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	fmt.Fprint(b.w, "\r\033[2K")
}

func (b *Bar) draw() {
	if b.total == 0 {
		fmt.Fprintf(b.w, "\r\033[2K%s...", b.label)
		return
	}
	const width = 24
	filled := width * b.done / b.total
	fmt.Fprintf(b.w, "\r\033[2K%s [%s%s] %d/%d",
		b.label, strings.Repeat("#", filled), strings.Repeat("-", width-filled), b.done, b.total)
}

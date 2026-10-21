package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type PythonPackage struct {
	Name    string
	Version string
}

// ParsePipList reads the JSON printed by "pip list --format=json".
func ParsePipList(r io.Reader) ([]PythonPackage, error) {
	var raw []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, err
	}
	out := make([]PythonPackage, 0, len(raw))
	for _, p := range raw {
		if p.Name != "" && p.Version != "" {
			out = append(out, PythonPackage{Name: p.Name, Version: p.Version})
		}
	}
	return out, nil
}

// ListPython runs "<python> -m pip list" and returns the installed packages.
func ListPython(ctx context.Context, python string) ([]PythonPackage, error) {
	cmd := exec.CommandContext(ctx, python, "-m", "pip", "list", "--format=json", "--disable-pip-version-check")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%s -m pip list failed: %s", python, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("cannot run %s: %w", python, err)
	}
	return ParsePipList(bytes.NewReader(out))
}

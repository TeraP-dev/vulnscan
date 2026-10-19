package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const maxBatch = 1000 // OSV's querybatch limit
var ErrNotFound = errors.New("osv: not found")

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Query struct {
	Package Package `json:"package"`
	Version string  `json:"version"`
}

type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
}

type Vuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"` // related records, e.g. CVE-*/DEBIAN-CVE-*
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []Affected `json:"affected"`
}

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New() *Client {
	return &Client{BaseURL: "https://api.osv.dev", HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type batchRequest struct {
	Queries []Query `json:"queries"`
}

type batchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

// QueryBatch returns, for each query (same order), the IDs of matching vulnerabilities.
func (c *Client) QueryBatch(ctx context.Context, qs []Query) ([][]string, error) {
	out := make([][]string, 0, len(qs))
	for start := 0; start < len(qs); start += maxBatch {
		end := start + maxBatch
		if end > len(qs) {
			end = len(qs)
		}
		body, err := json.Marshal(batchRequest{Queries: qs[start:end]})
		if err != nil {
			return nil, err
		}
		var resp batchResponse
		if err := c.do(ctx, http.MethodPost, "/v1/querybatch", body, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != end-start {
			return nil, fmt.Errorf("osv: sent %d queries, got %d results", end-start, len(resp.Results))
		}
		for _, r := range resp.Results {
			ids := make([]string, len(r.Vulns))
			for i, v := range r.Vulns {
				ids[i] = v.ID
			}
			out = append(out, ids)
		}
	}
	return out, nil
}

// GetVuln fetches full details (severity, fixed versions) for one vulnerability ID.
func (c *Client) GetVuln(ctx context.Context, id string) (*Vuln, error) {
	var v Vuln
	if err := c.do(ctx, http.MethodGet, "/v1/vulns/"+id, nil, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, dst any) error {

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s %s", ErrNotFound, method, path)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("osv: %s %s: %s: %s", method, path, resp.Status, msg)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestQueryBatchChunking(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var req batchRequest
		json.NewDecoder(r.Body).Decode(&req)
		// first query of every chunk "has" one vuln, the rest none
		results := make([]map[string]any, len(req.Queries))
		for i := range results {
			results[i] = map[string]any{}
		}
		results[0] = map[string]any{"vulns": []map[string]string{{"id": "CVE-TEST-1"}}}
		json.NewEncoder(w).Encode(map[string]any{"results": results})
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	qs := make([]Query, 2500)
	got, err := c.QueryBatch(context.Background(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Errorf("want 3 requests, got %d", calls)
	}
	if len(got) != 2500 || got[0][0] != "CVE-TEST-1" || len(got[1]) != 0 {
		t.Errorf("unexpected results")
	}
}

func TestGetVulnErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.GetVuln(context.Background(), "X"); err == nil {
		t.Fatal("want error on 404")
	}
}

// Live check: OSV_LIVE=1 go test ./internal/osv -run Live -v
func TestLiveKnownVulnerable(t *testing.T) {
	if os.Getenv("OSV_LIVE") == "" {
		t.Skip("set OSV_LIVE=1 to hit the real API")
	}
	c := New()
	q := Query{Package: Package{Name: "openssl", Ecosystem: "Debian:11"}, Version: "1.1.1n-0+deb11u1"}
	res, err := c.QueryBatch(context.Background(), []Query{q})
	if err != nil {
		t.Fatal(err)
	}
	if len(res[0]) == 0 {
		t.Fatal("expected known vulnerabilities for an old openssl")
	}
	v, err := c.GetVuln(context.Background(), res[0][0])
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s: %s (%d affected entries)", v.ID, v.Summary, len(v.Affected))
}

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/TeraP-ctf/vulnscan/internal/inventory"
	"github.com/TeraP-ctf/vulnscan/internal/osv"
	"github.com/TeraP-ctf/vulnscan/internal/report"
)

const usage = `vscan - check installed Debian packages against the OSV vulnerability database

Usage:
  vscan [flags]

Flags:
  -e, --ecosystem string   OSV ecosystem, e.g. Debian:13 (auto-detected on Debian)
  -s, --status string      dpkg status file (default /var/lib/dpkg/status)
  -j, --json               machine-readable output
  -a, --all                include findings with no fixed version yet
  -v, --version            print version and exit
  -h, --help               show this help

Examples:
  vscan                    scan this machine
  vscan -e Debian:13       choose the ecosystem yourself (e.g. on Kali)
  vscan -j | jq .          JSON output
  vscan -a                 include findings with no fix

Exit codes: 0 no findings, 1 findings, 2 error
`

// version comes from the module version when installed with "go install ...@vX.Y.Z".
func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func main() {
	var (
		ecosystem, statusPath    string
		asJSON, all, showVersion bool
	)
	const defaultStatus = "/var/lib/dpkg/status"
	flag.StringVar(&ecosystem, "ecosystem", "", "")
	flag.StringVar(&ecosystem, "e", "", "")
	flag.StringVar(&statusPath, "status", defaultStatus, "")
	flag.StringVar(&statusPath, "s", defaultStatus, "")
	flag.BoolVar(&asJSON, "json", false, "")
	flag.BoolVar(&asJSON, "j", false, "")
	flag.BoolVar(&all, "all", false, "")
	flag.BoolVar(&all, "a", false, "")
	flag.BoolVar(&showVersion, "version", false, "")
	flag.BoolVar(&showVersion, "v", false, "")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if showVersion {
		fmt.Println("vscan", version())
		return
	}
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "vscan: unexpected argument %q\n\n", flag.Arg(0))
		flag.Usage()
		os.Exit(2)
	}

	n, err := run(ecosystem, statusPath, asJSON, all)
	if err != nil {
		fmt.Fprintln(os.Stderr, "vscan:", err)
		os.Exit(2)
	}
	if n > 0 {
		os.Exit(1)
	}
}

func run(ecosystem, statusPath string, asJSON, all bool) (int, error) {
	if ecosystem == "" {
		var err error
		if ecosystem, err = detectEcosystem("/etc/os-release"); err != nil {
			return 0, err
		}
	}
	f, err := os.Open(statusPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	pkgs, err := inventory.ParseDpkgStatus(f)
	if err != nil {
		return 0, err
	}

	// One query per unique (source package, version).
	type key struct{ src, ver string }
	seen := map[key]bool{}
	var keys []key
	var queries []osv.Query
	for _, p := range pkgs {
		k := key{p.Source, p.QueryVersion()}
		if seen[k] {
			continue
		}
		seen[k] = true
		keys = append(keys, k)
		queries = append(queries, osv.Query{
			Package: osv.Package{Name: k.src, Ecosystem: ecosystem},
			Version: k.ver,
		})
	}

	ctx := context.Background()
	c := osv.New()
	ids, err := c.QueryBatch(ctx, queries)
	if err != nil {
		return 0, err
	}
	vulns, err := fetchAll(ctx, c, flatten(ids))
	if err != nil {
		return 0, err
	}

	// DLA/DSA records carry no severity; fetch the DEBIAN-CVE-* records they list as upstream.
	var extra []string
	for _, v := range vulns {
		if v.Score() >= 0 {
			continue
		}
		for _, u := range v.Upstream {
			if strings.HasPrefix(u, "DEBIAN-CVE-") {
				extra = append(extra, u)
			}
		}
	}
	more, err := fetchAll(ctx, c, extra)
	if err != nil {
		return 0, err
	}
	for id, v := range more {
		vulns[id] = v
	}

	findings := []report.Finding{}
	hidden := 0
	for i, k := range keys {
		for _, id := range ids[i] {
			v := vulns[id]
			fixed := strings.Join(v.FixedVersions(k.src, ecosystem), ", ")
			if fixed == "" && !all {
				hidden++
				continue
			}
			findings = append(findings, report.Finding{
				Package: k.src,
				Version: k.ver,
				ID:      id,
				Score:   v.ScoreWithUpstream(vulns),
				Fixed:   fixed,
				Summary: v.Summary,
			})
		}
	}
	report.Sort(findings)

	if asJSON {
		err = report.JSON(os.Stdout, findings)
	} else {
		report.Table(os.Stdout, findings)
		fmt.Fprintf(os.Stderr, "\n%d packages scanned against %s, %d findings", len(keys), ecosystem, len(findings))
		if hidden > 0 {
			fmt.Fprintf(os.Stderr, " (%d more with no fix available; use --all)", hidden)
		}
		fmt.Fprintln(os.Stderr)
	}
	return len(findings), err
}

func flatten(ids [][]string) []string {
	var out []string
	for _, l := range ids {
		out = append(out, l...)
	}
	return out
}

// fetchAll fetches unique IDs concurrently. IDs OSV doesn't have are skipped.
func fetchAll(ctx context.Context, c *osv.Client, ids []string) (map[string]*osv.Vuln, error) {
	uniq := map[string]bool{}
	for _, id := range ids {
		uniq[id] = true
	}
	out := make(map[string]*osv.Vuln, len(uniq))
	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	sem := make(chan struct{}, 8) // at most 8 concurrent requests

	for id := range uniq {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := c.GetVuln(ctx, id)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if !errors.Is(err, osv.ErrNotFound) && firstErr == nil {
					firstErr = err
				}
				return
			}
			out[id] = v
		}(id)
	}
	wg.Wait()
	return out, firstErr
}

func detectEcosystem(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot detect distro (%v); pass --ecosystem", err)
	}
	defer f.Close()
	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			kv[k] = strings.Trim(v, `"'`)
		}
	}
	if kv["ID"] == "debian" && kv["VERSION_ID"] != "" {
		return "Debian:" + kv["VERSION_ID"], nil
	}
	return "", fmt.Errorf("auto-detect supports Debian only (found ID=%q); pass --ecosystem, e.g. Debian:13", kv["ID"])
}

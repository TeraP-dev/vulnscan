package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"

	"github.com/TeraP-dev/vulnscan/internal/inventory"
	"github.com/TeraP-dev/vulnscan/internal/osv"
	"github.com/TeraP-dev/vulnscan/internal/progress"
	"github.com/TeraP-dev/vulnscan/internal/report"
)

const usage = `vscan - check installed Debian packages against the OSV vulnerability database

Usage:
  vscan [flags]

Flags:
  -e, --ecosystem string   OSV ecosystem, e.g. Debian:13 (auto-detected on Debian)
  -s, --status string      dpkg status file (default /var/lib/dpkg/status)
  -j, --json               machine-readable output
  -a, --all                include findings with no fixed version yet
	-d, --details            list every finding instead of one line per package
  -f, --fix                print an apt command that upgrades the affected packages
  -v, --version            print version and exit
  -h, --help               show this help

Examples:
  vscan                    scan this machine
  vscan -e Debian:13       choose the ecosystem yourself (e.g. on Kali)
  vscan -j | jq .          JSON output
  vscan -a                 include findings with no fix
  vscan -d                 show every advisory, not just a summary
  vscan -f                 print the apt command to apply the upgrades

Press Ctrl+C while scanning to cancel.

Exit codes: 0 no findings, 1 findings, 2 error, 130 interrupted
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
		ecosystem, statusPath                  string
		asJSON, all, details, fix, showVersion bool
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
	flag.BoolVar(&details, "details", false, "")
	flag.BoolVar(&details, "d", false, "")
	flag.BoolVar(&fix, "fix", false, "")
	flag.BoolVar(&fix, "f", false, "")
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { // after the first Ctrl+C, restore default behavior so a second one force-quits
		<-ctx.Done()
		stop()
	}()

	n, err := run(ctx, ecosystem, statusPath, asJSON, all, details, fix)
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "vscan: interrupted")
		os.Exit(130)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vscan:", err)
		os.Exit(2)
	}
	if n > 0 {
		os.Exit(1)
	}
}

func run(ctx context.Context, ecosystem, statusPath string, asJSON, all, details, fix bool) (int, error) {
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

	// One query per unique (source package, version); remember which binary packages belong to each source so we can build upgrade commands.
	type key struct{ src, ver string }
	seen := map[key]bool{}
	bins := map[key][]string{}
	var keys []key
	var queries []osv.Query
	for _, p := range pkgs {
		k := key{p.Source, p.QueryVersion()}
		bins[k] = append(bins[k], p.Name)
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

	// Show progress only when stderr is a terminal, so piped output stays clean.
	var bar *progress.Bar
	if isTerminal(os.Stderr) {
		bar = progress.New(os.Stderr)
	}
	ids, vulns, err := scan(ctx, queries, bar)
	bar.Clear()
	if err != nil {
		return 0, err
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
				Package:  k.src,
				Version:  k.ver,
				ID:       id,
				Score:    v.ScoreWithUpstream(vulns),
				Fixed:    fixed,
				Binaries: bins[k],
				Summary:  v.Summary,
			})
		}
	}
	report.Sort(findings)
	sums := report.Summarize(findings)

	switch {
	case asJSON:
		err = report.JSON(os.Stdout, findings)
	case fix:
		if cmd := report.FixCommand(sums); cmd != "" {
			fmt.Println(cmd)
		}
	case details:
		report.Table(os.Stdout, findings)
	default:
		report.SummaryTable(os.Stdout, sums)
	}
	if !asJSON {
		fmt.Fprintf(os.Stderr, "\n%d packages scanned against %s: %d findings in %d packages",
			len(keys), ecosystem, len(findings), len(sums))
		if hidden > 0 {
			fmt.Fprintf(os.Stderr, " (%d more with no fix available; use --all)", hidden)
		}
		fmt.Fprintln(os.Stderr)
		if !details && !fix && len(sums) > 0 {
			fmt.Fprintln(os.Stderr, "Run vscan -f for an apt command that applies these upgrades.")
		}
	}
	return len(findings), err
}

// scan does all the network work: batch query, advisory details, and the DEBIAN-CVE-* records that supply severity for DLA/DSA advisories.
func scan(ctx context.Context, queries []osv.Query, bar *progress.Bar) ([][]string, map[string]*osv.Vuln, error) {
	c := osv.New()
	bar.Start(fmt.Sprintf("Querying OSV for %d packages", len(queries)), 0)
	ids, err := c.QueryBatch(ctx, queries)
	if err != nil {
		return nil, nil, err
	}
	vulns, err := fetchAll(ctx, c, flatten(ids), bar, "Fetching advisories")
	if err != nil {
		return nil, nil, err
	}

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
	more, err := fetchAll(ctx, c, extra, bar, "Fetching severity records")
	if err != nil {
		return nil, nil, err
	}
	for id, v := range more {
		vulns[id] = v
	}
	return ids, vulns, nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func flatten(ids [][]string) []string {
	var out []string
	for _, l := range ids {
		out = append(out, l...)
	}
	return out
}

// fetchAll fetches unique IDs concurrently. IDs OSV doesn't have are skipped.
// It stops early when ctx is cancelled.
func fetchAll(ctx context.Context, c *osv.Client, ids []string, bar *progress.Bar, label string) (map[string]*osv.Vuln, error) {
	uniq := map[string]bool{}
	for _, id := range ids {
		uniq[id] = true
	}
	out := make(map[string]*osv.Vuln, len(uniq))
	if len(uniq) == 0 {
		return out, nil
	}
	bar.Start(label, len(uniq))

	var mu sync.Mutex
	var wg sync.WaitGroup
	var firstErr error
	sem := make(chan struct{}, 8) // at most 8 concurrent requests

loop:
	for id := range uniq {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			v, err := c.GetVuln(ctx, id)
			bar.Inc()
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
	if firstErr == nil {
		firstErr = ctx.Err()
	}
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

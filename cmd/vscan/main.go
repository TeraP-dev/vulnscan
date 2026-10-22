package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"

	"github.com/TeraP-dev/vulnscan/internal/debver"
	"github.com/TeraP-dev/vulnscan/internal/inventory"
	"github.com/TeraP-dev/vulnscan/internal/osv"
	"github.com/TeraP-dev/vulnscan/internal/pep440"
	"github.com/TeraP-dev/vulnscan/internal/progress"
	"github.com/TeraP-dev/vulnscan/internal/report"
)

const defaultStatus = "/var/lib/dpkg/status"
const usage = `vscan - check installed software against the OSV vulnerability database

Usage:
  vscan [flags]        (with no flags, this help is shown)

Flags:
  -S, --system             scan system packages (dpkg)
  -e, --ecosystem string   OSV ecosystem, e.g. Debian:13 (auto-detected on Debian)
  -s, --status string      dpkg status file (default /var/lib/dpkg/status)
  -p, --pip                scan Python packages instead of system packages
      --python string      Python interpreter used with --pip (default python3)
  -j, --json               machine-readable output
  -a, --all                include findings with no fixed version yet
  -d, --details            list every finding instead of one line per package
  -f, --fix                list the findings and print an apt command that upgrades them
  -v, --version            print version and exit
  -h, --help               show this help

Any flag other than -v and -h starts a scan; system packages are scanned
unless you pass -p.

Examples:
  vscan -S                      scan this machine's system packages
  vscan -e Debian:13            choose the ecosystem yourself (e.g. on Kali)
  vscan -f                      list findings and print the apt command to fix them
  vscan -p                      scan the Python packages of python3 on your PATH
  vscan -p --python ./venv/bin/python
  vscan -j | jq .               JSON output

Needs internet access: package names and versions are sent to api.osv.dev.
Press Ctrl+C while scanning to cancel.

Exit codes: 0 no findings, 1 findings, 2 error, 130 interrupted
`

type options struct {
	ecosystem, statusPath, python string
	pip, system                   bool
	asJSON, all, details, fix     bool
}

// target is one installed thing to look up in OSV.
type target struct {
	name     string   // name as queried
	version  string   // version as queried
	display  string   // name shown to the user
	binaries []string // dpkg only: installed binary packages built from this source
}

// version comes from the module version when installed with "go install ...@vX.Y.Z".
func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "vscan: "+format+"\n", args...)
	os.Exit(2)
}

func main() {
	if len(os.Args) == 1 {
		fmt.Print(usage)
		return
	}
	var o options
	var showVersion, help bool
	flag.StringVar(&o.ecosystem, "ecosystem", "", "")
	flag.StringVar(&o.ecosystem, "e", "", "")
	flag.StringVar(&o.statusPath, "status", defaultStatus, "")
	flag.StringVar(&o.statusPath, "s", defaultStatus, "")
	flag.BoolVar(&o.pip, "pip", false, "")
	flag.BoolVar(&o.pip, "p", false, "")
	flag.StringVar(&o.python, "python", "python3", "")
	flag.BoolVar(&o.asJSON, "json", false, "")
	flag.BoolVar(&o.asJSON, "j", false, "")
	flag.BoolVar(&o.all, "all", false, "")
	flag.BoolVar(&o.all, "a", false, "")
	flag.BoolVar(&o.details, "details", false, "")
	flag.BoolVar(&o.details, "d", false, "")
	flag.BoolVar(&o.fix, "fix", false, "")
	flag.BoolVar(&o.fix, "f", false, "")
	flag.BoolVar(&showVersion, "version", false, "")
	flag.BoolVar(&showVersion, "v", false, "")
	flag.BoolVar(&o.system, "system", false, "")
	flag.BoolVar(&o.system, "S", false, "")
	flag.BoolVar(&help, "help", false, "")
	flag.BoolVar(&help, "h", false, "")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if help {
		fmt.Print(usage)
		return
	}
	if showVersion {
		fmt.Println("vscan", version())
		return
	}
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "vscan: unexpected argument %q\n\n", flag.Arg(0))
		flag.Usage()
		os.Exit(2)
	}
	if o.pip && o.ecosystem != "" {
		fatalf("--pip and --ecosystem cannot be combined")
	}
	if o.pip && o.fix {
		fatalf("--fix is not supported with --pip yet")
	}
	if o.pip && o.system {
		fatalf("--pip and --system cannot be combined")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { // after the first Ctrl+C, restore default behavior so a second one force-quits
		<-ctx.Done()
		stop()
	}()

	n, err := run(ctx, o)
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "vscan: interrupted")
		os.Exit(130)
	}
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) {
			fmt.Fprintln(os.Stderr, "vscan: cannot reach api.osv.dev (are you offline?):", err)
		} else {
			fmt.Fprintln(os.Stderr, "vscan:", err)
		}
		os.Exit(2)
	}
	if n > 0 {
		os.Exit(1)
	}
}

func run(ctx context.Context, o options) (int, error) {
	ecosystem := o.ecosystem
	compare := debver.Compare
	var line func(string) string // compatibility line of a version; nil when not applicable
	var targets []target
	var err error
	if o.pip {
		ecosystem, compare, line = "PyPI", pep440.Compare, pep440.Line
		targets, err = pipTargets(ctx, o.python)
	} else {
		if ecosystem == "" {
			if ecosystem, err = detectEcosystem("/etc/os-release"); err != nil {
				return 0, err
			}
		}
		targets, err = dpkgTargets(o.statusPath)
	}
	if err != nil {
		return 0, err
	}

	queries := make([]osv.Query, len(targets))
	for i, t := range targets {
		queries[i] = osv.Query{
			Package: osv.Package{Name: t.name, Ecosystem: ecosystem},
			Version: t.version,
		}
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
	for i, t := range targets {
		returned := map[string]bool{}
		for _, id := range ids[i] {
			returned[id] = true
		}
		for _, id := range ids[i] {
			v := vulns[id]
			if v == nil || superseded(v, returned) {
				continue
			}
			fixed := strings.Join(v.FixedVersions(t.name, ecosystem), ", ")
			if fixed == "" && !o.all {
				hidden++
				continue
			}
			findings = append(findings, report.Finding{
				Package:  t.display,
				Version:  t.version,
				ID:       id,
				Score:    v.ScoreWithUpstream(vulns),
				Fixed:    fixed,
				Summary:  v.Summary,
				Binaries: t.binaries,
			})
		}
	}
	report.Sort(findings)
	sums := report.Summarize(findings, compare, line)

	switch {
	case o.asJSON:
		err = report.JSON(os.Stdout, findings)
	case o.fix:
		// Findings go to stderr so that stdout carries only the command.
		if o.details {
			report.Table(os.Stderr, findings)
		} else {
			report.SummaryTable(os.Stderr, sums)
		}
		fmt.Fprintln(os.Stderr)
		if cmd := report.FixCommand(sums); cmd != "" {
			fmt.Println(cmd)
		}
	case o.details:
		report.Table(os.Stdout, findings)
	default:
		report.SummaryTable(os.Stdout, sums)
	}
	if !o.asJSON {
		var notes []string
		if !o.details && !o.fix {
			notes = report.Notes(sums)
		}
		fmt.Fprintln(os.Stderr)
		for _, n := range notes {
			fmt.Fprintln(os.Stderr, n)
		}
		if len(notes) > 0 {
			fmt.Fprintln(os.Stderr)
		}
		fmt.Fprintf(os.Stderr, "%d packages scanned against %s: %d findings in %d packages",
			len(targets), ecosystem, len(findings), len(sums))
		if hidden > 0 {
			fmt.Fprintf(os.Stderr, " (%d more with no fix available; use --all)", hidden)
		}
		fmt.Fprintln(os.Stderr)
		if !o.details && !o.fix && !o.pip && len(sums) > 0 {
			fmt.Fprintln(os.Stderr, "Run vscan -f for an apt command that applies these upgrades.")
		}
	}
	return len(findings), err
}

// dpkgTargets groups installed packages by (source package, source version),
// which is how Debian advisories are keyed.
func dpkgTargets(statusPath string) ([]target, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pkgs, err := inventory.ParseDpkgStatus(f)
	if err != nil {
		return nil, err
	}
	type key struct{ src, ver string }
	idx := map[key]int{}
	var out []target
	for _, p := range pkgs {
		k := key{p.Source, p.QueryVersion()}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, target{name: k.src, version: k.ver, display: k.src})
		}
		out[i].binaries = append(out[i].binaries, p.Name)
	}
	return out, nil
}

func pipTargets(ctx context.Context, python string) ([]target, error) {
	pkgs, err := inventory.ListPython(ctx, python)
	if err != nil {
		return nil, err
	}
	out := make([]target, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, target{
			name:    osv.NormalizeName("PyPI", p.Name),
			version: p.Version,
			display: p.Name,
		})
	}
	return out, nil
}

// superseded reports whether v is a PYSEC record already covered by another
// returned record (the same bug usually also has a GHSA record with severity).
func superseded(v *osv.Vuln, returned map[string]bool) bool {
	if !strings.HasPrefix(v.ID, "PYSEC-") {
		return false
	}
	for _, a := range v.Aliases {
		if returned[a] {
			return true
		}
	}
	return false
}

// scan does all the network work: batch query, advisory details, and the
// DEBIAN-CVE-* records that supply severity for DLA/DSA advisories.
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

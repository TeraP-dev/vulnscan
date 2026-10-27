# vulnscan

[![ci](https://github.com/TeraP-dev/vulnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/TeraP-dev/vulnscan/actions/workflows/ci.yml)

Check the software installed on your machine against the [OSV](https://osv.dev)
vulnerability database and see **what to upgrade, and to which version**.

- System packages on Debian and Ubuntu (via dpkg) and Python packages (via pip)
- One line per package, ranked by severity, with the version to upgrade to
- Prints the `apt` command that applies the fixes; it never runs anything itself

Made this because the free tool for this job on Windows (Secunia PSI) was retired in 2018, and most
Linux scanners target containers and CI rather than your own machine.
Also, this project is vibecoded (lol) so do your own research before using it, I'm not responsible for any losses, the project is under MIT license.

## Example

```
$ vscan -e Debian:11 -s testdata/old-status     # old OpenSSL fixture included in the repo
SEVERITY  PACKAGE  INSTALLED         UPGRADE TO        FINDINGS
CRITICAL  openssl  1.1.1n-0+deb11u1  1.1.1w-0+deb11u5  9
```

Advisories change over time, so the numbers you see may differ.

## Install

```
go install github.com/TeraP-dev/vulnscan/cmd/vscan@latest    # needs Go; installs to ~/go/bin
```

Or download the Linux binary (amd64/arm64) from
[Releases](https://github.com/TeraP-dev/vulnscan/releases), check it against
`checksums.txt`, and put `vscan` on your `PATH`.

## Usage

```
vscan -S              # scan system packages (Debian and Ubuntu are auto-detected)
vscan -e Debian:13    # pick the ecosystem yourself, e.g. on Kali
vscan -f              # list the findings and print the apt command that fixes them
vscan -p              # scan Python packages instead
vscan                 # no flags: show help
```

```
-S, --system       scan system packages (dpkg)
-e, --ecosystem    OSV ecosystem, e.g. Debian:13 or Ubuntu:22.04:LTS
-s, --status       dpkg status file (default /var/lib/dpkg/status)
-p, --pip          scan Python packages instead
    --python       interpreter for --pip (default python3)
-j, --json         JSON output, one entry per finding
-a, --all          include findings with no fix yet
-d, --details      one line per finding instead of per package
-f, --fix          list findings and print an apt command that upgrades them
-v, --version      print version
-h, --help         show help
```

Exit codes: `0` no findings, `1` findings, `2` error, `130` interrupted
(Ctrl+C cancels a scan). Progress is shown on stderr only when it is a terminal,
so piped output stays clean.

## Reading the output

- **SEVERITY**: highest CVSS base score among the package's findings (CRITICAL
  9.0+, HIGH 7.0+, MEDIUM 4.0+, LOW below; UNKNOWN = no score). On Ubuntu, when
  there is no CVSS score, Ubuntu's own priority is used.
- **UPGRADE TO**: upgrade to this version **or newer** to resolve all findings.
  For each advisory it takes the lowest fix above your version, then the highest
  of those. On Kali, `2.1.13-stable-1` counts as newer than
  `2.1.13-stable-1~deb13u1`.
- **FINDINGS**: number of advisories that affect your version (`-d` lists them).

## Fixing system packages

`vscan -f` prints the findings to stderr and the command to stdout, so
`vscan -f > fix.sh` captures just the command. It never runs it:

```
sudo apt update && sudo apt install --only-upgrade \
  libssl1.1
```

- It only upgrades packages you already have; apt shows its plan and asks first.
- Your repositories decide which versions exist. Run `vscan` again afterwards to
  see what is left.
- On rolling distributions such as Kali, check the distribution's guidance on
  partial upgrades first.
- Package names are validated, so a crafted status file cannot inject shell syntax.

## Python packages

```
$ vscan -p --python /tmp/oldenv/bin/python     # a virtualenv with requests 2.25.0, urllib3 1.26.4
SEVERITY  PACKAGE   INSTALLED  UPGRADE TO  FINDINGS
HIGH      urllib3   1.26.4     2.8.0       11
MEDIUM    idna      2.10       3.15        2
MEDIUM    requests  2.25.0     2.33.0      4
MEDIUM    pip       26.1.2     26.2.0      1
```

- One interpreter per run; `--python` selects a virtualenv.
- `UPGRADE TO` fixes everything, so it can be a major-version jump (urllib3 1.x
  to 2.x). A note on stderr then shows the best fix that stays on your major version.
- `--fix` is not supported for Python yet.

## How it works

Installed packages are read from the dpkg status file and grouped by source
package and version (how Debian and Ubuntu key their advisories), then sent to
the OSV API in batches. Each matching advisory supplies the fixed version;
severity comes from CVSS v3/v4, taken from the `DEBIAN-CVE-*` records behind
Debian advisories. On Ubuntu, per-CVE records are kept and the `USN` notices
that duplicate them are dropped. For Python, the inventory comes from `pip list`,
names follow PEP 503, versions are ordered by PEP 440, and duplicate
`PYSEC`/`GHSA` records are collapsed.

## Limitations

- **Debian and Ubuntu via dpkg only.** For other dpkg-based distributions pass
  `--ecosystem`. Ubuntu is tested against a fixture, not yet on a real machine.
  For Ubuntu Pro (ESM) fixes use e.g. `-e Ubuntu:Pro:22.04:LTS`.
- **Kali is best-effort.** OSV has no Kali ecosystem, so use the Debian release
  Kali tracks and expect some mismatches.
- **Not scanned:** npm, snap, Go binaries, anything installed by hand.
- **Findings with no fix are hidden** (`-a` shows them; expect noise). "No fix"
  in the data does not mean you are safe or unpatched.
- **Severity is CVSS, not exploitability.**
- **Needs internet.** Package names and versions (nothing else) are sent to
  `api.osv.dev`; nothing is cached. With `--pip`, vscan also runs
  `<python> -m pip list` locally.
- Multi-arch packages are not architecture-qualified in `--fix` output, and very
  large result sets may be truncated (OSV pagination is not followed).

## License

MIT
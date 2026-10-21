# vulnscan

[![ci](https://github.com/TeraP-dev/vulnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/TeraP-dev/vulnscan/actions/workflows/ci.yml)

Check the software installed on your machine against the [OSV](https://osv.dev) vulnerability database and see **what to upgrade, and to which version**.

- Scans system packages on Debian-family Linux (via dpkg) and Python packages (via pip)
- One line per package, ranked by severity, with the version to upgrade to
- Prints the `apt` command that applies the fixes. It never runs anything itself.

It exists because the free tool for this job on Windows (Secunia PSI) was retired in 2018, and most Linux scanners are built for containers and CI pipelines rather than for checking your own machine.

## Example

The repository includes a small test file with an old OpenSSL, so you can
reproduce this:

```
$ vscan -e Debian:11 -s testdata/old-status
SEVERITY  PACKAGE  INSTALLED         UPGRADE TO        FINDINGS
CRITICAL  openssl  1.1.1n-0+deb11u1  1.1.1w-0+deb11u5  9

1 packages scanned against Debian:11: 9 findings in 1 packages
Run vscan -f for an apt command that applies these upgrades.
```

Advisories are published all the time, so the numbers you see may differ.

## Install

Requires Go (see `go.mod` for the minimum version).

```
go install github.com/TeraP-dev/vulnscan/cmd/vscan@latest
```

Go installs into `~/go/bin`. If `vscan` is not found afterwards, add that
folder to your `PATH`.

## Quick start

```
vscan                 # scan system packages (Debian is auto-detected)
vscan -e Debian:13    # choose the ecosystem yourself, e.g. on Kali
vscan -f              # print the apt command that applies the upgrades
vscan -d              # list every advisory instead of one line per package
vscan -p              # scan Python packages instead
```

## Reading the output

| Column | Meaning |
|---|---|
| SEVERITY | Highest CVSS base score among the package's findings: CRITICAL (9.0+), HIGH (7.0+), MEDIUM (4.0+), LOW (below 4.0), UNKNOWN (no score available) |
| PACKAGE | Source package (system) or package name (Python) |
| INSTALLED | The version you have |
| UPGRADE TO | Upgrade to this version **or newer** to resolve all listed findings |
| FINDINGS | Number of advisories that affect your installed version |

**How `UPGRADE TO` is chosen:** for each advisory, the lowest fixed version that
is newer than yours; for the package, the highest of those. On Kali, a version
without Debian's suffix still counts: `2.1.13-stable-1` is newer than
`2.1.13-stable-1~deb13u1`.

Progress is shown on stderr while scanning (only when stderr is a terminal), so
piping the output stays clean. Press Ctrl+C to cancel.

## Usage

```
vscan [flags]
```

| Flag | Meaning |
|---|---|
| `-e`, `--ecosystem` | OSV ecosystem, e.g. `Debian:13` (auto-detected on Debian) |
| `-s`, `--status` | dpkg status file (default `/var/lib/dpkg/status`) |
| `-p`, `--pip` | Scan Python packages instead of system packages |
| `--python` | Python interpreter used with `--pip` (default `python3`) |
| `-j`, `--json` | Machine-readable output, one entry per finding |
| `-a`, `--all` | Include findings with no fixed version yet |
| `-d`, `--details` | List every finding instead of one line per package |
| `-f`, `--fix` | Print an apt command that upgrades the affected packages |
| `-v`, `--version` | Print version and exit |
| `-h`, `--help` | Show help |

Exit codes: `0` no findings, `1` findings reported, `2` error, `130` interrupted.

## Fixing system packages

`vscan -f` prints a command and nothing else. You decide whether to run it:

```
$ vscan -e Debian:11 -s testdata/old-status -f
sudo apt update && sudo apt install --only-upgrade \
  libssl1.1
```

- It only upgrades packages that are already installed (`--only-upgrade`).
- apt shows its plan and asks before changing anything. Read it.
- Your configured repositories decide which versions are available. They may not
  offer the exact fix yet. Run `vscan` again afterwards to see what is left.
- On rolling distributions such as Kali, check the distribution's guidance on
  partial upgrades before cherry-picking packages.
- Package names are validated before they are put in the command, so a crafted
  status file cannot inject shell syntax.
- Multi-arch packages (for example `libc6:i386`) are not architecture-qualified.

## Python packages

`vscan -p` checks what `python3 -m pip list` reports. Use `--python` to scan a
virtualenv or another interpreter:

```
$ python3 -m venv /tmp/oldenv && /tmp/oldenv/bin/pip install 'requests==2.25.0' 'urllib3==1.26.4'
$ vscan -p --python /tmp/oldenv/bin/python
SEVERITY  PACKAGE   INSTALLED  UPGRADE TO  FINDINGS
HIGH      urllib3   1.26.4     2.8.0       11
MEDIUM    idna      2.10       3.15        2
MEDIUM    requests  2.25.0     2.33.0      4
MEDIUM    pip       26.1.2     26.2.0      1
```

- One interpreter per run. Scan each environment separately.
- `UPGRADE TO` resolves **all** listed findings, so it can be a major-version
  jump (above, urllib3 1.x to 2.x). Use `-d` to see each advisory's fix.
- When the full fix needs a new major version, a note on stderr shows the best
  fix that stays on your current one and how many findings it resolves.
- Some advisories have no severity and show as `UNKNOWN`.
- `--fix` is not supported for Python yet.

## How it works

**System packages**

1. Reads installed packages from the dpkg status file and groups them by source
   package and source version, which is how Debian advisories are keyed.
2. Sends them to the OSV API in batches.
3. Fetches each matching advisory for its fixed version. Debian security
   advisories (DSA/DLA) carry no score, so the score is taken from the
   `DEBIAN-CVE-*` records they reference.
4. Ranks by CVSS base score (v3 and v4 supported), groups findings by package,
   and prints one line per package.

**Python packages**

Same flow, but the inventory comes from `pip list`, names are normalized as in
PEP 503, versions are compared with PEP 440 rules, and duplicate `PYSEC`/`GHSA`
records for the same bug are collapsed.

## Limitations

- **System packages: Debian-family only, via dpkg.** Auto-detection supports
  Debian; for other dpkg-based distributions pass `--ecosystem` yourself. Ubuntu
  is untested.
- **Kali is best-effort.** OSV has no Kali ecosystem, so use the Debian release
  Kali currently tracks. Kali runs ahead of stable Debian, so expect some
  mismatches.
- **Not scanned:** software installed outside dpkg and pip (npm, snap, Go
  binaries, anything installed by hand).
- **"No fix" is hidden by default.** A finding with no fixed version means the
  advisory data lists none. It does not mean your system is safe or unpatched.
  Use `--all` to see these; expect noise.
- **Severity is a CVSS base score**, not a measure of how likely exploitation
  is. Findings with no score show as `UNKNOWN`.
- **Network use.** Package names and versions of everything scanned are sent to
  `api.osv.dev`. Nothing else, such as your hostname, is sent. With `--pip`,
  vscan also runs `<python> -m pip list` locally.
- Results with very many vulnerabilities for a single package may be truncated
  (OSV pagination is not followed yet).

## License

MIT
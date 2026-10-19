# vulnscan

[![ci](https://github.com/TeraP-ctf/vulnscan/actions/workflows/ci.yml/badge.svg)](https://github.com/TeraP-ctf/vulnscan/actions/workflows/ci.yml)

A small CLI that checks the packages installed on a Debian-based Linux system
against the [OSV](https://osv.dev) vulnerability database and tells you which
ones have a known vulnerability **and a fix you can install**.

It exists because the free tool for this job on Windows (Secunia PSI) was
retired in 2018, and most Linux scanners are built for containers and CI
pipelines rather than for checking your own machine.

## Example

```
$ vscan -e Debian:11 -s testdata/old-status
SEVERITY  PACKAGE  INSTALLED         FIXED IN          ID
CRITICAL  openssl  1.1.1n-0+deb11u1  1.1.1n-0+deb11u6  DLA-3942-1
CRITICAL  openssl  1.1.1n-0+deb11u1  1.1.1w-0+deb11u2  DLA-3942-2
HIGH      openssl  1.1.1n-0+deb11u1  1.1.1w-0+deb11u4  DLA-4321-1
...
1 packages scanned against Debian:11, 9 findings
```

## Install

Requires Go (see `go.mod` for the minimum version).

```
go install github.com/TeraP-ctf/vulnscan/cmd/vscan@latest
```

## Usage

```
vscan [flags]

  -e, --ecosystem string   OSV ecosystem, e.g. Debian:13 (auto-detected on Debian)
  -s, --status string      dpkg status file (default /var/lib/dpkg/status)
  -j, --json               machine-readable output
  -a, --all                include findings with no fixed version yet
  -v, --version            print version and exit
  -h, --help               show this help
```

Exit code: `0` no findings, `1` findings reported, `2` error.

## How it works

1. Reads installed packages from the dpkg status file and groups them by
   source package and source version, which is how Debian advisories are keyed.
2. Sends them to the OSV API in batches.
3. Fetches each matching advisory for its severity and fixed version. Debian
   security advisories (DSA/DLA) carry no score, so the score is taken from the
   `DEBIAN-CVE-*` records they reference.
4. Sorts by CVSS base score (v3 and v4 supported) and prints a table.

## Limitations

- **Debian-family only, via dpkg.** Packages installed by pip, npm, snap or by
  hand are not scanned. Auto-detection supports Debian; for other dpkg-based
  distributions pass `--ecosystem` yourself. Ubuntu is untested.
- **Kali is best-effort.** OSV has no Kali ecosystem, so use the Debian release
  Kali currently tracks. Kali runs ahead of stable Debian, so expect some
  mismatches.
- **"No fix" is hidden by default.** A finding with no fixed version means
  Debian's data lists none. It does not mean your system is safe or unpatched.
  Use `--all` to see these; expect noise.
- **Severity is a CVSS base score**, not a measure of how likely exploitation
  is. Findings with no score show as `UNKNOWN`.
- **Network use.** Package names and versions of everything installed are sent
  to `api.osv.dev`. Nothing else, such as hostname, is sent.
- Results with very many vulnerabilities for a single package may be truncated
  (OSV pagination is not followed yet).

## License

MIT
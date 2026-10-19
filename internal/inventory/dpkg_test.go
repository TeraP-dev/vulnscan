package inventory

import (
	"strings"
	"testing"
)

const fixture = `Package: libssl3
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.11-1~deb12u2
Description: Secure Sockets Layer toolkit
 continuation line

Package: removed-pkg
Status: deinstall ok config-files
Version: 1.0

Package: bash
Status: install ok installed
Version: 5.2.15-2
`

func TestParseDpkgStatus(t *testing.T) {
	pkgs, err := ParseDpkgStatus(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("want 2 installed packages, got %d", len(pkgs))
	}
	if pkgs[0].Source != "openssl" || pkgs[1].Source != "bash" {
		t.Errorf("unexpected sources: %+v", pkgs)
	}
}

func TestSourceVersion(t *testing.T) {
	in := "Package: libssl3\nStatus: install ok installed\nSource: openssl (3.0.11-1)\nVersion: 3.0.11-1+b1\n"
	pkgs, _ := ParseDpkgStatus(strings.NewReader(in))
	if pkgs[0].QueryVersion() != "3.0.11-1" {
		t.Errorf("got %q", pkgs[0].QueryVersion())
	}
}

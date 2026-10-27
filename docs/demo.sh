#!/usr/bin/env bash
# Records the README demo. From the repo root:
#   asciinema rec -c ./docs/demo.sh -i 2 --overwrite demo.cast
type_cmd() {
  printf '$ '
  for ((i = 0; i < ${#1}; i++)); do printf '%s' "${1:i:1}"; sleep 0.04; done
  sleep 0.4
  printf '\n'
  bash -c "$1"
  sleep 2.5
}

clear
type_cmd 'vscan -e Debian:11 -s testdata/old-status'
type_cmd 'vscan -e Debian:11 -s testdata/old-status -f'
type_cmd 'vscan -p --python /tmp/demoenv/bin/python'
#!/bin/bash
#
# cato@x13.no, 2026
#
# bpack.sh — pack a file into a self-extracting, paste-able shell snippet.
# Usage: ./bpack.sh FILE   (prints the snippet to stdout)
#
set -uo pipefail

die() {
  echo "Died: $*" >&2
  exit 1
}

###
not_empty() {
  local var_name="$1"
  local val="${!var_name}"
  [[ -n "${val//[[:space:]]/}" ]] || die "Var '$var_name' is empty"
}

###
shquote() {
  local s="${1//\'/\'\\\'\'}"
  printf "'%s'" "$s"
}

###
sha256_of() {
  { sha256sum "$1" 2>/dev/null || shasum -a 256 "$1"; } | cut -d' ' -f1
}

#
# MAIN
#
fname="${1-}"

not_empty fname
[ -f "$fname" ] || die "No such file: $fname"

tmpf="$(mktemp)" || die "mktemp failed"
trap 'rm -f "$tmpf"' EXIT

shortfname="$(basename "$(realpath "$fname")")"
perms_octal="$(stat -c '%04a' "$fname")"
qname="$(shquote "$shortfname")"
expected_sha="$(sha256_of "$fname")"
not_empty expected_sha

{
  echo "set +o history; f=${qname}; want='${expected_sha}';"
  echo 'if [ -e "$f" ]; then echo "File \"$f\" already exists, aborting."; else'
  echo "cat <<'EOT' | base64 -d | gzip -d > \"\$f\""
  gzip -9 -c "$fname" | base64 -w 120 | perl -lpe ''
  echo "EOT"
  echo 'sum="$( { sha256sum "$f" 2>/dev/null || shasum -a 256 "$f"; } )"; got="${sum%% *}";'
  echo "if [ \"\$got\" = \"\$want\" ]; then chmod ${perms_octal} \"\$f\"; echo \"Unpacked OK: \$f\"; else rm -f \"\$f\"; echo \"Checksum mismatch; removed \$f\" >&2; fi;"
  echo "fi; set -o history;"
} > "$tmpf"

echo
cat "$tmpf"
echo

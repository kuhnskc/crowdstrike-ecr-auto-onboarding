#!/usr/bin/env bash
# Fails if ecr-lambda-source.zip contains credentials, stray source copies,
# or a handler that differs from src/lambda/ecr_auto_onboard_production.py.
set -euo pipefail

ZIP="${1:-ecr-lambda-source.zip}"
HANDLER=ecr_auto_onboard_production.py
fail=0

if unzip -Z1 "$ZIP" | grep -qE '^(src|manual|cloudformation)/'; then
  echo "FAIL: $ZIP contains repo source directories (src/, manual/ or cloudformation/):"
  unzip -Z1 "$ZIP" | grep -E '^(src|manual|cloudformation)/' | head
  fail=1
fi

if ! diff -q <(unzip -p "$ZIP" "$HANDLER") "src/lambda/$HANDLER" >/dev/null; then
  echo "FAIL: $HANDLER inside $ZIP differs from src/lambda/$HANDLER; rebuild the zip"
  fail=1
fi

# Assignments of a 32-hex client id or 40-char secret to CLIENT_ID / CLIENT_SECRET style names
pattern="(client_?id|client_?secret)['\"]?\]?[[:space:]]*[:=][[:space:]]*['\"][0-9A-Za-z]{32,40}['\"]"
while IFS= read -r f; do
  case "$f" in */) continue ;; esac
  if unzip -p "$ZIP" "$f" 2>/dev/null | grep -aiqE "$pattern"; then
    echo "FAIL: possible hardcoded credential in $ZIP:$f"
    fail=1
  fi
done < <(unzip -Z1 "$ZIP")

[ "$fail" -eq 0 ] && echo "OK: $ZIP is clean"
exit "$fail"

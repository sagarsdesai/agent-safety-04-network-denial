#!/usr/bin/env bash
set -euo pipefail
export NO_COLOR=1

OPEN_SHELL="${OPEN_SHELL:-/usr/bin/openshell}"
SANDBOX="${SANDBOX:-sentry-first}"
URL="https://api.github.com/zen"

mkdir -p .local evidence
run_dir="$(mktemp -d .local/network-denial.XXXXXX)"

"$OPEN_SHELL" sandbox get "$SANDBOX" --policy-only \
  > "$run_dir/policy-before.yaml"

"$OPEN_SHELL" sandbox get "$SANDBOX" \
  > "$run_dir/status-before.txt"

started="$(date +%s.%N)"

if "$OPEN_SHELL" sandbox exec "$SANDBOX" -- \
    /usr/bin/curl --verbose --connect-timeout 5 --max-time 15 \
    "$URL" > "$run_dir/request.txt" 2>&1; then
  request_rc=0
else
  request_rc=$?
fi

# Allow time for the supervisor's event to reach the gateway.
found=0
for attempt in 1 2 3 4 5; do
  "$OPEN_SHELL" logs "$SANDBOX" --since 5m \
    > "$run_dir/logs.txt" 2> "$run_dir/log-warnings.txt"

  awk -v start="$started" '
    /^\[[0-9]+\.[0-9]+\]/ {
      stamp = $1
      gsub(/[][]/, "", stamp)
      if ((stamp + 0) >= (start + 0) &&
          index($0, "NET:OPEN") &&
          index($0, "DENIED /usr/bin/curl(") &&
          index($0, "api.github.com:443") &&
          index($0, "transparent_tcp_policy_denied"))
        print
    }
  ' "$run_dir/logs.txt" > "$run_dir/denial.txt"

  if [ -s "$run_dir/denial.txt" ]; then
    found=1
    break
  fi
  sleep 1
done

"$OPEN_SHELL" sandbox get "$SANDBOX" --policy-only \
  > "$run_dir/policy-after.yaml"

"$OPEN_SHELL" sandbox get "$SANDBOX" \
  > "$run_dir/status-after.txt"

cat "$run_dir/request.txt"
printf '\nRequest command exit status: %s\n' "$request_rc"

if [ "$request_rc" -eq 0 ] || [ "$found" -ne 1 ]; then
  printf 'NOT PASSED: expected failure plus a fresh matching denial.\n'
  printf 'Inspect local diagnostics: %s\n' "$run_dir"
  exit 1
fi

if ! cmp -s "$run_dir/policy-before.yaml" "$run_dir/policy-after.yaml"; then
  printf 'NOT PASSED: effective policy changed during validation.\n'
  exit 1
fi

for state in before after; do
  if ! grep -Eq '^[[:space:]]*Phase: Ready[[:space:]]*$' \
      "$run_dir/status-$state.txt"; then
    printf 'NOT PASSED: sandbox was not Ready %s the request.\n' "$state"
    exit 1
  fi
done

grep -E '^[[:space:]]*Revision:' "$run_dir/status-before.txt" \
  > "$run_dir/revision-before.txt"
grep -E '^[[:space:]]*Revision:' "$run_dir/status-after.txt" \
  > "$run_dir/revision-after.txt"

if ! cmp -s "$run_dir/revision-before.txt" "$run_dir/revision-after.txt"; then
  printf 'NOT PASSED: policy revision changed during validation.\n'
  exit 1
fi

report="evidence/$(basename "$run_dir").txt"
{
  printf 'URL: %s\n' "$URL"
  printf 'Request start, Unix seconds: %s\n' "$started"
  printf 'Request command exit status: %s\n' "$request_rc"
  printf 'Sandbox Ready before and after: yes\n'
  printf 'Effective policy and revision unchanged: yes\n'
  cat "$run_dir/revision-after.txt"
  cat "$run_dir/denial.txt"
  printf 'PASS: fresh executable-attributed network-policy denial.\n'
} > "$report"

cat "$report"
printf '\nEvidence: %s\nRaw local diagnostics: %s\n' "$report" "$run_dir"

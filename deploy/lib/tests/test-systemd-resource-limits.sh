#!/usr/bin/env bash
# Checkpoint 7 §10-12/§24-K: static regression coverage for the small,
# conservative resource-safety bounds on the two vpn1 systemd units — a
# leaked credential, accidental large workload, or a runaway/leaking
# process must not be able to trivially exhaust the whole host. Not a
# claim these values are "correct" for every VPS size, just that they
# exist and stay in the intended (proportional, not a fixed guessed
# byte value) shape.
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SINGBOX_UNIT="$REPO_ROOT/deploy/almalinux/systemd/sing-box.service"
SUBSCRIPTION_UNIT="$REPO_ROOT/deploy/almalinux/systemd/vpn-subscription.service"

failures=0
assert_contains() {
  local file="$1" pattern="$2" desc="$3"
  if grep -qE "$pattern" "$file"; then
    echo "ok: $desc"
  else
    echo "FAIL: $desc (pattern [$pattern] not found in $file)"
    failures=$((failures + 1))
  fi
}

echo "--- sing-box.service ---"
assert_contains "$SINGBOX_UNIT" '^LimitNOFILE=[0-9]+$' \
  "sing-box.service sets an explicit file-descriptor limit"
assert_contains "$SINGBOX_UNIT" '^Restart=on-failure$' \
  "sing-box.service restarts on failure"
assert_contains "$SINGBOX_UNIT" '^RestartSec=[0-9]+$' \
  "sing-box.service has an explicit restart delay (paired with systemd's default start-limit throttling)"
# A PERCENTAGE, not a fixed byte value — the whole point is that it
# scales with host size instead of being wrong for either a 512MB or a
# 16GB VPS. MemoryMax (a hard OOM-killing cap) is deliberately NOT set —
# see the unit file's own comment for why a universal safe hard limit
# doesn't exist across this project's supported VPS size range.
assert_contains "$SINGBOX_UNIT" '^MemoryHigh=[0-9]+%$' \
  "sing-box.service sets a proportional (percentage) soft memory governor, not a fixed byte value"
if grep -qE '^MemoryMax=' "$SINGBOX_UNIT"; then
  echo "FAIL: sing-box.service sets a hard MemoryMax — this project deliberately avoids a universal hard memory cap (see Checkpoint 7 §12)"
  failures=$((failures + 1))
else
  echo "ok: sing-box.service does not set a hard MemoryMax"
fi

echo
echo "--- vpn-subscription.service ---"
assert_contains "$SUBSCRIPTION_UNIT" '^Restart=on-failure$' \
  "vpn-subscription.service restarts on failure"
assert_contains "$SUBSCRIPTION_UNIT" '^MemoryHigh=[0-9]+%$' \
  "vpn-subscription.service sets a proportional soft memory governor"
assert_contains "$SUBSCRIPTION_UNIT" '^IPAddressAllow=127\.0\.0\.0/8 ::1/128$' \
  "vpn-subscription.service stays loopback-only (unchanged, re-asserted here for context)"

echo
if [ "$failures" -gt 0 ]; then
  echo "$failures test(s) FAILED"
  exit 1
fi
echo "all tests passed"

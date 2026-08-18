# DEVICE_ACCEPTANCE_TESTS.md

Automated CI cannot validate a real Hiddify/v2rayNG import on a real
iOS/Android/MagicOS/Linux/Windows/macOS device against a real VPS — this
document is the explicit manual test matrix for that, per the honesty
rule already established in `docs/CLIENT_COMPATIBILITY.md`: a cell only
ever changes to PASS after a dated, filled-in entry exists below, never
from spec conformance or code review alone.

## Matrix

| Platform | Client | VLESS+REALITY | Hysteria2 | Subscription refresh | Network switch | DNS leak | Streaming (QUIC-heavy app) |
|---|---|---|---|---|---|---|---|
| iOS | Hiddify | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested |
| Android | Hiddify | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested |
| HONOR MagicOS | Hiddify | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested |
| Android | v2rayNG | not yet tested | N/A (unsupported/not guaranteed — see `docs/clients/V2RAYNG_ANDROID.md`) | not yet tested | not yet tested | not yet tested | not yet tested |
| Linux | Hiddify | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested |
| Windows | Hiddify | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested |
| macOS | Hiddify | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested | not yet tested |

## What each column means

- **VLESS+REALITY** / **Hysteria2**: the client successfully connects
  through that transport specifically (switch to it manually if the
  client auto-selects the other one first) and traffic actually egresses
  through the VPS (e.g. `curl ifconfig.me` shows the VPS's IP).
- **Subscription refresh**: after `vpn-admin user rotate-token` or
  `vpn-admin user rotate-vless`/`rotate-hysteria`, re-importing/
  refreshing the subscription in the client picks up the new
  credentials and the old ones stop working.
- **Network switch**: the connection survives (or promptly reconnects
  after) switching from Wi-Fi to mobile data and back, and after a
  screen-off idle period (mobile platforms).
- **DNS leak** (added 2026-08-18, previously had no column at all — see
  `docs/CLIENT_PROTOCOL_BEHAVIOR.md`'s DNS section for why this project
  cannot verify this from the server side): run a DNS-leak test (e.g.
  https://dnsleaktest.com from the connected device) with the VPN off,
  then again with it connected on each transport. PASS means the
  connected result shows only resolvers associated with the VPS/its
  provider, never the carrier's/Wi-Fi's own resolver. Record the actual
  resolver IPs/ASNs seen in each state, not just PASS/FAIL.
- **Streaming (QUIC-heavy app)** (added 2026-08-18, prompted by a real
  production report of YouTube's iOS app failing to play video while
  Safari and ordinary HTTPS worked — see that investigation's report for
  the full hypothesis list): with each transport selected explicitly,
  confirm actual sustained video/call playback in a QUIC-using native
  app (e.g. YouTube), not just that the app opens or an IP-check page
  loads. Record app name/version, whether QUIC could be forced off in
  that app or at the network level for comparison, and whether the
  result differs between transports.

## How to actually run this

Prerequisites:

1. A real AlmaLinux 9 (or Rocky Linux 9) VPS with a public IP and two
   DNS names pointed at it (`vpn.example.com`, `sub.example.com` — see
   `docs/ALMALINUX_DEPLOYMENT.md`).
2. `sudo ./deploy/almalinux/install.sh` run there, completing without
   error (a failed install must not have printed "Install complete" —
   see `docs/PRODUCTION_HARDENING_PLAN.md` #22).
3. `sudo vpn-admin doctor` (or `vpn doctor`) on the VPS reporting no
   `[FAIL]` lines. Also run `sudo vpn-admin doctor --protocol` — it adds
   a best-effort `[L5-6]` check that dials the server's own REALITY
   listener with a throwaway `sing-box` client. Passing `doctor`
   without `--protocol` only proves L1-L4 (process/config/listeners/
   subscription-render-coherence); it does **not** prove a real client
   can authenticate — that is exactly what this whole matrix exists to
   verify by hand, and a real device test below should still be run
   even if both `doctor` variants are fully green.
4. `sudo vpn-admin user create --name test --qr` to get a subscription
   QR code / URL.
5. The device under test, on a real network, with the relevant client
   installed per `docs/clients/`.

For each matrix row (see `docs/CLIENT_PROTOCOL_BEHAVIOR.md` for what
each of the DNS/IPv6/tunnel-drop fields below actually mean and why they
are not something server-side config can guarantee):

```
Date:
Platform:
Client + version:
Device model / OS version:
VPS region / provider:
sing-box version (from `vpn-admin version` on the VPS):

Profile import:          PASS/FAIL
VLESS+REALITY:            PASS/FAIL
Hysteria2:                 PASS/FAIL / NOT TESTED
Subscription refresh:      PASS/FAIL
Network switch:            PASS/FAIL

Observed public IP after connecting (must equal the VPS's public IP):
Required client-side setting (e.g. Hiddify Service Mode = VPN/TUN, not
  Proxy Only — record whatever was actually needed):

DNS leak result (e.g. https://dnsleaktest.com with VPN on vs. off —
  record which resolver/location showed, PASS if it matches the VPS's
  location/ISP, FAIL if your real ISP/location leaked through):
IPv6 result (does the device have IPv6 connectivity at all before
  connecting? If so, does an IPv6-specific leak test show the VPS or
  your real network? N/A if the device/network has no IPv6 at all):
Tunnel-drop behavior (kill the VPS's sing-box process or disable Wi-Fi/
  data briefly — does the client fail closed, fail open, or hang?
  Record what actually happens, do not assume a kill switch exists):

Steps to disable/revoke and prove it took effect:
  1. `vpn-admin user disable test` on the VPS.
  2. Client attempts to reconnect/use the existing session — confirm it
     is rejected (REALITY/Hysteria2 handshake fails, or the client shows
     a connection error) within a reasonable time.
  3. `vpn-admin user enable test`, `vpn-admin user rotate-token test`.
  4. Re-import the new subscription URL on the client and confirm it
     connects again.
Revocation actually took effect: PASS/FAIL

Notes:
```

Paste the filled-in block above as a new dated entry directly below this
line once a real test is run, and update the corresponding matrix cell.

## Performance sanity check (not a benchmark)

Run once per real device/VPS test above, connected via REALITY (repeat
for Hysteria2 if also testing it). This is meant to catch an obvious
stall, fragmentation problem, reconnect failure, or routing break — it
is not a throughput measurement (`vpn benchmark` on the VPS, see
`docs/PERFORMANCE_OPTIMIZATION_PLAN.md`, is the real benchmark tool).

```
Browsing a few ordinary HTTPS sites:        PASS/FAIL (note any that hang/fail)
Sustained download (a large file, 1+ min):   PASS/FAIL (note if it stalls or dies mid-transfer)
Sustained upload (a large file, 1+ min):     PASS/FAIL
Disconnect and reconnect the client:         PASS/FAIL (note how long reconnect took)
Idle 5-10 minutes, then reuse the connection: PASS/FAIL (note if it needed a manual reconnect)

Notes (any stall, unusually slow transfer, or unexpected disconnect):
```

## Telegram-specific matrix

Per `docs/TELEGRAM_RESILIENCE_PLAN.md`: "Telegram works" is not one
test. A cell in this matrix only becomes PASS/FAIL after it is actually
exercised on a real device on a real network — never inferred from the
general matrix above, from `vpn doctor`/`vpn doctor --telegram`, or from
YouTube/Instagram working. See `docs/TELEGRAM_TROUBLESHOOTING.md` for
exact per-row steps (disabling Telegram's own proxy first, switching
transports manually, etc).

| Test                          | Reality | Hysteria2 | Auto |
| ------------------------------ | ------- | --------- | ---- |
| App startup / connects at all  | not yet tested | not yet tested | not yet tested |
| Text messages send/receive     | not yet tested | not yet tested | not yet tested |
| Image download                 | not yet tested | not yet tested | not yet tested |
| Video/media download           | not yet tested | not yet tested | not yet tested |
| Media upload                   | not yet tested | not yet tested | not yet tested |
| Channels (large/high-traffic)  | not yet tested | not yet tested | not yet tested |
| Notifications / background reconnect | not yet tested | not yet tested | not yet tested |
| Voice call                     | not yet tested | not yet tested | not yet tested |
| Video call                     | not yet tested | not yet tested | not yet tested |
| Wi-Fi -> cellular handover      | not yet tested | not yet tested | not yet tested |
| Cellular -> Wi-Fi handover      | not yet tested | not yet tested | not yet tested |
| IPv4-only network               | not yet tested | not yet tested | not yet tested |
| IPv6-preferring network          | not yet tested | not yet tested | not yet tested |

Row-filling template (paste as a new dated entry, one per transport
actually tested):

```
Date:
Location (country/network — do NOT record exact GPS/address, only
  enough to know "Russian residential" vs "Russian mobile" vs "not
  Russia" etc):
ISP / mobile carrier:
Wi-Fi or mobile data:
Client + version:
Device model / OS version:
Hiddify version / sing-box core version (Hiddify -> Settings -> About):
Transport under test: Reality / Hysteria2 / Auto
Telegram internal proxy: confirmed DISABLED before testing (yes/no)

App startup:                    PASS/FAIL
Text messages:                  PASS/FAIL
Image download:                 PASS/FAIL
Video/media download:           PASS/FAIL
Media upload:                   PASS/FAIL
Channels:                       PASS/FAIL
Notifications/background:       PASS/FAIL
Voice call:                     PASS/FAIL
Video call:                     PASS/FAIL

Notes (exact failure mode, timestamps, anything unusual):
```

**This matrix cannot be filled in from outside Russia.** Development
performed on this repository has no way to reproduce Russian
residential/mobile ISP DPI behavior — see
`docs/TELEGRAM_RESILIENCE_PLAN.md` §"Remaining limitations". Every row
above stays "not yet tested" until a real family member/friend on a
real Russian network runs it and reports back.

## Entries

_No entries yet — this document defines the procedure, not a result. Do
not mark any matrix cell PASS without a corresponding entry here._

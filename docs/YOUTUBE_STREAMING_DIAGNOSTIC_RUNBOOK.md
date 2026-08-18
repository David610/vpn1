# YOUTUBE_STREAMING_DIAGNOSTIC_RUNBOOK.md

A production report: iPhone + Hiddify, VPN connects and routes public
traffic through the VPS, YouTube's native app fails to play video over
**both** VLESS+REALITY and Hysteria2, while Safari and ordinary HTTPS
work fine. This document is the real-device test procedure to actually
narrow that down, ordered by diagnostic value — each step is chosen
because its outcome rules several hypotheses in or out, not because
it's easy.

This is the execution of the diagnosis referenced from `TASKS.md`'s
"Phase 16" entry. Nothing in this repository could confirm or reject
the underlying hypotheses without a real device on a real network —
see `docs/CLIENT_PROTOCOL_BEHAVIOR.md` for why MTU, DNS, and IPv6
client behavior are structurally invisible to this project's own
tooling. This runbook exists to close that gap with an actual test,
not another round of code review.

**Budget**: ~45-90 minutes, one iPhone with Hiddify installed, SSH/sudo
access to the VPS. Steps 1-6 need only the phone; step 7 needs the VPS.
Do them in order — each one is cheaper than the next, and several make
the following ones unnecessary once you have an answer.

## Before you start

- **Never share, paste, or commit**: your VLESS UUID, Hysteria2
  password, REALITY private key, Salamander obfuscation password, your
  full subscription URL/token, or a raw, unedited packet capture
  (`.pcap`) file. Step 7 below produces a `.pcap` — it is deleted at
  the end of that step, on purpose; only its metadata-only summary
  (produced by the same step) is safe to keep or share.
- Record your Hiddify app version and build (Hiddify -> Settings ->
  About) and iOS version before you start — `docs/clients/HIDDIFY_IOS.md`
  documents an open, confirmed problem with Hiddify's iOS release
  pipeline (hiddify/hiddify-app#2317); this doesn't prove it's related,
  but it's worth having recorded.
- Every step below tells you exactly what a PASS and a FAIL each prove
  — and, just as importantly, what they *don't*. Don't skip that part
  of the writeup, and don't reach a conclusion a single step can't
  actually support.

## Step 0 — Baseline: does the server-side actually work at all?

Run this before touching the phone. It now covers **both** transports
(it didn't before this investigation — see `TASKS.md`'s Phase 16
entry):

```bash
sudo vpn-admin doctor --protocol --require-protocol
```

- **PASS on both `L5-6` (REALITY) and `L5-6-H2` (Hysteria2)**: this
  server's own listeners, key/password material, and authentication
  path work, dialed from the VPS's own network. This does **not** prove
  reachability from the phone's specific network, MTU, DNS, or Hiddify
  behavior — it only means you can stop suspecting "the server itself
  is broken" and move straight to the phone-side steps below.
- **FAIL on either one**: stop here and fix the server first — the
  failure message tells you which layer. Nothing past this point is
  meaningful until this passes (or until `L5-6-H2` reports its honest
  ceiling: `Inconclusive`/`WARN`, which is not a fail, but means you
  should read `run_hysteria2_client_selftest`'s doc comment in
  `apps/admin/src/main.rs` before trusting it either way).

## Step 1 — Force QUIC/UDP off and retest (highest diagnostic value)

**What this discriminates**: whether the failure is UDP/QUIC-specific
at all. This single test separates roughly half the hypothesis list in
one shot.

1. On the phone, connect via Hiddify (REALITY selected explicitly —
   see Step 6 for why "explicitly").
2. If Hiddify exposes a "block QUIC" / "UDP" toggle, enable it.
   Otherwise: on the Wi-Fi router serving the phone, block outbound
   UDP/443 only (leave TCP/443 open), and run this step over Wi-Fi, not
   cellular (you can't firewall a cellular carrier's network).
3. Open the YouTube app, try to play a video.

| Result | Meaning |
|---|---|
| YouTube now plays | QUIC/UDP handling between the app and the tunnel is implicated (this repo's earlier diagnosis: hypotheses H1/H2/H3/H13/H14). Go to Step 6 next to see if REALITY and Hysteria2 are equally affected. |
| YouTube still fails with QUIC forced off | Not a QUIC-specific problem — go to Steps 3-4 (DNS/IPv6) next, skip ahead of Step 5 (MTU, which mostly matters for QUIC). |

Undo the QUIC block before continuing to other steps.

## Step 2 — Raw sing-box vs. Hiddify (isolates the client app itself)

**What this discriminates**: whether the problem is Hiddify's iOS
TUN/NetworkExtension layer specifically, versus the network path to
the VPS, versus the server.

1. On a laptop on the **same network** as the phone (same Wi-Fi, or
   tethered to the same cellular connection), install upstream
   `sing-box` (not this project's fork — the actual SagerNet release).
2. Fetch your subscription in native JSON form (do this on the laptop,
   not by pasting the URL anywhere public):
   ```bash
   curl -s "https://<your-subscription-host>:<port>/sub/<token>?format=singbox" > sub.json
   ```
3. Run `sing-box run -c sub.json` (or convert it into a minimal client
   config with a local SOCKS inbound if your `sub.json` doesn't already
   have one — see `crates/compat-config/tests/reality_interop.rs` for
   the exact JSON shape a working throwaway client config needs).
4. Through that local SOCKS proxy, download a real multi-megabyte file
   (not just an IP check) — e.g. `curl -x socks5h://127.0.0.1:<port>
   https://speed.cloudflare.com/__down?bytes=25000000 -o /dev/null`.

| Result | Meaning |
|---|---|
| Raw sing-box transfers cleanly | The network path to the VPS and the server are fine at the protocol level. Points at Hiddify's iOS TUN/NetworkExtension layer specifically (H1, H3, H13, H14) — worth filing against Hiddify upstream once you have this data point. |
| Raw sing-box also stalls/fails | Not Hiddify-specific — investigate the network-to-VPS path itself (Steps 5 and 7). |

## Step 3 — DNS comparison (Safari vs. YouTube app)

**What this discriminates**: whether the YouTube app resolves
`googlevideo.com`/`youtubei.googleapis.com`/`ytimg.com` through a
different path than Safari — a real, uninvestigated possibility per
`docs/CLIENT_PROTOCOL_BEHAVIOR.md`'s DNS section (this project's
generated config has no `dns` block at all; DNS is 100% Hiddify's own
behavior).

This project has no server-side way to observe the phone's own DNS
traffic — this is a phone-side-only test.

1. With the VPN connected, install a network-diagnostic app capable of
   a manual DNS lookup (many free "network tools" apps on the App
   Store include this; alternatively, some let you view resolved IPs
   for open connections).
2. In Safari, load `youtube.com` and note which IP(s) it connects to
   (Safari's own dev tools, or a network-tools app's "active
   connections" view, if available).
3. In the YouTube app, attempt playback, then check the same
   network-tools app for what IP(s)/hostnames it's actually talking to.
4. Compare: same IP family (v4 vs v6)? Same general IP range/ASN?

| Result | Meaning |
|---|---|
| Same IPs/family for both apps | DNS routing is not the differentiator — rules H6/H8 down. |
| Materially different IPs, or the YouTube app shows IPv6 addresses Safari doesn't | Consistent with H5/H6/H7/H8 (DNS or IPv6 routing difference) — proceed to Step 4. |

## Step 4 — IPv4-only test

**What this discriminates**: whether IPv6 leakage or a broken IPv6
tunnel path is involved (H5, H7, H27).

1. If iOS or Hiddify exposes an IPv6-off / "IPv4 preferred" option,
   enable it and reconnect.
2. Retest YouTube app playback.

| Result | Meaning |
|---|---|
| YouTube now plays | IPv6 was implicated — check server-side with `sudo vpn-admin doctor` (its "L2" section reports this deployment's AAAA/IPv6-egress posture; see `check_public_hostname_and_ipv6_policy` in `apps/admin/src/main.rs`). If this deployment's AAAA record has unconfirmed egress, that's the actionable finding — pulling the AAAA record is a legitimate, low-risk operator action documented as an option in this project's earlier diagnosis. |
| No change | IPv6 is not the differentiator here. |

## Step 5 — Client-side MTU sweep

**What this discriminates**: whether path MTU/PMTU is truncating or
fragmenting QUIC-heavy traffic (H4/H6/H25). Only meaningful if Step 1
implicated QUIC.

This project deliberately does not apply a global MTU override — see
`docs/TELEGRAM_RESILIENCE_PLAN.md` §J for why a server-side fix can't
work here at all (QUIC's path-MTU discovery happens inside its own
encrypted stream). This is a client-side-only, revert-after experiment.

1. If Hiddify exposes a per-profile MTU override, try 1400, then 1360,
   then 1280 (each is a full disconnect/reconnect), retesting YouTube
   playback after each value.
2. Separately, from the VPS, run the existing MTU/PMTU probe. Point
   `--target-host` at something on the *phone's* actual network path if
   you can (a box you control reachable from that ISP) — the default
   target only characterizes the VPS's own uplink, not the client path
   that actually matters here:
   ```bash
   sudo vpn-benchmark --target-host <best-available-target>
   ```
   Read the "MTU / PMTU" section of its output. A "largest
   non-fragmenting ICMP payload" well under 1472 (i.e. effective path
   MTU well under 1500) is a real PMTU-related finding independent of
   anything sing-box-side.

| Result | Meaning |
|---|---|
| A lower client-side MTU fixes playback | MTU/PMTU confirmed (H4/H6/H25). Record the working value per network/carrier in `docs/DEVICE_ACCEPTANCE_TESTS.md`; this is a path fact, not a vpn1 bug, and has no safe global fix (see `docs/TELEGRAM_RESILIENCE_PLAN.md` §J). |
| No MTU value changes anything | MTU/PMTU is not the cause here — the earlier hypothesis is weakened. |

## Step 6 — REALITY vs. Hysteria2, isolated

**What this discriminates**: whether the failure is genuinely
transport-agnostic (points upstream of both — Hiddify's TUN layer, DNS,
IPv6) or actually asymmetric between the two (points at something
transport-specific after all, e.g. Hysteria2's own QUIC handling, or
REALITY's TCP-over-UDP relay).

1. Fully disconnect. Select **REALITY** explicitly (not auto). Connect.
   Test YouTube.
2. Fully disconnect. Select **Hysteria2** explicitly. Connect. Test
   YouTube.

| Result | Meaning |
|---|---|
| Both fail identically | Confirms the original report — the cause is upstream of both transports (Hiddify's TUN/UDP handling, DNS, or IPv6), not either protocol's own wire format. This was this project's leading hypothesis (H1/H13/H14) going in. |
| Only one fails | The original report characterization was incomplete — re-run Steps 1-5 with the working transport disabled so you're only ever testing the failing one, and treat this as a **new, more specific** bug (transport-specific, not general). |

## Step 7 — Packet capture during a reproduced failure (VPS-side)

**What this discriminates**: whether the client's packets ever reach
the VPS at all (client/carrier-side UDP problem) versus arriving fine
while the stream still stalls (server-side relay or Google-CDN-side
issue). Do this last — it needs you to reproduce the failure live while
the capture runs.

This project already has a purpose-built, safe capture tool for
exactly this — use it instead of a hand-rolled `tcpdump` invocation:
`/opt/vpn1/deploy/lib/vpn-investigate.sh`. It captures **only** the specified
client IP on TCP/443 or UDP/443, with a bounded duration (max 300s) and
a small snap length (headers/early bytes only, never full payload), and
`summarize` reports packet metadata only — timestamps, protocol,
length, TCP flags — never payload content.

1. Get the phone's current public IP (with the VPN connected, from the
   phone itself — e.g. a "what is my IP" page in Safari; this is the
   VPS's own address if the tunnel is up, which is **not** what you
   want here — see the note below).

   **Important**: `vpn-investigate.sh capture` filters by the IP the
   VPS's public interface sees as the *source* of the client's UDP/TCP
   packets — while the tunnel is up, that's the phone's real
   pre-VPN public IP (its carrier/Wi-Fi's own address), not the VPS's
   own IP. Get this from the phone via a cellular/Wi-Fi network
   diagnostic tool, or simply disconnect the VPN briefly and check "what
   is my IP" right before reconnecting and starting the capture.

2. Start the capture on the VPS, then immediately reproduce the
   failure on the phone (open YouTube app, try to play a video) for the
   duration of the capture window:
   ```bash
   sudo /opt/vpn1/deploy/lib/vpn-investigate.sh capture <phone_real_ip> /root/yt-diag.pcap 120
   ```
3. Summarize (metadata only — safe to read, copy, or share):
   ```bash
   sudo /opt/vpn1/deploy/lib/vpn-investigate.sh summarize /root/yt-diag.pcap
   ```
4. **Delete the raw capture** — never keep or share it:
   ```bash
   shred -u /root/yt-diag.pcap
   ```

Read the summary for:
- Any UDP/443 packets from the client at all during the reproduced
  failure — if none, the client/carrier never sent them (implicates
  Hiddify's TUN or the carrier blocking outbound QUIC, not the VPS).
- TCP `rst`/retransmission counts on the REALITY connection during a
  reproduced REALITY-transport failure — a nonzero, elevated count
  during the failure window versus a working baseline is consistent
  with a lossy/degraded path (H1/H3/H24).

## Results — fill this in and copy into `docs/DEVICE_ACCEPTANCE_TESTS.md`

| Step | Result | Notes |
|---|---|---|
| 0. `doctor --protocol --require-protocol` | PASS / FAIL / WARN on which check(s) | |
| 1. QUIC forced off | plays / still fails | |
| 2. Raw sing-box vs. Hiddify | raw sing-box: pass/fail; Hiddify: pass/fail | |
| 3. DNS comparison | same / different IPs, family | |
| 4. IPv4-only | plays / still fails | |
| 5. MTU sweep | working value, if any / no change | |
| 6. REALITY vs. Hysteria2 | both fail / only one fails (which) | |
| 7. Packet capture | client UDP/443 seen: y/n; RST/retrans count | |

Also fill in the **DNS leak** and **Streaming (QUIC-heavy app)** columns
in `docs/DEVICE_ACCEPTANCE_TESTS.md`'s matrix for your platform/client
row, dated, per that document's existing rule: a cell only ever changes
away from "not yet tested" after a real, dated result like this one.

When reporting back, include exactly the fields listed in `docs/
TELEGRAM_TROUBLESHOOTING.md`'s "When reporting a failure, include" /
"Never include" lists — they apply here unchanged.

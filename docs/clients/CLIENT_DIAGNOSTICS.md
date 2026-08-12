# Client-side network diagnostics

Server-side tooling (`deploy/lib/vpn-benchmark.sh`, `vpn doctor
--performance`) can only see the VPS's own CPU, memory, and uplink — it
cannot see the network path between a real user's device and the VPS,
which for users in Russia is frequently the actual bottleneck (ISP-level
QUIC/UDP throttling, DPI interference, peering quality). This script
fills that gap by running from wherever the user actually is.

## Requirements

Python 3.7+ (already present on essentially all Windows 10/11, macOS,
and Linux installs; `python3 --version` to check). No other software,
no admin/root privileges, nothing to install.

## What it collects — and does not

Collected: DNS lookup latency, TCP connect latency to your VPN server,
ICMP ping loss/RTT (via the OS's own `ping` binary — no raw sockets), a
best-effort path-MTU estimate, a baseline HTTPS download-speed sample,
your public exit IP (to confirm whether a VPN was actually active during
a given run), your OS, and a timestamp.

**Never collected**: your subscription URL, UUID, REALITY key, Hysteria2
password, or any vpn1 config file. The script never reads those and has
no code path that could.

## How to run it (recommended: three runs, nothing else changed between them)

```
python3 vpn-client-diag.py --server your.vpn.host --label baseline
```

1. **`--label baseline`** — VPN disconnected.
2. **`--label reality`** — connected via your VLESS+REALITY profile in
   Hiddify.
3. **`--label hysteria2`** — connected via your Hysteria2 profile in
   Hiddify.

Run each 2-3 times if you can (Wi-Fi and mobile data separately, if you
want to compare) — use `--network-label "home wifi"` /
`--network-label "MTS mobile"` etc. to tag which is which; the script
does not detect this automatically.

Add `--json out.json` to also save a file, or just copy the JSON block
the script prints at the end — either is fine to paste back into an
issue or a Claude session.

## Reading the result

- **`public_ip`** is the fastest sanity check: your baseline run should
  show your own ISP's IP; your `reality`/`hysteria2` runs should show
  the VPS's IP. If a "connected" run still shows your ISP's IP, the VPN
  was not actually tunneling traffic during that run — discard it, don't
  compare it.
- **`download.mbps`** is a real-world throughput sample (10 MB from a
  public CDN) — the number to compare across `baseline` vs `reality` vs
  `hysteria2` runs. This is what Phase 4's A/B comparison is built on.
- **`ping.loss_pct` / `rtt_*_ms`** characterize your actual path quality
  independent of vpn1 entirely — high loss or RTT on the *baseline* run
  already tells you part of the story is your ISP path, not the VPN.
- **`pmtu.path_mtu_estimate`** flags a real path-MTU problem if
  meaningfully below 1500 — worth knowing before blaming the tunnel for
  fragmentation-related stalls.

## Interpreting a Hysteria2-worse-than-REALITY result

Do not assume this means Hysteria2's userspace QUIC is CPU-bound on the
server. Multiple major Russian ISPs are documented (see
`docs/PERFORMANCE_OPTIMIZATION_PLAN.md`) to specifically throttle or
drop QUIC/UDP-443 traffic to foreign destinations — a Hysteria2 shortfall
that appears on the `reality` vs `hysteria2` A/B but *not* on
`vpn-benchmark`'s server-side hairpin test is stronger evidence of
ISP-side UDP interference than of CPU exhaustion. Cross-check against
`vpn doctor --performance`'s CPU/steal numbers captured on the VPS
*during* your test run before concluding either way.

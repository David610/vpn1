# Performance Optimization Plan

Status: implemented (P0/P1 items below are shipped). This document is
the evidence trail for those changes and the measurement methodology for
everything that still needs production data.

## How to read this document — claim taxonomy

Every claim below is tagged with exactly one of these four categories.
They are NOT interchangeable, and a prior version of this document
conflated the first and third — that has been corrected throughout:

- **VERIFIED CONFIGURATION/CODE GAP** — confirmed by reading this
  repository directly: some upstream-recommended setting was simply
  absent from the deploy pipeline. This is a fact about the CODE, not a
  fact about this (or any) VPS's actual runtime behavior. It does NOT by
  itself mean this gap was causing the reported slowness — only that it
  was missing and upstream documents it as mattering for this workload.
- **VERIFIED UPSTREAM RECOMMENDATION** — confirmed against current
  sing-box/Hysteria2 documentation or source: the vendor states this
  setting/behavior matters for this class of workload. This is evidence
  FOR closing the configuration gap above; it is still not a measurement
  of this deployment.
- **MEASURED PRODUCTION BOTTLENECK** — an actual before/after or
  comparative measurement, taken on the real production VPS, showing a
  specific component is the limiting factor. **Nothing in this document
  currently carries this tag.** This repository has no access to a
  production VPS; every number `vpn-benchmark`/`vpn doctor --performance`
  would produce has to come from actually running them on the real host
  (see "What to run on the actual VPS" at the end).
- **HYPOTHESIS — needs production measurement** — plausible from the
  architecture and general networking knowledge, but unconfirmed either
  way. Listed with the exact command to confirm or refute it.

**This PR does not claim to have explained the user's reported
slowness.** It closes verified configuration gaps that upstream
documentation says matter for this workload, and it ships the
measurement tooling needed to actually find the real bottleneck. Whether
any of these gaps were the actual cause, partially, or not at all, is
unknown until someone runs the tooling below against the real VPS and
the real client-side network path.

## Executive summary

**Verified configuration/code gaps, closed in this pass (P0/P1):** no
kernel-level UDP buffer or TCP congestion-control tuning existed
anywhere in the deploy pipeline; Hysteria2 had no optional fixed-
bandwidth (Brutal) mode; the sing-box systemd unit had no CPU scheduling
hint; there was no benchmark/performance-diagnostic tooling at all, so
no decision here could previously have been evidence-based in the first
place.

**Deliberately NOT changed:** the subscription's REALITY-by-default
selector — confirmed in the code as an intentional decision from a prior
"Telegram-reliability pass," not an oversight — is left as the default,
with an opt-in `SelectionProfile` mechanism added alongside it rather
than replacing it.

**What remains unknown:** whether any of the above was actually
constraining this user's throughput, and whether CPU/steal/network-path
issues this repository cannot observe are the real limiting factor. See
"Hypotheses — needs production measurement" below, and run the tooling
this pass ships against the real VPS before concluding anything further.

---

## Verified configuration/code gaps (closed this pass)

### G1. No kernel-level UDP socket buffer tuning existed — P0, FIXED

**VERIFIED CONFIGURATION/CODE GAP:** repo-wide search for `sysctl`,
`rmem`, `wmem` across `deploy/`, `crates/`, `apps/`, `services/`
returned zero matches before this pass. `deploy/almalinux/install.sh`'s
staged installer configured OS packages, sing-box, systemd units, TLS,
REALITY keys, nginx, and the firewall — never the kernel network stack.

**VERIFIED UPSTREAM RECOMMENDATION:** the official Hysteria2 performance
guide (`https://v2.hysteria.network/docs/advanced/Performance/`)
recommends raising `net.core.rmem_max`/`net.core.wmem_max` to 16 MiB on
Linux for QUIC/UDP throughput — these are *ceilings* a UDP socket can
request via `setsockopt`, and the stock distro default (a few MB) can
cap Hysteria2's throughput independent of CPU, network, or sing-box's
own code, on a host whose actual traffic needs more.

**Whether this specific VPS was actually hitting that ceiling under real
load is unmeasured** — this is a gap-closure, not a proven fix. See
`vpn doctor --performance`'s UDP receive-buffer-error counters
(`/proc/net/snmp` `Udp: RcvbufErrors`) for the one signal that would
actually confirm sockets were being throttled by this ceiling; a
nonzero, growing count under load is the closest thing to positive
production evidence this repo can point to a method for.

**Fix shipped:** `deploy/lib/perf-tuning.sh`, sourced by
`install.sh`/`update.sh`, writes `/etc/sysctl.d/99-vpn1-dataplane.conf`
with `net.core.rmem_max = 16777216` / `net.core.wmem_max = 16777216`,
idempotently. After applying, it reads back the EFFECTIVE live value via
`sysctl -n` and reports per-value applied/not-applied status — it does
not claim success merely because `sysctl --system` exited 0 (a value can
be silently rejected by the kernel while the overall command still
"succeeds"). See `perf_tuning_apply` in that file.

**Expected benefit:** removes a real, verified-absent ceiling; benefit
is unmeasured on this specific host.

**Downside:** none identified — these are ceilings, not forced
allocations.

**Rollback (now genuinely immediate, no reboot required — see G3 for
why "just delete the file" alone is not sufficient):**
```
sudo deploy/lib/perf-tuning.sh rollback
```

### G2. No TCP congestion-control tuning for the REALITY/TCP path — P0, FIXED

**VERIFIED CONFIGURATION/CODE GAP:** same search as G1 —
`tcp_congestion_control` was never set; the host's distro-default
congestion control (`cubic` on stock AlmaLinux/Ubuntu/Debian kernels)
was left in place for the VLESS+REALITY TCP/443 path.

**VERIFIED UPSTREAM RECOMMENDATION:** BBR is widely documented as better
than cubic for long-lived, potentially lossy connections, because it is
not purely loss-based — cubic treats any packet loss as a congestion
signal and halves its window, a poor fit for non-congestive loss (common
on cross-border routes). This is a general kernel TCP property, not a
sing-box-specific optimization; it applies to any TCP workload on a
lossy path, REALITY included.

**Whether this specific path exhibits the kind of non-congestive loss
BBR is meant to help with is unmeasured.** `vpn-benchmark`'s network-path
layer (packet loss / RTT / jitter, run with `--target-host` on the real
client-side path) is the way to check; a low-loss path gets little to no
benefit from this change.

**Fix shipped:** `deploy/lib/perf-tuning.sh` verifies BBR is actually
usable before enabling it — `perf_kernel_supports_bbr` checks
`/proc/sys/net/ipv4/tcp_available_congestion_control` and, if BBR isn't
already listed, attempts `modprobe tcp_bbr` (BBR is a loadable module on
several supported distro kernels, notably stock Ubuntu/Debian — a kernel
that supports it can still be missing it from the "available" list
purely because nothing has loaded the module yet) and re-checks. Only
if BBR is confirmed available does it set
`net.ipv4.tcp_congestion_control = bbr`. The paired qdisc
(`net.core.default_qdisc`) is chosen via `perf_qdisc_available`, which
checks `fq` then `fq_codel` availability WITHOUT mutating any live
interface's qdisc (an earlier version of this check briefly attached a
test qdisc to loopback to probe availability — replaced with a
non-mutating check via `lsmod`/`modules.builtin`/`modprobe --dry-run`).
If neither qdisc can be verified usable, BBR is still set but
`default_qdisc` is left at the distro default rather than guessing.
**Never forced on a kernel that doesn't support it.**

After applying, the effective congestion controller is read back via
`sysctl -n net.ipv4.tcp_congestion_control` — the log line
"`TCP bbr congestion control enabled and confirmed active`" is only ever
printed when that readback genuinely equals `bbr`, never merely because
this script wrote that line to a file.

**Downside:** BBR can be less fair to other TCP flows sharing a
bottleneck link in some topologies — a known, debated tradeoff in the
congestion-control literature. Given this host's role (a VPN egress, not
a general-purpose multi-tenant router), judged acceptable.

**Rollback (immediate, no reboot):**
```
sudo deploy/lib/perf-tuning.sh rollback
```

### G3. Kernel tuning rollback was documented but not actually reversible — P0, FIXED

**VERIFIED CONFIGURATION/CODE GAP (found in review of this same PR):**
the original version of this pass documented rollback as "delete
`/etc/sysctl.d/99-vpn1-dataplane.conf` and run `sysctl --system`." That
is NOT sufficient for an immediate runtime revert: `sysctl --system`
only applies values some `/etc/sysctl.d` file explicitly lists — a
parameter no remaining file mentions is left at whatever its CURRENT
live value already is; it does not fall back to a kernel-compiled-in
default by omission. Deleting vpn1's drop-in alone would leave the live
kernel still running vpn1's 16 MiB buffer ceiling (and BBR, if it was
enabled) indefinitely, until a reboot — and possibly not even then, if
something else's sysctl.d file happens to also set these.

**Fix shipped:** `deploy/lib/perf-tuning.sh`'s `perf_capture_baseline`
records this host's PRE-vpn1 values for `rmem_max`/`wmem_max`/
`tcp_congestion_control`/`default_qdisc` to
`/var/lib/vpn1/perf-tuning-baseline.env` on the very first apply on a
given host — exactly once, never overwritten by a later run (idempotent
across every subsequent install.sh/update.sh run; verified by
`deploy/lib/tests/test-perf-tuning.sh`). `perf_tuning_rollback` writes
an explicit rollback drop-in (`/etc/sysctl.d/99-vpn1-dataplane-rollback.conf`)
containing those captured values and applies it immediately — a real,
verified-effective revert, not a hope that omission works. It then reads
back each value via `sysctl -n` and reports exactly which ones did and
did not actually restore, the same "verify, don't assume" discipline as
G1/G2's apply path. Runnable directly:
```
sudo deploy/lib/perf-tuning.sh rollback
```
**Known limitation, documented rather than hidden:** if a host already
ran an OLDER version of this script (before baseline capture existed)
before upgrading to this one, the "baseline" captured on this host's
first run under the new code is whatever the live values already were
at that point — which may already include vpn1's own prior tuning, not
this host's true original distro defaults. `perf_capture_baseline`
detects this exact situation (vpn1's drop-in already exists but no
baseline file does) and prints an explicit warning saying so, rather
than silently mis-recording. This is a real, inherent limit of any
"capture on first run" scheme applied retroactively — not something a
different implementation could avoid without a pre-existing historical
record this project has never kept.

### G4. Hysteria2 had no bandwidth hint / Brutal congestion-control option — P1, FIXED (opt-in, default unchanged)

**VERIFIED CONFIGURATION/CODE GAP:** `crates/compat-config/src/server.rs`'s
`render_singbox_server_config` never set `up_mbps`, `down_mbps`, or
`ignore_client_bandwidth` on the Hysteria2 inbound before this pass.
Without those fields, sing-box's Hysteria2 implementation defaults to
its adaptive BBR-based congestion control.

**VERIFIED UPSTREAM RECOMMENDATION:** sing-box's Hysteria2 docs describe
Brutal (fixed-rate mode via `up_mbps`/`down_mbps` +
`ignore_client_bandwidth: true`) as the recommended setting **"for
servers whose admin already knows the real bandwidth."** The same docs
warn that a value higher than the network can actually sustain "will
backfire, causing network congestion and unstable connections" — a
guessed value is not a safe default, which is exactly why this ships
opt-in rather than defaulted-on with a guessed number.

**Fix shipped:** `Hysteria2ServerParams::{up_mbps,down_mbps}` (both
`Option<u32>`, both-or-neither enforced by `DeploymentConfig::validate`),
rendered into the Hysteria2 inbound only when both are set, alongside
`ignore_client_bandwidth: true`. **Left unset by default.** Validated
against the REAL pinned sing-box binary, not just this crate's own unit
tests: `crates/compat-config/tests/hysteria2_interop.rs`'s
`hysteria2_brutal_bandwidth_config_passes_real_sing_box_check` renders a
server config with `up_mbps`/`down_mbps` set and runs the actual `sing-box
check` against it — this is a different, stronger claim than "the JSON
this crate produces looks like what the docs describe": it proves the
exact pinned sing-box version (1.13.18, see the version-pin section
below) actually accepts the config as valid.

**Whether Brutal mode would help THIS VPS is unmeasured and cannot be
known without a real bandwidth measurement** — this is why it is opt-in,
requiring the operator to run `vpn-benchmark` and supply a *measured*
sustained-throughput number, not a guess or the provider's advertised
(often burst, not sustained) rate.

**Rollback:** remove `up_mbps`/`down_mbps` from `[hysteria2]` in
`deployment.toml`, run `vpn-admin render-config`.

### G5. No `Nice=` scheduling hint on the sing-box systemd unit — P1, FIXED

**VERIFIED CONFIGURATION/CODE GAP:** `deploy/almalinux/systemd/sing-box.service`
set `LimitNOFILE=65535` and extensive sandboxing directives, but no
`Nice=`/`CPUSchedulingPolicy=`.

**VERIFIED UPSTREAM RECOMMENDATION:** the Hysteria2 performance guide
advises raising process priority moderately under contention, explicitly
cautioning against jumping to real-time scheduling and to test
incrementally.

**Fix shipped:** `Nice=-5` — a modest bump, not
`CPUSchedulingPolicy=fifo`/`rr`. Matters only under real CPU contention;
negligible on an idle host. **Whether this host actually experiences
that contention is unmeasured** — `vpn doctor --performance`'s load
average and %steal readings are the way to check.

**Rollback:** delete the `Nice=-5` line from
`deploy/almalinux/systemd/sing-box.service`, then
`systemctl daemon-reload && systemctl restart sing-box` — or, on a host
that went through `update.sh`, simply re-run `update.sh` against a
checkout with that line reverted (see "Update-path parity," G7 below,
for why this now actually reaches an existing installation).

### G6. Subscription defaulted to VLESS+REALITY, not a throughput-based race — VERIFIED as deliberate; addressed as an opt-in profile, default unchanged

**VERIFIED CONFIGURATION/CODE GAP — but a deliberate one, not an
oversight:** `crates/compat-config/src/render.rs`'s
`render_singbox_client_subscription` builds a manual `selector` outbound
defaulting to the first VLESS+REALITY endpoint, with `route.final`
pointing at that selector, not at the `urltest` (`auto`) group. The
function's own doc comment and dedicated tests
(`selector_default_is_reality_and_lists_hysteria2_and_auto`,
`route_final_points_at_manual_selector_not_urltest`) document this as a
specific decision from a prior "Telegram-reliability pass" (see
`docs/TELEGRAM_RESILIENCE_PLAN.md`): `urltest`'s
`https://www.gstatic.com/generate_204` probe only proves generic HTTPS
reachability, says nothing about sustained throughput or behavior under
active DPI, and Hysteria2/QUIC is more exposed to UDP blocking/
throttling than REALITY's TCP/443 disguise.

**Does this explain the reported slowness?** Unknown, and only partially
even in principle: if Hysteria2 is in fact faster for this user right
now, they are on REALITY by default and would need to switch manually —
that much is a verified fact about current behavior. Whether that is
actually true for this user's network is a `MEASURED PRODUCTION
BOTTLENECK`-tier question this repository cannot answer.

Unilaterally flipping the default to Hysteria2, or to a plain `urltest`
race, was explicitly out of scope and would not have been justified
even if it were in scope: `crates/network-state`/`crates/failure-classifier`
currently record only boolean success/failure per transport (confirmed
by direct inspection of `Observation`/`Outcome`), not latency or
throughput — there is no data source in this codebase that could drive a
genuinely throughput-aware automatic selector today. See "Future work"
below.

**Fix shipped:** `SelectionProfile` (`reliability` / `performance` /
`auto`) exposed via `?profile=` on the subscription URL. `reliability`
(REALITY default) is unchanged and remains the default when `profile` is
omitted. `performance` sets the selector's default to Hysteria2.  `auto`
sets the selector's default to sing-box's own `auto` (urltest) group.
Every profile still lists every transport in the selector, so a user can
always override by hand.

**Rollback:** none needed — omit `?profile=` (or pass
`?profile=reliability`) for the original, unchanged behavior.

### G7. `vpn-benchmark`'s tunnel-outbound selection used hardcoded tag strings that never matched real deployments — P0, FIXED

**VERIFIED CODE BUG (found in review of this same PR, before merge):**
the first version of `deploy/lib/vpn-benchmark.sh` in this PR called
`tunnel_benchmark` with the literal outbound tags `"vless-reality-out"`
and `"hysteria2-out"`. The actual subscription renderer
(`crates/compat-config/src/render.rs`'s `standard_endpoints`) uses the
outbound tags `"Reality"` and `"Hysteria2"` — and `CompatEndpoint::label`
is operator-configurable free text, so even those aren't guaranteed
across every deployment. The hardcoded tags would never have matched any
real subscription's outbounds, meaning the tunnel-throughput layer of
this benchmark would have failed (or, worse, matched nothing and
silently produced no measurement) on every real installation.

**Fix shipped:** `deploy/lib/vpn-benchmark-lib.sh`'s
`vpn_benchmark_discover_outbound_tag` discovers the correct tag
dynamically from the rendered subscription JSON by matching on `type`
(`"vless"` with `.tls.reality.enabled == true`, or `"hysteria2"`) —
properties the renderer actually guarantees, never on tag/label text.
Zero matches is a clean `SKIP` (this deployment doesn't offer that
transport); more than one match is a hard failure (`AMBIGUOUS`), never a
silent guess; a match on a reserved `select`/`auto`/`direct` tag is
rejected as defense in depth. `sing-box check` now runs against the
generated client config before it is ever started, so a malformed
config fails loudly with the validator's own error message instead of
however sing-box's `run` happens to fail. Covered by
`deploy/lib/tests/test-vpn-benchmark-lib.sh` (15 assertions, including
an operator-renamed-labels case, an ambiguous-match case, and a
reserved-tag defense-in-depth case) — CI-safe, no sing-box binary or
network access required.

### G8. `update.sh` did not deploy several assets `install.sh` installs — P0, FIXED

**VERIFIED CODE BUG (found in review of this same PR, before merge):**
`install.sh` installs `vpn-benchmark` (plus its `vpn-benchmark-lib.sh`
sidecar) and the updated `sing-box.service` (with `Nice=-5`), but
`update.sh` — the script an EXISTING production installation actually
runs to pick up changes — never touched any of them. An installation
upgraded through `update.sh` would silently keep running the OLD
`sing-box.service` (no `Nice=-5`) indefinitely, and would never gain
`vpn-benchmark` at all. Separately, `install.sh` itself had a real bug:
it installed `vpn-benchmark.sh` to `$BIN_DIR/vpn-benchmark` without also
installing `vpn-benchmark-lib.sh` alongside it, so a freshly installed
`vpn-benchmark` would fail immediately on its first `source` — that bug
existed in the version of this PR before this review too.

**Fix shipped:** `update.sh` now stages, backs up, and installs all
systemd units `install.sh` installs (not just the ones this PR touched —
the same mechanism generalizes to any future unit change), runs
`systemctl daemon-reload` (required for a unit-file-only change like
`Nice=` to take effect — `reload-or-restart` alone does nothing if
systemd hasn't re-read the file), and syncs `vpn-health-check`/
`vpn-benchmark`/`vpn-benchmark-lib.sh` the same way. Rollback (on any
failure after the mutation phase begins) restores the previous version
of every one of these, exactly like it always did for the three core
binaries — including deleting a helper script that didn't exist before
this update introduced it, so a failed update leaves the host exactly as
it was, not half-upgraded. `install.sh` now installs
`vpn-benchmark-lib.sh` alongside `vpn-benchmark`.
`deploy/lib/tests/test-install-update-parity.sh` statically asserts
`install.sh`'s and `update.sh`'s asset lists match, and fails CI the
moment a future asset is added to one but not the other — this is a
regression class, not a one-off bug, so the test targets the class.

---

## Hypotheses — needs production measurement

None of the following can be confirmed or refuted from this repository —
no `MEASURED PRODUCTION BOTTLENECK` claim exists anywhere in this
document. They require running the shipped diagnostics
(`vpn doctor --performance`, `vpn-benchmark`) **on the actual production
VPS**, ideally with `--target-host` on the actual client-side (Russian
ISP) network path — not this repository's default target, which only
characterizes the VPS's own uplink.

| # | Hypothesis | How to check | What would confirm it |
|---|---|---|---|
| H1 | CPU steal is significant (noisy-neighbor host) | `vpn doctor --performance` (steal %) | Steal consistently > ~5-10% during load |
| H2 | 1 vCPU is saturated by Hysteria2/QUIC userspace crypto under real load | `vpn-benchmark`'s "sing-box client CPU ticks" (server-side protocol-overhead layer — see the methodology note below), or `top -H -p $(pgrep sing-box)` during a real transfer | sing-box pinned near 100% of one core while throughput plateaus |
| H3 | Packet loss / high RTT / jitter on the Russia→VPS path specifically | `vpn-benchmark --target-host <a host on that path>` (this IS a real network-path measurement — see methodology note), or `mtr <target>` | Loss consistently > ~1-2%, or RTT/jitter far above geographic expectation |
| H4 | The VPS provider's own uplink is bandwidth-capped or oversubscribed | `vpn-benchmark`'s raw-VPS-throughput layer, vs. the provider's advertised rate, at different times of day | Raw (non-tunneled) download throughput consistently well below advertised |
| H5 | MTU/PMTU issues on the path | `vpn-benchmark`'s MTU/PMTU probe | Effective path MTU well below 1500 |
| H6 | UDP socket buffer ceiling (G1) was actually being hit before this fix | `Udp: RcvbufErrors` in `/proc/net/snmp` (surfaced by `vpn doctor --performance`), before vs. after this pass | Nonzero, growing count before; zero/flat after |
| H7 | DNS resolution latency inside the tunnel | not currently instrumented | would need a dedicated DNS-timing probe — not built this pass |

**None of these should be "fixed" by guessing.** If H1/H2 come back
positive, the correct action is a VPS resize (see below), not more
kernel tuning. If H3/H4/H5 come back positive, the bottleneck is the
network path or the provider, and **no server-side software change in
this repository can fix that.**

### On "1 vCPU → 2 vCPU"

Strictly conditional, not implemented or assumed: **if and only if**
production measurement confirms H1/H2 (CPU-bound sing-box, and/or high
steal, during real load), moving to 2 modern vCPUs is the concrete next
step — Hysteria2/QUIC's userspace crypto/congestion-control processing
is CPU-bound work that benefits directly from more cores, and a 1-vCPU
host has zero scheduler headroom when another process needs the CPU at
the same moment. **RAM is not recommended to be increased** — no
evidence of memory pressure exists in this investigation.

### Future work not implemented this pass (and why)

- **Throughput/latency-aware automatic transport selection.** Needs new
  data collection — `crates/network-state`'s `Observation` type has no
  latency/throughput field today, only `Outcome::{Success,
  Failure(category)}`. Real instrumentation work (new probe logic, new
  fields, new scoring in `crates/policy`), not a config change; doing it
  hastily risks a worse regression than the conservative default.
  `SelectionProfile` gives a manual lever today without pretending to
  have built the data-driven version.
- **DNS-latency-inside-tunnel measurement (H7).** Not built.
- **Firewall conntrack/rate-limit/MTU rules.** No evidence (code or
  upstream) that `deploy/almalinux/firewall.sh`/`firewall-ufw.sh` are a
  bottleneck — they only open ports. Speculative tuning without evidence
  would violate the explicit "no unjustified tweaks" constraint on this
  work.

---

## Hysteria2 QUIC tuning investigated and NOT changed (and why)

The original task explicitly asked about QUIC receive-window
configuration, MTU/path-MTU behavior, GSO/GRO, and CPU requirements. MTU
is covered by `vpn-benchmark`'s MTU/PMTU probe (H5) and CPU by H1/H2
above. The remaining two:

### QUIC receive-window configuration — investigated, NOT changed

**VERIFIED UPSTREAM (sing-box source/docs, pinned v1.13.18):** sing-box's
QUIC-based protocols (Hysteria, Hysteria2, TUIC) share a common set of
tunable parameters — `stream_receive_window`, `connection_receive_window`
(plus `idle_timeout`, `keep_alive_period`, `max_concurrent_streams`,
`initial_packet_size`, `disable_path_mtu_discovery`) — with documented
**default stream/connection receive windows of 8 MiB / 20 MiB**, and
built-in **auto-tuning that increases the window as needed up to the
configured maximum**. Hysteria's own v1 tuning fields
(`recv_window_conn`/`recv_window`/`recv_window_client`/`max_conn_client`/
`disable_mtu_discovery`) are deprecated upstream and scheduled for
removal in sing-box 1.16.0 — not applicable to the Hysteria2 config this
project generates in the first place.

**Decision: leave at upstream defaults, do not configure.** Three
independent reasons, not one:
1. The window is auto-tuning, not a fixed ceiling like `rmem_max`/
   `wmem_max` (G1) — the class of problem G1 fixes (a hard ceiling too
   low for real traffic) does not apply here the same way.
2. Upstream's own documentation for the receive-window settings warns
   they "should not be changed unless you fully understand what you are
   doing" — the opposite framing from the UDP-buffer recommendation G1
   is based on, which is stated as a positive recommendation for this
   exact workload.
3. No production measurement exists showing the 8 MiB/20 MiB default is
   actually being hit as a ceiling (unlike G1, where H6 at least
   identifies a concrete counter — `RcvbufErrors` — that could show
   evidence either way; no equivalent stream/connection-window
   exhaustion signal is currently surfaced by this project's tooling).

Setting a custom value here would be exactly the kind of "tuning added
merely because a knob exists" the task explicitly said not to do. If a
future production measurement identifies QUIC flow-control stalls
specifically (not just raw throughput being low), revisit this section
first — a knob to try already exists (`stream_receive_window`/
`connection_receive_window` on the Hysteria2 inbound), it is simply not
enabled without that evidence.

### GSO/GRO (Generic Segmentation/Receive Offload) — investigated, NOT changed, no action possible at the sing-box config layer

**VERIFIED UPSTREAM (quic-go, the QUIC library sing-box's Hysteria2/TUIC
implementation is built on):** UDP GSO support landed in quic-go v0.36.0
(send-path batching, kernel ≥4.18, Linux only) and is used
**automatically when the running kernel supports it** — there is no
sing-box-level configuration field that enables or disables it; it is
selected transparently based on kernel capability at the socket-option
level. UDP GRO (the receive-side complement) is the same: a kernel
capability quic-go/the Go runtime detects and uses automatically, not a
sing-box config knob.

**Decision: no code change — this is a kernel-version property, not a
configuration gap.** Every OS this project supports (AlmaLinux 9, Rocky
9, RHEL 9, Ubuntu 22.04+, Debian 12+ — see `deploy/lib/os.sh`) ships a
kernel well above 4.18, so GSO/GRO are already available and already
used automatically on every supported deployment target. There is
nothing for `deploy/lib/perf-tuning.sh` or the sing-box config generator
to set — adding a "GSO/GRO tuning" section to either would be
configuring something that isn't actually configurable at this layer,
which is precisely the "speculative" category the task said to avoid.
If a future, unusual deployment target ships a pre-4.18 kernel, that
host simply doesn't get GSO/GRO — sing-box/quic-go fall back to
unbatched syscalls automatically; there is no failure mode to guard
against, only a (kernel-version-dependent, not vpn1-dependent)
throughput ceiling.

---

## sing-box version pin: 1.13.14 → 1.13.18

**VERIFIED UPSTREAM (SagerNet/sing-box releases + full commit-range
audit, checked 2026-08-12):** v1.13.18 is the current stable release
(released 2026-08-09; `v1.14.0-beta.*` tags are pre-release and
correctly not adopted, per the explicit instruction not to move to a
1.14 prerelease). `v1.13.17` does not exist as a stable release —
SagerNet went `1.13.16 → 1.13.18` directly.

Full commit-range audit (`v1.13.14..v1.13.18`) found:
- **No REALITY-related commits** anywhere in the range — no
  `protocol/vless` REALITY-handshake code, no `common/tls` REALITY files
  touched functionally.
- **No Hysteria2/vless/reality config-schema changes** affecting this
  project's generator fields (`private_key`/`short_id`/`handshake.*`,
  `users`/`password`/`masquerade`/`obfs`/`up_mbps`/`down_mbps`/
  `ignore_client_bandwidth`) — confirmed both by the commit audit and
  directly, by running the real 1.13.18 binary's `sing-box check` against
  every config shape this project generates (see the interop test suite,
  including the new Brutal-bandwidth case from G4).
- Two QUIC-adjacent stability fixes: a `quic-go` write-leak fix
  (v1.13.15) and a `sing-quic` fix for "UDP sessions not closed on
  connection close" (v1.13.16) — net-positive for Hysteria2 reliability,
  not a regression risk.
- One unrelated privacy fix (AnyTLS client-metadata removal, v1.13.16) —
  AnyTLS is not used by this deployment.
- No regressions found reported against any version in this range.

**Decision: bump to 1.13.18.** `SINGBOX_VERSION` in
`deploy/almalinux/install.sh` and the CI `singbox-validate` job's pinned
version/checksum were updated together (same commit, per this file's own
"bumping the version must update the SHA256 pins in the same commit"
discipline); the SHA256 checksums for both architectures were computed
from the real release assets, verified with a second independent
download before pinning (SagerNet does not publish a detached
`checksums.txt` for this release, same as was already true for
`1.13.14`). All real interop tests (`reality_interop`,
`reality_decoy_budget`, `hysteria2_interop` — including the new Brutal
case) were run against the real 1.13.18 binary and pass. See
`docs/COMPATIBILITY_VERSIONS.md` for the version table.

---

## Priority summary

| Priority | Item | Status |
|---|---|---|
| P0 | G1: UDP socket buffer sysctls (rmem_max/wmem_max) | Shipped |
| P0 | G2: BBR + fq/fq_codel, gated on verified kernel support | Shipped |
| P0 | G3: genuine no-reboot rollback (baseline capture + verified restore) | Shipped |
| P0 | G7: `vpn-benchmark` outbound discovery fixed (was broken on every real deployment) | Shipped |
| P0 | G8: `update.sh` asset parity with `install.sh` | Shipped |
| P0 | Measurement tooling: `vpn doctor --performance`, `vpn-benchmark` | Shipped |
| P0/P1 | sing-box 1.13.14 → 1.13.18 | Shipped |
| P1 | G4: Hysteria2 Brutal bandwidth, opt-in, validated against real binary | Shipped (off by default) |
| P1 | G5: `Nice=-5` on sing-box.service | Shipped |
| P1 | G6: `SelectionProfile` (reliability/performance/auto) | Shipped (default unchanged) |
| P2 | H1-H7: production-only measurements | Not actionable without VPS access — run the tooling above |
| P2 | VPS resize (1→2 vCPU) | Conditional on H1/H2 — do not do preemptively |
| P2 | QUIC receive-window tuning | Investigated — leave at upstream auto-tuning default, no evidence to justify a fixed value |
| P2 | GSO/GRO | Investigated — kernel-automatic, no sing-box-level knob exists, no action possible |
| P2 | Throughput-aware auto-selection | Future work — needs new instrumentation |

---

## Measurement tooling shipped this pass

### `vpn doctor --performance`

Read-only host/kernel/network **measurements** (never a recommendation,
never pass/fail): CPU model, vCPU count, load average, instantaneous CPU
utilization and %steal, RAM/swap, primary interface + MTU + qdisc,
current and available TCP congestion control, `net.core.rmem_max`/
`wmem_max`, cumulative TCP retransmit / UDP error counters from
`/proc/net/snmp` (including `RcvbufErrors`, the H6 signal above), and
sing-box's own PID, nice value, open-file-descriptor limit, and
CPU-ticks-consumed. Every metric this process cannot read prints
`unavailable`, never a guess. `apps/admin/src/main.rs`
(`cmd_doctor_performance`), pure `/proc`/`/sys` reads plus `ip`/`tc`/`ps`.

### `vpn-benchmark` (`deploy/lib/vpn-benchmark.sh`)

A repeatable, multi-sample (`--runs`, default 3; min/median/max, never a
single number) benchmark across four **distinctly labeled** layers —
this labeling is deliberate and load-bearing, not cosmetic (see the
methodology note immediately below):

1. **Host** — CPU/RAM/steal/load (bash-only).
2. **Network path** (`--target-host`) — packet loss, RTT/jitter (`ping`),
   hop-by-hop loss (`mtr`, if installed), MTU/PMTU via a binary-search
   `ping -M do` probe. **This IS a real client-side network-path
   measurement** when `--target-host` points at (or the whole script
   runs from) an actual vantage point on that path.
3. **Raw VPS throughput** — a plain HTTPS download with no tunnel,
   isolating "this VPS's own uplink" from "the tunnel software."
4. **VLESS+REALITY / Hysteria2 SERVER-SIDE PROTOCOL OVERHEAD** — a REAL
   sing-box client, running on THIS SAME VPS, dials THIS SAME VPS's own
   public listener through a throwaway benchmark user (created and
   deleted by the script), with its outbound discovered dynamically from
   the live subscription JSON (G7) and validated with `sing-box check`
   before it's ever started, while sampling sing-box's own CPU ticks
   during the transfer.

**Methodology note, corrected in this review (item 9): layer 4 is NOT a
measurement of a real remote client's network path.** A sing-box client
running on the VPS and dialing that same VPS's own public IP is a
genuinely real handshake through the real protocol/crypto/QUIC stack —
useful for isolating protocol/CPU overhead (compare against layer 3's
raw number, at matched RTT ≈ 0) — but the traffic never leaves this
host's own uplink/routing. Path-specific loss, jitter, censorship
middleboxes, or peering problems on a real user's route (e.g. Russia →
this VPS) are invisible to layer 4 by construction. A prior version of
this benchmark's own output described layer 4 as measuring "over the
real network," which is what a reader would reasonably take to mean the
client's real path — that phrasing has been corrected in the script
itself (see its file-header comment and per-section labels) and is
called out explicitly here so this document doesn't repeat the same
overstatement. For an actual remote-path measurement, use layer 2 from a
real vantage point, or run a sing-box client on a real remote host on
that path against this VPS — this script cannot fake that from the
server side alone, and does not claim to.

Every step needing a tool or live component this host doesn't have
prints `SKIPPED: <reason>` and continues. The final "Assessment" section
is a decision *guide* that repeats the layer-4 caveat, not a computed
verdict.

---

## What to run on the actual VPS

```
vpn doctor --performance
vpn-benchmark --runs 5 --target-host <a host on your users' real ISP path>
```

Then work through the hypothesis table above. In particular:

- If raw VPS throughput (layer 3) is already far below the provider's
  advertised rate, with high CPU steal → **provider problem**; no sysctl
  or sing-box change here can fix it.
- If raw throughput is fine but the layer-4 (server-side, hairpin)
  throughput is much lower with sing-box CPU low during the transfer →
  likely protocol/congestion-control overhead intrinsic to the tunnel at
  this RTT — NOT something layer 4 can attribute to the real network
  path, which it cannot see.
- If layer-4 throughput is much lower AND sing-box is pinned near 100%
  of one core → **CPU-bound**; this is the case where a 2-vCPU resize is
  justified (see "1 vCPU → 2 vCPU" above).
- High packet loss or RTT/jitter in **layer 2**, run against a real
  vantage point on the users' ISP path → that IS a real network-path
  measurement (unlike layer 4) → evidence of a peering/routing problem no
  server-side tuning here can fix.
- Compare `Udp: RcvbufErrors` (via `vpn doctor --performance`) before and
  after this pass, under real load, for the closest thing this project
  has to direct evidence on H6/G1.

---

## 2026-08-12 addendum: root-cause audit against PR #16, and what changed

This session's task was to find the *actual* bottleneck rather than add
more tuning, starting from the assumption that PR #16 (the pass
documented above) might already be sufficient, insufficient, or partly
unwired. **This session had no SSH access to any production VPS and no
Russia-side vantage point** — confirmed at the start (no credentials, no
inventory file, no VPN config present in this environment) — so
everything below is either a code/upstream-documentation fact or an
explicit "cannot be measured here."

### Root-cause matrix

**CONFIRMED FROM CODE** (re-verified against HEAD, not assumed from the
PR #16 description):
- `deploy/lib/perf-tuning.sh` sets exactly 4 sysctls (rmem/wmem 16MiB
  ceilings, conditionally-gated BBR + fq/fq_codel), nothing else — no
  generic tuning cruft. Idempotent, capability-gated (never forces BBR on
  a kernel that doesn't support it), has a real rollback path, and is
  wired into **both** `install.sh` and `update.sh` with no drift between
  them.
- `Nice=-5` on `sing-box.service` is real and is the only CPU-scheduling
  directive present (no `CPUQuota`/`CPUWeight`).
- Hysteria2 Brutal (`up_mbps`/`down_mbps`) is `Option<u32>`, defaults to
  `None`, validated together-or-neither, and is never populated with a
  guessed value anywhere in the renderer.
- The default subscription profile is `Reliability` (VLESS+REALITY), and
  the code says why in-line: "the only profile safe to run as a
  fleet-wide default under active DPI" — a deliberate anti-censorship
  tradeoff, not a throughput claim. This is unchanged and was judged
  correct, not a bug.
- The client subscription's routing is `route.final -> select` only —
  no `route.rules`, no GeoIP/domestic-bypass logic anywhere in
  `crates/compat-config` or `services/subscription`. Confirmed
  full-tunnel by omission, not by an explicit documented design choice.
- Server/outbound selection (`auto` / `urltest`) is a plain HTTPS
  latency/success race — the code's own comments already say this is not
  throughput- or loss-aware, and `crates/network-state`'s `Observation`
  type has no latency/throughput field to build one from without new
  instrumentation work.
- The previously-reverted multi-node scaffolding (commits `50838b7` →
  `9c674fd`) was reverted because it was **unwired dead code** (nothing
  in `apps/admin` or `services/subscription` ever constructed a
  `NodeSpec`) and because credential-bearing state was judged to need
  its own dedicated security review — not because multi-node itself was
  rejected as an idea. `docs/TELEGRAM_RESILIENCE_PLAN.md` §K already
  contains a considered design (independent per-node deployments + a
  thin merge layer, explicitly rejecting shared/replicated identity as
  riskier) and a zero-code interim mitigation (two independent
  deployments, two subscription URLs, manually switched). Its one real
  gap — no rollback story — is fixed in this pass (see below).
- `nf_conntrack_max`/`nf_conntrack_buckets` are untouched anywhere in the
  repo (neither `perf-tuning.sh` nor the firewall scripts); this was
  previously a deliberate, documented "no evidence" omission (see
  "Future work not implemented this pass" above), which this session's
  independent review agreed is architecturally plausible but still
  unmeasured — see below for what was and wasn't done about it.

**CONFIRMED FROM UPSTREAM DOCUMENTATION** (current sing-box/Hysteria2/
Linux-networking primary sources, re-checked this session):
- Hysteria2 runs on quic-go (userspace QUIC); Hysteria2's own
  performance guide states a CPU-throttled/low-power VPS can become the
  bottleneck. No authoritative source gives a concrete Mbps-per-core
  number for this workload — the qualitative risk is confirmed, the
  specific threshold is not.
- Hysteria2's own docs explicitly warn against setting Brutal
  `up_mbps`/`down_mbps` higher than real capacity — doing so causes
  self-inflicted congestion/instability. This validates the existing
  "opt-in only, never a guessed value" code as correct, not overcautious.
- **Multiple major Russian ISPs (Yota, MTS, Megafon, Beeline) are
  documented (net4people/bbs #108, tracked since 2022, corroborated by a
  2026 FOCI paper) to block or silently drop QUIC Initial Packets on
  UDP/443 to foreign destinations.** This is the single most consequential
  new finding this session added: a Hysteria2 shortfall for Russian users
  can be ISP-side censorship of the QUIC transport itself, independent of
  — and potentially larger than — any server-side CPU question. This was
  not previously documented in this repository.
- Since June 2025, Russian ISPs have additionally throttled
  Cloudflare-fronted traffic (TCP and QUIC) to roughly 16KB/s; this
  repository's REALITY endpoints front through the VPS's own IP, not
  Cloudflare, so it is not directly implicated, but is worth knowing if a
  future change ever routes through Cloudflare IP space.
- AmneziaWG has near-parity real-world throughput with vanilla
  WireGuard, but **sing-box does not natively support it** (open feature
  requests SagerNet/sing-box#2276, #4045, unofficial forks only) and
  **Hiddify does not list it** among supported protocols. Adopting it
  would require either the official Amnezia client or a sing-box fork,
  breaking this project's stated Hiddify-compatibility goal without a
  clear compensating win over the QUIC-blocking finding above, which
  Hysteria2-over-TCP-disguised-REALITY already partially sidesteps by
  existing as a fallback.

**LIKELY BUT UNMEASURED:**
- Whether 1 vCPU actually saturates at real production Hysteria2
  throughput (qualitatively plausible per upstream docs; no number from
  this deployment).
- Whether VLESS+REALITY (TCP) suffers materially worse head-of-line
  blocking than Hysteria2 (QUIC) on the real Russia→VPS path specifically
  — this is a generic TCP-vs-QUIC property from general protocol
  literature, not a REALITY- or Hysteria2-project-published benchmark.
- Conntrack table exhaustion under real concurrent-client load (default
  bucket sizing on a 2GB host is plausibly low enough to matter under
  many-flow fan-out from browsing traffic; no load test exists to
  confirm or refute this in this repository).
- Whether `Nice=-5` produces any observable sshd/systemd latency under
  real contention (the mechanism is sound — CFS proportional weighting,
  not RT starvation — but this has not been load-tested).

**CANNOT BE MEASURED FROM THIS ENVIRONMENT:**
Everything requiring a live VPS or a Russia-side vantage point: actual
CPU/steal during a real transfer, whether `perf-tuning.sh` has actually
been *run* on the production host (repository state is not proof of
runtime state — this remains genuinely unverified), actual RU→VPS loss/
jitter/UDP treatment, ASN/peering quality, and real sustained bandwidth
figures needed to safely configure Brutal. This session had no SSH
access and no way to reach a Russian network vantage point; anyone with
that access should run `vpn doctor --performance`, `vpn-benchmark --runs
5`, and the new client-side script below, and compare against this
matrix.

**RULED OUT:**
- 2GB RAM as a bottleneck: `rmem_max`/`wmem_max` are ceilings, not
  per-flow multipliers, and Hysteria2/QUIC multiplexes clients over a
  small number of listening UDP sockets, not one kernel socket per
  client — worst case is tens of MB against 2GB total. Architecturally
  not a risk (live swap/pressure still unmeasured on the real host, but
  there is no plausible mechanism for this specific gap to cause it).
- Unjustified generic sysctl tuning: none exists in the repo; scope is
  and remains narrow by design.
- `perf-tuning.sh` being unwired in code: it is wired into both install
  and update paths with no parity gap. (Whether it has actually executed
  successfully on the live production box is a *different*, still-open
  question — see "cannot be measured" above.)

### What was changed this session, and why each change is justified

Given the complete absence of live measurement access, changes were
limited to things justifiable from code/documentation evidence alone —
diagnostic tooling and documentation gaps — not speculative tuning:

1. **`deploy/local/vpn-client-diag.py`** (new) — a stdlib-only Python 3
   script that runs on the user's actual Windows/macOS/Linux device to
   measure DNS latency, TCP connect latency, ICMP ping loss/RTT, a
   best-effort PMTU estimate, a baseline download-throughput sample, and
   public exit IP, tagged by run label (`baseline`/`reality`/
   `hysteria2`). This is the one piece of tooling explicitly missing:
   `vpn-benchmark.sh` measures only the VPS's own uplink and says so
   explicitly in its own comments (layer 4 is a same-host hairpin, not a
   real client path). Collects no secrets — never reads a subscription
   URL, token, or key. See `docs/clients/CLIENT_DIAGNOSTICS.md` for
   methodology.
2. **`vpn doctor --performance`: added a conntrack utilization section**
   (`apps/admin/src/main.rs`) — reads
   `net.netfilter.nf_conntrack_max`/`nf_conntrack_count` and warns above
   80% utilization. This is observability only; the sysctl itself was
   **deliberately not changed** (see below) — this closes the "cannot be
   measured" gap on conntrack without guessing a new ceiling value.
3. **`docs/TELEGRAM_RESILIENCE_PLAN.md` §K: added a rollback section**
   for the multi-node design. This was a real, previously-acknowledged
   gap (credential isolation, updates, and health-check limits were all
   discussed; rollback was not) found during this session's audit of why
   the multi-node scaffolding was reverted. Fixing a documented gap in an
   existing design doc is justified regardless of production access;
   writing new multi-node *code* is not (see below).

### What was deliberately NOT changed, and why

- **`nf_conntrack_max` was not raised.** The plausible-risk finding above
  is real, but this repository's own prior work already drew the correct
  line here ("no evidence... speculative tuning without evidence would
  violate the explicit 'no unjustified tweaks' constraint") and this
  session found no new evidence to cross that line — only a stronger
  articulation of the same unmeasured risk. Observability (item 2 above)
  was added instead so a future run with real access can decide from
  data, not a guess.
- **`Nice=-5` was not replaced with `CPUWeight=`.** A safer cgroup-native
  alternative exists in principle, but `Nice=-5` already has documented
  upstream rationale (Hysteria2 performance guide) and no measured
  evidence of sshd/systemd starvation exists to justify changing a
  working, already-conservative choice speculatively.
- **No multi-node code was written.** No measurement in this session (or
  available to it) shows CPU, not peering/ASN quality, is the actual
  ceiling — and §K's own zero-code interim mitigation (two independent
  deployments, two subscription URLs) already covers the "what if this
  VPS gets blocked" case without new credential-isolation code. Building
  the Option A merge layer speculatively, without first confirming via
  `docs/AWS_REACHABILITY_TEST.md`-style testing that peering is actually
  the limiting factor, would repeat the exact mistake the original
  revert was correcting.
- **No split-tunneling/domestic-bypass routing was added.** The
  subscription being full-tunnel is confirmed, and Russian ISPs blocking
  foreign QUIC is real evidence that *some* routing change could help —
  but this repository has no maintained GeoIP/GeoSite domestic rule set,
  and a naive `.ru`-direct rule was explicitly ruled out as unsafe by the
  task's own framing (many non-RU services use `.ru`; many RU services
  don't). Building this properly needs a maintained rule-set source and
  its own privacy-tradeoff review — out of scope to improvise this
  session without evidence of which specific domestic services are
  actually the ones users want faster.
- **No VPS resize, no AmneziaWG adoption, no protocol change.** None of
  these are supported by a measurement this session could take; see the
  closing summary below for the explicit unresolved status of each.

### Rollback instructions for this session's changes

- `deploy/local/vpn-client-diag.py`, `docs/clients/CLIENT_DIAGNOSTICS.md`:
  pure additions, delete the files to remove.
- `vpn doctor --performance` conntrack section: revert the diff in
  `apps/admin/src/main.rs`; no state is written, purely additive output.
- `docs/TELEGRAM_RESILIENCE_PLAN.md` §K rollback subsection: documentation
  only, revert the diff to remove.
None of these changes touch installed sysctls, systemd units, or
firewall state — there is nothing to roll back on a live host.

### Closing summary

- **Primary bottleneck**: unproven from this environment. The strongest
  evidence-backed candidate is **Russian ISP-side QUIC/UDP-443
  interference against Hysteria2** (documented against multiple major RU
  ISPs), not server CPU — but this repository has no live measurement to
  confirm it applies to this specific deployment's users.
- **Secondary bottleneck**: possible Hysteria2/quic-go CPU ceiling on 1
  vCPU at high throughput (qualitatively real per upstream docs, no
  measured threshold), and/or REALITY's TCP-based head-of-line blocking
  on a lossy path (generic protocol property, not measured here).
- **1 vCPU**: still unproven — no CPU/steal measurement exists during
  real load. Do not resize preemptively; run `vpn doctor --performance`
  during a real transfer first.
- **2 GB RAM**: sufficient — ruled out architecturally (ceilings, not
  per-flow multipliers); no plausible mechanism in this codebase for RAM
  to be the limit.
- **Protocol recommendation**: keep `Reliability` (VLESS+REALITY) as the
  default — this was already correct and is now confirmed intentional,
  not accidental. Offer Hysteria2 as the explicit fallback it already is,
  but do not assume it is "the fast one" for Russian users specifically
  given the QUIC-blocking evidence above.
- **VPS/network recommendation**: do not resize for CPU without a
  measurement. If/when real data shows peering or QUIC-blocking (not
  CPU) is the ceiling, a second independent node/provider is the more
  promising lever than more vCPUs — the design for that already exists
  in `docs/TELEGRAM_RESILIENCE_PLAN.md` §K and is not blocked on more
  code, only on evidence that it's needed.
- **Measured improvement**: none — no production measurement was
  possible in this session. What shipped is diagnostic capability
  (client-side script, conntrack observability) and two documentation
  fixes, not a performance change.
- **Remaining unverified items**: essentially everything requiring a
  real VPS or a Russia-side vantage point — actual CPU/steal under load,
  whether kernel tuning is actually active on the live host, real
  RU→VPS loss/jitter/UDP treatment, ASN/peering quality, and real
  sustained bandwidth for any future Brutal configuration. Run `vpn
  doctor --performance`, `vpn-benchmark --runs 5`, and
  `deploy/local/vpn-client-diag.py` (from an actual Russia-side device)
  to close these.

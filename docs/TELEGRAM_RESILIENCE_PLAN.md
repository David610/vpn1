# TELEGRAM_RESILIENCE_PLAN.md

Investigation and implementation plan for improving vpn1's reliability
against Telegram's reported unreliability under Russian censorship,
while YouTube and Instagram work well through the same VPN.

**Scope discipline, stated up front and enforced throughout this
document**: vpn1 serves roughly ten trusted family/friend users. It is
not a commercial VPN service. Every recommendation below is chosen for
reliability, diagnosability, and simplicity over scale, breadth of
protocol support, or novelty. Nothing here claims Telegram is "fixed"
under Russian censorship — there is no way to prove that from outside
Russia, and this document says so explicitly wherever it matters.

## 0. What this investigation could and could not do

This session has no access to a Russian residential or mobile network,
no real Hiddify Android/iOS device, and no real VPS. Every conclusion
below is either (a) a fact directly verified by reading and testing this
repository's actual source code, or (b) a technically-reasoned
hypothesis, explicitly labeled as such. Section 5 states this
limitation again, deliberately, because it is the single most important
thing to remember when reading everything else in this document.

## 1. Confirmed issues (directly demonstrated by repository inspection)

These were true of the repository before this pass, verified by reading
`crates/compat-config/src/render.rs`, `apps/admin/src/main.rs`, and
`crates/compat-config/src/deployment.rs`:

1. **BUG/RELIABILITY ISSUE** — Automatic transport selection
   (`render_singbox_client_subscription`) built only a `urltest` group
   (`tag: "auto"`) and set `route.final` to it directly. `urltest`
   measures a fast plain-HTTPS request to `https://www.gstatic.com/
   generate_204` — it proves nothing about Telegram, long-lived
   connections, media transfers, UDP reliability, PMTU, or DPI
   resistance on a censored network. A fresh subscription import had no
   deterministic default transport at all; it was whatever won that one
   Google-latency race at import time. **Fixed in this pass — see §A.**
2. **RELIABILITY/OPERABILITY ISSUE** — Hysteria2 Salamander obfuscation
   was already correctly optional-and-explicit (never silently enabled,
   never silently rotated — `apps/admin/src/main.rs`'s
   `hysteria-obfs-rotate` command, `standard_endpoints`'s
   `hysteria_obfs_password_file` doc comment), and `vpn-admin doctor`
   already reported its state as `[WARN]` when disabled. This is closer
   to "already correctly designed" than "broken" — see §D for what was
   still missing (Telegram-specific framing, not the mechanism itself).
3. **DOCUMENTATION GAP** — Two client guides
   (`docs/HIDDIFY_ANDROID.md`, `docs/clients/HIDDIFY_IOS.md`) described
   `urltest`/"automatic selection" as the only behavior, reinforcing the
   exact assumption §1 above shows is unsound for a censored network.
   **Fixed — see §A and the doc edits in that section.**
4. **OPERABILITY ISSUE** — No `vpn doctor` check resolved the deployment's
   own public hostname or reported its A/AAAA record shape. IPv6 policy
   was implicit: sing-box listeners bind `::` (dual-stack,
   `crates/compat-config/src/server.rs`) regardless of whether the
   public hostname has an AAAA record or whether the VPS's IPv6 egress
   actually works, and nothing surfaced a mismatch between "AAAA
   advertised" and "IPv6 actually usable." **Fixed — see §E.**
5. **OPERABILITY ISSUE** — No `vpn doctor` check detected multiple
   `sing-box` binaries on a host with differing versions (e.g.
   `/usr/local/bin/sing-box` vs `/usr/bin/sing-box`) — a documented
   real-world incident class (`docs/INCIDENT_2026-08-10_REALITY_
   HANDSHAKE_TIMEOUT.md` cites this exact drift pattern as a source of
   confusion during troubleshooting, though not confirmed as this
   incident's cause). **Fixed — see §I.**
6. **DOCUMENTATION GAP** — No document distinguished the ~9 distinct
   Telegram functions (startup, text, media download/upload, channels,
   notifications, voice/video calls) as separate pass/fail axes, no
   document covered Telegram's own internal proxy setting as an
   independent failure source, and no document covered Android's
   Always-on-VPN/Block-connections-without-VPN diagnostic mechanism.
   **Fixed — see §F, `docs/TELEGRAM_TROUBLESHOOTING.md`.**
7. **DOCUMENTATION GAP** — `docs/DEVICE_ACCEPTANCE_TESTS.md` had no
   Telegram-specific test matrix (transport x function), only a
   general connectivity matrix per platform/client. **Fixed — see §G.**
8. **OPERABILITY ISSUE** — No sanitized diagnostic bundle command
   existed; an operator asking for help had no safe way to share server
   state without manually redacting secrets by hand. **Fixed — see §H.**

## 2. Probable weaknesses (technically reasonable, not proven to cause the reported Telegram failures)

These are real properties of the system that *could* plausibly
contribute to Telegram-specific failures under Russian DPI, but nothing
in this repository or any available evidence proves they are the actual
cause of what was reported. Listed here so they are not silently
implemented as "the fix" without evidence:

- **MTU/PMTU mismatches**, especially for Hysteria2 (QUIC/UDP is more
  PMTU-sensitive than Reality's TCP). No global fix was applied — see
  §J below for why, and `docs/TELEGRAM_TROUBLESHOOTING.md` §7 for the
  controlled, revertible, client-side experiment procedure instead.
- **IPv6 leakage on the client device** (Telegram routing over the
  device's native IPv6 instead of the VPN tunnel) — plausible on a
  network where the client has real IPv6 and vpn1's AAAA/IPv6 story is
  incomplete. The server-side half of this is now diagnosable (§E); the
  client-side half is fundamentally outside vpn1's control and can only
  be documented (§F).
- **Hiddify TUN routing / per-app exclusion** on the client device — a
  Telegram-specific split-tunnel exclusion (accidental or vendor
  default) would produce exactly "YouTube/Instagram work, Telegram
  doesn't" without any server-side signal at all. Entirely outside
  vpn1's visibility; documented in §F.
- **Telegram's own internal proxy setting** — same shape of failure as
  above, entirely client-side, now explicitly documented (§F, and
  featured prominently as Step 1 of the troubleshooting flow because it
  is cheap to check and easy to overlook).
- **Datacenter/ASN-level filtering specific to Telegram's own peering**
  — Telegram is known to have been targeted more aggressively than
  generic HTTPS traffic in some jurisdictions historically; a single VPS
  on a single provider/ASN has no redundancy against this class of
  filtering regardless of which local transport is used. See §K
  (multi-node) for why this is architecturally the most promising
  unaddressed lever, and why it isn't implemented as code this session.

## 3. Not currently justified

Per the investigation's own scope constraints, none of the following
were added, and none should be added reactively just because Telegram
failed once without more specific evidence pointing at a protocol-level
cause a new transport would actually fix:

- XHTTP, TUIC, Trojan, WebSocket transport, a custom obfuscation
  protocol, custom cryptography — no evidence in this repository points
  at a protocol-level deficiency in Reality or Hysteria2 specifically;
  adding a third/fourth transport for ~10 users increases fingerprint
  surface, maintenance burden, and diagnostic complexity without a
  demonstrated need.
- MTProto proxy — this is a *client-side* Telegram feature (§F Step 1
  documents it), not something vpn1's server stack implements or should
  implement; running one would duplicate Telegram's own infrastructure
  for no benefit to VPN reliability.
- Global MSS clamping or a global MTU override — see §J. Both would
  apply the same unverified value to every user's every path,
  potentially degrading networks that had no problem, in exchange for
  possibly fixing one unconfirmed symptom on one user's one path.
- A bespoke transport-selection protocol beyond sing-box's own
  `selector`/`urltest` outbound types — sing-box already provides
  exactly the primitives needed (§A); building a custom equivalent would
  duplicate upstream-maintained code for no capability gain.

## 4. Implementation order

- **P0** (implemented this pass): §A deterministic transport default,
  §E IPv6 policy diagnostics, §I version-consistency diagnostics, the
  `urltest`-scope disclaimer now always printed by `vpn doctor`.
- **P1** (implemented this pass): §C `vpn doctor --telegram`, §H
  `vpn doctor --report`, §F `docs/TELEGRAM_TROUBLESHOOTING.md`, §G
  Telegram-specific acceptance matrix.
- **P2** (implemented this pass, lower urgency): documentation
  cross-linking, incident-doc acceptance-command update to match the new
  selector outbound.
- **P3** (documented, not implemented this pass — see §K): multi-node
  data-model/deployment design. Deliberately deferred: it is the
  highest-value remaining lever for censorship resilience specifically,
  and also the one most likely to introduce a real security or
  reliability regression (credential distribution across independent
  trust domains) if rushed. Building it carefully is worth more than
  building it fast for ten trusted users who are not waiting on a
  release deadline.

## 5. Remaining limitations (read this before believing anything above "fixed" the reported problem)

Nothing in this pass, or in this repository, can verify:

- Russian residential ISP DPI behavior
- Russian mobile-network (carrier-level) behavior
- Telegram's actual behavior on any specific Russian ISP, today
- Real Hiddify Android/iOS/MagicOS behavior, since no such device was
  available in this development environment
- Future censorship changes — DPI/blocking behavior is adversarial and
  changes over time; nothing here is a permanent guarantee

**Every "not yet tested" cell in `docs/DEVICE_ACCEPTANCE_TESTS.md`
stays exactly that — "not yet tested" — until a real person on a real
Russian network fills it in with a dated entry.** This document does not
change that status for a single cell.

---

## A. Deterministic primary transport

**Changed:** `crates/compat-config/src/render.rs`,
`render_singbox_client_subscription`.

Before: `outbounds` contained one endpoint per transport plus a
`urltest` group (`tag: "auto"`); `route.final` pointed directly at
`"auto"`.

After: the same `urltest` group is still built (nothing removed — "auto"
remains fully selectable), plus a new `selector` outbound (`tag:
"select"`) whose `outbounds` list is every endpoint tag plus `"auto"`,
and whose `default` is the first VLESS+REALITY endpoint's tag (falling
back to the first endpoint of any kind if a reduced/experimental
endpoint set somehow has no REALITY endpoint, so the renderer never
panics). `route.final` now points at `"select"`, not `"auto"`.

Effect: a freshly imported Hiddify/sing-box profile starts on REALITY,
deterministically, every time — not on whatever `urltest`'s one-shot
Google-latency race happened to prefer at import time. Users can still
tap into Hysteria2 or Auto manually from the same server list Hiddify
already renders for a `selector` outbound (this is exactly the
tappable-list UI Hiddify/NekoBox-style clients already render for
`selector`-type outbounds — no new client behavior required, this is
standard, current sing-box functionality, not a custom protocol).

**Tests:** 3 new unit tests in `crates/compat-config/src/render.rs`
(`route_final_points_at_manual_selector_not_urltest`,
`selector_default_is_reality_and_lists_hysteria2_and_auto`,
`selector_default_falls_back_to_first_endpoint_when_no_reality_endpoint_present`),
plus the existing `singbox_subscription_has_both_outbounds_and_urltest_selector`
updated to also assert the `selector` outbound is present. All pass.

**Docs updated:** `docs/CLIENT_COMPATIBILITY.md`,
`docs/HIDDIFY_ANDROID.md`, `docs/clients/HIDDIFY_IOS.md`,
`docs/INCIDENT_2026-08-10_REALITY_HANDSHAKE_TIMEOUT.md` §11a step 8
(outbound count and the new selector-default assertion).

## B / C. `vpn doctor` improvements and `vpn doctor --telegram`

**Changed:** `apps/admin/src/main.rs`.

New always-on checks added to `cmd_doctor`:

- `check_public_hostname_and_ipv6_policy`: resolves `public_host`,
  reports A/AAAA counts, and — only if an AAAA record exists — probes
  this VPS's own IPv6 UDP egress (reusing the existing resolver-probe
  infrastructure) to distinguish "AAAA exists and IPv6 actually works"
  (`[OK]`) from "AAAA exists but IPv6 egress could not be confirmed"
  (`[WARN]`, matching the exact wording the investigation asked for) from
  "no AAAA at all" (`[INFO]`, not a failure — see §E).
- `check_singbox_binary_version_consistency`: checks the configured
  `sing-box` binary plus the two common fixed install locations
  (`/usr/local/bin/sing-box`, `/usr/bin/sing-box`), runs `version` on
  each one that exists, and warns (naming exactly which path systemd/
  vpn-admin currently uses) if more than one is present with differing
  versions. Silent if only one binary exists (the common, healthy case)
  or if multiple exist but report the same version.
- A permanent `[INFO]` line, printed on every `doctor` run, stating that
  `auto`/`urltest` tests generic HTTPS connectivity, not Telegram, and
  pointing at this document and `docs/TELEGRAM_TROUBLESHOOTING.md`.

New opt-in mode: `vpn doctor --telegram`. Runs the exact same checks as
plain `doctor` (no additional network probing of its own — see the
function's doc comment for why), then prints a Telegram-oriented summary
(current default transport, obfuscation state) ending in the mandatory
disclaimer text specified by the investigation, verbatim:

```
Server-side diagnostics passed.
This does NOT verify:
- Russian DPI compatibility
- Hiddify TUN routing
- Telegram app proxy settings
- Russian mobile ISP behavior
Run the client acceptance checklist next.
```

(printed as a structured multi-line block, not a single sentence, so it
reads clearly in a terminal — see `print_telegram_diagnostics_summary`).

**Tests:** unit tests for the pure decision logic
(`singbox_version_consistency_report`, `probe_singbox_binary_versions`)
that don't require real `/usr/bin`/`/usr/local/bin` binaries to exist in
CI; integration tests in `apps/admin/tests/cli.rs`
(`doctor_fails_on_unresolvable_public_hostname`,
`doctor_reports_ipv4_only_hostname_as_info_not_a_failure`,
`doctor_always_prints_urltest_scope_disclaimer`,
`doctor_telegram_prints_disclaimer_and_never_claims_russian_verification`).
All pass.

## D. Hysteria2 hardening

Audited (not changed, beyond the diagnostics above): Salamander
obfuscation generation (`credentials::generate_hysteria2_obfs_password`,
cryptographically random), storage (`hysteria_obfs_password_file`, mode
0640 `root:vpn-subscription`, deliberately placed under the shared
`reality_dir()` because `hysteria_dir()` is `sing-box`-only — see that
function's doc comment), rotation (`vpn-admin hysteria-obfs-rotate`:
validates the candidate config with the real sing-box binary before
applying, rolls back fully on any failure, restarts `vpn-subscription`
so it picks up the new password — it caches the password at startup),
and subscription-side rendering (obfs threaded into both the share-link
URI and the native sing-box JSON, tested in `render.rs`).

**Finding:** this mechanism was already correctly designed — optional,
explicit, safe to rotate, and never silently enabled for existing
deployments (which would break every existing client's cached profile
without warning). `vpn doctor` already reported its state before this
pass. The gap closed by this pass is diagnostic *framing*, not the
mechanism: `vpn doctor --telegram`'s summary now states the obfuscation
state specifically in Telegram-troubleshooting context (§C), and
`docs/TELEGRAM_TROUBLESHOOTING.md` references it.

**Not changed:** automatically enabling Salamander for new installs.
This was evaluated and deliberately not done — `install.sh` does not
currently call `hysteria-obfs-rotate` automatically, and adding that
would change new-install behavior in a way that needs its own explicit
review (interaction with `docs/ALMALINUX_DEPLOYMENT.md`'s installation
flow, first-boot subscription generation timing) rather than being
folded into a diagnostics-focused pass. Recommended as a focused
follow-up, not attempted here.

## E. Explicit IPv6 policy

Documented policy, enforced by the new `doctor` check (§B):

- sing-box listens on `::` (dual-stack) for both Reality and Hysteria2
  regardless of DNS — this was already true (`crates/compat-config/src/
  server.rs`) and is not changed.
- If `public_host` has no AAAA record: IPv6-capable clients connect over
  IPv4 only. This is the safe default state (no leak risk from DNS
  resolution) and is now reported `[INFO]`, not silently unmentioned.
- If `public_host` has an AAAA record and the VPS's own IPv6 UDP egress
  probes successfully: `[OK]`.
- If `public_host` has an AAAA record but IPv6 egress cannot be
  confirmed: `[WARN]`, with the exact message the investigation
  specified — this is the ambiguous state the policy explicitly refuses
  to leave silent.

What this does **not** and cannot cover: whether a specific client
device is leaking Telegram traffic over its own native IPv6 route
instead of the tunnel. That is a client-side property vpn1's server
cannot observe from the server. `docs/TELEGRAM_TROUBLESHOOTING.md` §6
documents how to check for it from the client.

## F. Client diagnostics documentation

New: `docs/TELEGRAM_TROUBLESHOOTING.md` — the 8-step procedure specified
by the investigation (disable Telegram's own proxy first, test each
transport independently, the full functionality checklist, Android
per-app/Always-on-VPN/battery checks, iOS VPN-profile/proxy checks,
IPv6-leak detection, controlled MTU experiments with an explicit
rationale for why vpn1 doesn't apply a global MSS/MTU override, and
exactly what evidence to collect — with an explicit list of what must
never be shared).

## G. Acceptance tests

**Changed:** `docs/DEVICE_ACCEPTANCE_TESTS.md` — added the Telegram x
transport (Reality/Hysteria2/Auto) x function matrix, the dated-entry
template for it, and an explicit statement that this matrix cannot be
filled in from outside Russia and stays "not yet tested" until someone
does.

## H. Better debug bundle

**New:** `vpn doctor --report` (optionally `--report-output PATH`,
writing mode 0600 instead of stdout). Produces a sanitized bundle:
versions, service state, listener presence, hostname-resolution counts,
transport/obfuscation configuration status, certificate expiry,
firewall summary, selected non-secret configuration fields, and a
redacted tail of `journalctl -u sing-box -u vpn-subscription`.

Redaction (`redact_secrets`, no new dependency — implemented over
`std` only): strips anything shaped like a UUID (VLESS UUIDs) or a
long (24+ char) hex or base64url-ish token (REALITY keys, subscription
tokens, Hysteria2/obfuscation passwords — all generated in exactly this
shape by `crates/compat-config/src/credentials.rs`), replacing each with
`<redacted>` while leaving surrounding text — including non-ASCII/UTF-8
log content — intact. Deliberately over-inclusive: a false-positive
redaction is the safe failure mode for something meant to be pasted
elsewhere; a missed one is not.

**Tests:** 5 unit tests covering UUID redaction, hex-token redaction,
base64url-token redaction, no false positives on ordinary log prose, and
UTF-8 preservation around a redacted token; 3 integration tests covering
section presence, that a real REALITY private key generated by `init`
never appears in the output, and that `--report-output` writes mode
0600. All pass.

## I. Version consistency

**Changed:** `apps/admin/src/main.rs`, `check_singbox_binary_version_consistency`
(§B above has the detail). Read-only — never changes which binary is
active, only reports drift.

## J. Why no global MTU/MSS change was made

Both are unverified-scope, high-blast-radius interventions:

- Server-side MSS clamping only affects Reality (TCP); it cannot touch
  Hysteria2 (QUIC/UDP) at all, so it can never be "the fix" for both
  transports even in the best case.
- QUIC (Hysteria2) does its own path-MTU discovery inside its encrypted
  stream — a server-side network device (including vpn1's own sing-box)
  cannot inspect or clamp it. The only real lever is a client-side MTU
  override, if the client exposes one.
- No evidence in this repository or from the reported symptoms
  specifically implicates MTU/PMTU over other candidate causes (proxy
  settings, split tunneling, IPv6 leakage, DPI targeting).
- A wrong global value degrades every user on every network, all the
  time, in exchange for possibly helping one user's one path.

`docs/TELEGRAM_TROUBLESHOOTING.md` §7 gives the controlled, revertible,
per-device experiment procedure instead (1400/1360/1280, when the
client exposes an override), which is the appropriate place for a value
that is genuinely path-dependent.

## K. Multi-node design (documented, not implemented this pass)

### Why this is the most promising remaining lever

A single VPS is vulnerable to IP/subnet/ASN-level blocking, provider-
specific Telegram peering issues, and single points of routing failure
— none of which any number of *local* transports on that one VPS can
fix. For ~10 users, two independent VPS endpoints plausibly provide more
real resilience than a third or fourth transport on one server (per the
investigation's own framing). This is a genuine architectural gap, not
a hypothesis about Telegram specifically.

### What already generalizes to multi-node with zero code changes

`render_singbox_client_subscription` (§A) operates over an arbitrary
`&[CompatEndpoint]` and already builds one `selector` option per
endpoint by its `label`. Nothing about it assumes exactly one node or
exactly two endpoints — a subscription containing `"Node A - Reality"`,
`"Node A - Hysteria2"`, `"Node B - Reality"`, `"Node B - Hysteria2"` as
four labeled endpoints would render correctly today, with the selector
defaulting to the first `VlessReality`-transport tag in the list. This
was verified directly by this pass's own test suite (the renderer is
exercised with arbitrary endpoint lists, including a single-endpoint
edge case, with no special-casing required).

### What is genuinely missing

`compat_config::deployment::DeploymentConfig` (and everything built on
it — `vpn-admin`, `services/subscription`, the whole `/etc/vpn/compat`
state layout) assumes exactly one node: one `state_dir`, one REALITY
keypair, one Hysteria2 obfuscation password, one `users.json`. Real
multi-node support needs an answer to a genuinely hard question this
pass deliberately did not rush: **does a user have one identity valid on
every node, or independent per-node identities?**

- **Option A — independent per-node deployments, one merging layer.**
  Each node runs today's single-node stack completely unmodified (same
  `install.sh`, same `vpn-admin`, same trust boundary, same secrets,
  zero new attack surface per node). A new, separate, deliberately thin
  service would fetch each node's already-public subscription data (or
  read a small manually-maintained manifest) and merge it into one
  combined subscription response using the *already-generalized*
  renderer above. Per-user credentials would necessarily differ per
  node (each node's `vpn-admin user create` is independent), which is
  actually a security *improvement* over a shared identity — a leaked
  credential only compromises one node.
- **Option B — shared user identity replicated across nodes.** Would
  require synchronizing `users.json` (including secrets) across
  independent hosts, a new class of cross-host trust and a new failure
  mode (replication lag/split-brain — the exact incident class
  `docs/INCIDENT_2026-08-10_REALITY_HANDSHAKE_TIMEOUT.md` already
  documents *within a single node*). Rejected as materially riskier for
  no clear benefit to ~10 users who can each hold two subscription
  profiles instead.

**Recommendation: Option A, as a follow-up session with its own focused
security review** — not rushed into this diagnostics-and-reliability
pass. The credential-distribution and cross-host-trust design deserves
dedicated attention, not a late addition to a session that was already
touching diagnostics, rendering, and documentation across a dozen files.

### What works today, with zero code changes, as an interim mitigation

Run two fully independent vpn1 deployments (two separate VPSes, `sudo
./deploy/almalinux/install.sh` on each, unmodified). Give each of the
~10 users two Hiddify profiles — one subscription URL per VPS. If one
VPS/IP/ASN gets blocked, users manually switch to the other profile.
This requires no new code, no new trust boundary, and no schema change
— it is available today, and is the recommended interim answer to "what
do we do if this VPS gets blocked" until Option A above is built
properly.

### Rollback (gap identified 2026-08-12, addressed here)

This section originally covered credential isolation, updates, and
health-check limits for Option A, but never addressed rollback — a real
gap flagged by a later performance-focused audit of this plan. Recorded
here so a future Option A implementation doesn't have to re-derive it:

- **Merging-layer rollback is inherently cheap, by construction.** Because
  Option A keeps each node's `install.sh`/`vpn-admin` completely
  unmodified and the merge step is a separate, thin, stateless service
  that only *reads* each node's already-public subscription data, the
  merge layer itself has no persistent state to roll back — reverting it
  to a previous version (or removing it entirely) cannot corrupt or
  desynchronize either node, because neither node depends on the merge
  layer's existence to keep serving its own users.
- **Per-node rollback is just single-node rollback, already covered.**
  Since each node is an independent, unmodified deployment, rolling back
  a bad `vpn1` update on Node B (e.g. via the existing
  `deploy/almalinux/update.sh` version-pin/reinstall path, or
  `deploy/lib/perf-tuning.sh rollback` for kernel tuning specifically)
  never touches Node A or the merge layer's config. This is a direct
  consequence of rejecting Option B (shared/replicated identity) above —
  there is no cross-node state for a rollback to get half-applied to.
- **Adding a node is reversible without a code change.** Per "What works
  today" above, the zero-code interim mitigation (two independent
  deployments, two subscription URLs) means a bad or unreachable Node B
  can simply be decommissioned and its subscription URL withdrawn,
  leaving Node A users completely unaffected — this is true whether or
  not the merge layer from Option A has been built yet.
- **What a merge-layer rollback plan would still need to define, before
  Option A ships**, is out of scope for this document to invent
  unilaterally and belongs in that follow-up session's own review: which
  git ref/tag the merge service pins per node (so "roll back the merge
  layer" and "roll back a node" stay independent operations), and how an
  operator distinguishes "Node B is intentionally being rolled back" from
  "Node B silently went unreachable" in the merged subscription's
  behavior (both must not, e.g., silently drop Node B's users to a
  broken selector entry).

### 2026-08 addendum: fresh research on the open questions above

A follow-up investigation (iPhone/Telegram/Russia resilience pass,
2026-08-11) re-researched the specific open questions this section left
unanswered, using current primary sources. Findings, each graded:

- **sing-box still has no ordered-failover primitive** (CONFIRMED
  against `sagernet/sing-box` source at HEAD as of 2026-08-11).
  `selector` is manual-only (no health check at all);
  `urltest` is a latency race with a sticky `tolerance` window — it
  prefers whichever outbound is *currently selected* unless a candidate
  beats it by more than `tolerance` (default 50ms), and only falls back
  to list-order when NO outbound has any latency history yet (which can
  hand a dead node to a client that never got a successful probe). List
  order does not otherwise express priority. Feature requests for a
  true "try A, else B, else C" priority group
  (github.com/SagerNet/sing-box/issues/2130 and /4065) are both open
  and unimplemented. This confirms Option A's own framing above: a
  `selector` (manual override, default = REALITY on the
  first/preferred node) containing all four labeled endpoints, plus one
  `urltest` "auto" group racing all four, is the most correct
  structure achievable with stock sing-box today — true deterministic
  ordered failover is not.
- **Hysteria2 Salamander fingerprinting in Russia specifically: UNKNOWN
  / SPECULATIVE, not LIKELY** — this addendum previously over-graded
  this claim; corrected below (2026-08-11 re-check §2026-08-11b).
- **AWS as Node B's provider: still UNKNOWN whether the specific IP is
  reachable from Russia** — this addendum's original framing stands;
  run `docs/AWS_REACHABILITY_TEST.md` before deploying it to real
  users.
- **Telegram's status in Russia**: treat any specific 2026 block
  date/percentage as UNVERIFIED secondary aggregation, not a primary
  measurement this repo confirmed directly. Qualitatively, multiple
  independent 2026 sources (Zona Media, Meduza, Amnesty International)
  describe a rolling throttle/block campaign since Feb 2026 — this does
  not change this plan's priorities either way: getting a VPN tunnel
  out of Russia reliably (REALITY primary, Hysteria2 secondary) remains
  the dominant lever regardless of exactly how Telegram itself is being
  targeted.

### 2026-08-11b addendum: re-check of the above, with stricter evidence discipline

A second-pass fact-check (triggered by review of the first addendum,
same day) re-verified the Gecko/Salamander claims against primary
sources with much stricter grading — a claim only counts as evidence
if it cites an actual observed event (a measurement, a dated user
report, a named ISP), not a generic engineering discussion. Corrections:

- **Salamander-in-Russia fingerprinting claim downgraded to UNKNOWN.**
  The only source behind the original "may already be fingerprintable
  in Russia" claim was `throneproj/Throne#1563`, a feature-request
  thread that *asserts* "DPI systems in Russia/China/Iran detect and
  block Salamander's XOR-obfuscated QUIC traffic" with **zero
  supporting measurement, date, or ISP name** — it is an unsupported
  claim embedded in a design discussion, not evidence of an actual
  Russia-specific event. No OONI report, no net4people/bbs issue, and
  no Russian-media report of an actual observed Salamander-specific
  block was found. **Do not describe Salamander as "likely
  fingerprintable in Russia" without a real incident report** — as of
  2026-08-11 that claim is UNKNOWN, not LIKELY.
- **Generic UDP/QUIC blocking in Russia is CONFIRMED, separately from
  Salamander specifically.** Russia's TSPU DPI system has documented,
  multi-sourced QUIC/UDP-443 filtering behavior (a 2026 FOCI/PETS
  measurement paper on "Russia's Early Introduction of QUIC SNI
  Censorship"; Zona Media's April 2026 reporting that Roskomnadzor
  "almost completely blocked unidentified UDP traffic" over summer
  2026). This means Hysteria2 (any obfuscation) is exposed to a real,
  confirmed UDP-blocking risk in Russia — but that risk is about UDP
  being targeted generically, not about Salamander's obfuscation
  specifically being classified and singled out. REALITY (TCP) staying
  the primary/default transport is well-supported by this distinction
  on its own, independent of the Salamander question.
- **VLESS+REALITY: upgrade to PROBABLE (partial degradation), with real
  citations.** Unlike the Salamander claim, informal-but-real,
  dated, Russia-specific user reports exist: `net4people/bbs#490`
  (June 2025, TLS connections >~15-20KB to foreign IPs freezing after
  ~15-20KB on mobile networks) and `net4people/bbs#546` (Nov 2025,
  named ISPs — MTS/MGTS Moscow, RTK Izhevsk, JustLan — throttling/
  resetting VLESS+Reality+Vision connections, with some users reporting
  that dropping `flow: xtls-rprx-vision` or using non-TLS-mimicking
  variants helped). This is community-sourced, not an academic
  measurement study, but it is genuinely Russia-specific and describes
  actual observed behavior, not a theoretical concern. **Not currently
  acted on** (no flow/config change made this pass — one or two
  informal reports are not enough to change ~10 users' default
  transport), but worth tracking: if this becomes a widely-reported
  problem, `flow: xtls-rprx-vision` may be worth making
  operator-toggleable per net4people/bbs#546's informal finding.
  Grade: PROBABLE for "REALITY sometimes throttled/probed on specific
  Russian ISPs"; SPECULATIVE/unsupported for any claim that REALITY is
  broadly or reliably blocked.
- **Gecko obfuscation: status changed from "not implemented" to
  "implemented but not stable," which is a materially different fact
  even though the action (do not adopt yet) is unchanged.** Checked at
  every layer, 2026-08-11:
  - `apernet/hysteria` (upstream protocol reference): Gecko shipped in
    v2.9.2, marked **experimental** in its own changelog.
  - `SagerNet/sing-box`: Gecko was merged, but only into
    **`1.14.0-alpha.26`**, part of the still-unreleased 1.14.0 line.
    Current stable is **1.13.18**; current pre-release is
    **1.14.0-beta.14** — no stable 1.14.0 has shipped as of 2026-08-11.
  - Hiddify's own bundled/forked core (`hiddify/hiddify-sing-box`,
    latest release `1.13.0.h5`, Feb 2026) is based on upstream
    sing-box ~1.13.0 — several minor versions before Gecko even landed
    in an alpha. Hiddify's iOS client cannot use Gecko regardless of
    what the server runs.
  - vpn1's pinned production sing-box (1.13.14 / 1.13.18 on Node A)
    also predates Gecko.
  - **Conclusion unchanged from the first addendum: do not adopt
    Gecko.** Both the server side (no stable sing-box release supports
    it) and the client side (Hiddify's bundled core doesn't either)
    are missing it simultaneously — this is not a "waiting on one
    open issue" situation, it's "waiting on a stable release + a
    client core bump," a materially higher bar. Track sing-box's
    1.14.0 stable release and Hiddify's core-fork version bump
    together before revisiting.
  - **Separately and more urgently for iOS specifically**: as of
    2026-08-11, `hiddify/hiddify-app#2317` is a currently OPEN issue
    describing Hiddify's iOS release CI as broken — the live App Store
    build was shipping as an unsigned "dev" flavor because signed iOS
    release jobs were failing Apple auth. This is unrelated to Gecko
    but is a more concrete, currently-tracked, iOS-specific risk factor
    worth flagging to users experiencing any iOS connectivity problem
    (see `docs/clients/HIDDIFY_IOS.md`).

None of the above changes this document's existing "Not changed" list.
No transport, obfuscation mode, or MTU value was altered by either
addendum — together they sharpen the evidence behind decisions already
made above and flag concrete items (Gecko's real blocker being a
version-pair, not one open issue; Salamander's Russia-specific
fingerprinting being unproven; REALITY's informal-but-real throttling
reports; Hiddify's current iOS release-pipeline problem) to revisit
with further verification before acting on them.

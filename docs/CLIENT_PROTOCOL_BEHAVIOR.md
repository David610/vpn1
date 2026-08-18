# Client protocol behavior contract

Protocol-level facts about what the generated subscription/server config
actually controls, versus what depends entirely on the client
application or the client's OS/network. Per-client walkthroughs
(`docs/clients/`) restate the relevant parts of this in device-specific
terms; this document is the single place the underlying facts live, so
they don't drift between per-client docs. Nothing here is claimed from
spec conformance alone — see `docs/CLIENT_COMPATIBILITY.md` and
`docs/DEVICE_ACCEPTANCE_TESTS.md` for what has actually been verified
against a real client/device versus what remains a documented, honest
assumption.

## What vpn1 generates vs. what the client controls

| Layer | Who controls it | vpn1's role |
|---|---|---|
| VLESS+REALITY / Hysteria2 outbound config (server, port, UUID/password, keys, SNI) | vpn1 (subscription renderer, `crates/compat-config/src/render.rs`) | Generates it; server and client always agree because both are rendered from the same `CompatUser`/`RealityServerParams`/`Hysteria2ServerParams` state — see `server_and_client_configs_agree_on_reality_key_material` in `crates/compat-config/tests/reality_interop.rs`. |
| Which transport is selected by default | vpn1 (a `selector` outbound with `default` set — see `render.rs`'s `SelectionProfile`) | Deterministic (REALITY by default), never a silent race — but the client can always override it by hand, and a manual `urltest` (`auto`) option is offered, never forced. |
| **Full-device tunneling (TUN/VPN mode vs. proxy-only)** | **The client app + client OS**, entirely | **Not present anywhere in the generated config.** The subscription contains only `outbounds` + `route.final` — no `inbounds`, no TUN/interface directive. Whether traffic actually leaves the device through the tunnel depends 100% on the client's own "Service Mode: VPN/TUN" setting (Hiddify) and the OS granting a VPN permission. This is documented per-client (see `docs/clients/HIDDIFY_IOS.md`'s "Four different claims" table) rather than assumed. |
| DNS resolution while connected | The client app's own DNS handling | **The generated config has no `dns` block.** vpn1 does not choose a resolver, does not force DNS through the tunnel, and cannot detect or prevent a client/OS-level DNS bypass (e.g. a device-wide "private DNS" setting that ignores the VPN's DNS). Any DNS behavior is whatever Hiddify's own template/defaults do with the imported outbounds — untested by this project on a real device (see below). |
| IPv4 / IPv6 | Server: dual-stack listener. Client: entirely its own routing behavior | Server-side: both inbounds bind `"listen": "::"` (dual-stack wildcard — accepts IPv4 and IPv6 client connections if the OS/network provide both). The generated config has no `route` rules restricting/preferring either family for the client's own traffic, and no explicit AAAA/A DNS handling — that's the client's own resolver + OS routing, not something this config expresses. |
| MTU / fragmentation | The client app + OS network stack | No MTU/MSS override is set anywhere in this repo's generated config. Upstream sing-box's own defaults are used unless a reproducible failure demonstrates otherwise — none has been observed or reported as of this writing. |
| Kill switch / leak prevention if the tunnel drops | The client app | Not something a server-side subscription can express or enforce at all — sing-box's client-side "on connection failure" behavior (if any) is entirely Hiddify's own implementation, untested here. |

## DNS — explicit statement

- **Resolver used while connected**: whatever the client app (Hiddify)
  configures by default for an imported `outbounds`-only profile with no
  explicit `dns` block. Not controlled or overridden by this server.
- **Does DNS travel through the tunnel**: unknown/unverified — depends on
  the client's own routing of DNS queries once VPN/TUN mode is active.
  Not something this project's server-side config can force.
- **Can system/private DNS bypass it**: plausible — a device-level
  "private DNS" setting (Android) or per-app DNS override, if the client
  doesn't route DNS through its own TUN interface, would resolve outside
  the tunnel. Not tested against a real device.
- **Tunnel-failure behavior**: whatever the client app does (fail closed,
  fail open, or resume the pre-VPN resolver) — not configurable from the
  server side, not tested.
- **Do not claim DNS leak prevention** — no real-device DNS leak test has
  been run (see `docs/DEVICE_ACCEPTANCE_TESTS.md`; there is no "DNS leak"
  column in that matrix yet because no test has been attempted). A DNS
  leak test (e.g. https://dnsleaktest.com from the connected device,
  compared against the same test with the VPN off) is the only way to
  establish this and remains an open manual test.

## IPv4 / IPv6 — explicit statement

- **Server listener**: both VLESS+REALITY and Hysteria2 inbounds bind
  `"::"` (all interfaces, dual-stack) — see `render_singbox_server_config`
  in `crates/compat-config/src/server.rs`. A dual-stack VPS accepts
  client connections over either family; an IPv4-only VPS (most cloud
  providers by default) only ever has an IPv4 address to connect to,
  regardless of this listener setting.
- **`public_host`/DNS A/AAAA records**: entirely operator-controlled —
  this project neither manages DNS records nor inspects which record
  types exist for the configured domain. If only an A record is
  published, clients only ever reach the server over IPv4, full stop —
  no code path here compensates for that.
- **Client route behavior for the client's OWN traffic** (i.e. whether
  the client's IPv6 traffic is tunneled, dropped, or leaks outside the
  tunnel) is entirely the client app's decision — not expressed anywhere
  in the generated config, not tested against a real device.
- **VPS/domain with IPv4 only**: works as long as the client itself can
  reach the server's IPv4 address — no different from any IPv4-only
  service. Not a degraded mode; nothing here assumes IPv6 exists.
- **Client prefers IPv6**: if the client's network prefers IPv6 for
  general routing but the server domain only has an A record, standard
  DNS resolution falls back to the IPv4 address like any other IPv4-only
  service — this is normal DNS/happy-eyeballs behavior, not something
  vpn1 needs to special-case.
- **No partial/ambiguous dual-stack behavior is introduced by this
  project**: the server config is deliberately silent on IPv4-vs-IPv6
  preference: it does not force one, does not disable one, does not
  attempt Happy-Eyeballs-style logic. Ambiguity here comes only from
  whatever the operator's DNS records and the client's own network
  actually provide.

## UDP / TCP behavior

- **VLESS+REALITY**: runs over TCP/443 by design (the REALITY disguise
  requires a real TCP TLS handshake with a decoy). Any UDP the client
  sends (including a device's own QUIC/HTTP3 traffic to third-party
  sites) is relayed multiplexed over that same TCP connection, using
  full-cone/per-destination-session (`xudp`) framing. The generated
  outbound now sets `"packet_encoding": "xudp"` explicitly (added
  2026-08-18) — **but this is sing-box's own documented default for
  this field regardless**, so setting it changes no runtime behavior;
  it exists only so this deployment does not silently depend on an
  implicit upstream default that could change in a future sing-box
  release. An earlier version of this document, and this project's own
  YouTube-app playback investigation, described the field as absent and
  treated its absence as a likely cause of that bug — that was
  incorrect (this project had not checked sing-box's own default value
  before writing that hypothesis), and the hypothesis is weakened, not
  confirmed, by this correction. See `crates/compat-config/src/
  render.rs`'s `render_singbox_client_subscription_with_profile` for
  the exact field.
- **Does this project's subscription's `packet_encoding` even reach a
  real Hiddify iOS user**: not necessarily. `docs/clients/HIDDIFY_IOS.md`
  documents the subscription URL handed to users as
  `?format=hiddify`, which `services/subscription` renders identically
  to `?format=uri` (share links: `vless://...`, `hysteria2://...`) —
  never the native sing-box JSON (`?format=singbox`) this field lives
  in. Whatever sing-box outbound Hiddify itself constructs from a
  parsed `vless://` share link is entirely Hiddify's own doing, not
  something this repository's `packet_encoding` setting can reach or
  verify. This is not a new problem introduced by this correction —
  MTU, DNS, and IPv6 policy were already documented above as entirely
  client-owned for the same reason; `packet_encoding` for
  URI/`format=hiddify` imports belongs in that same category.
- **Hysteria2**: UDP/443 end to end (QUIC-based) — this is the entire
  point of offering it as a secondary transport. **UDP/443 is
  meaningfully more likely to be blocked, throttled, or simply
  unavailable on a given network than TCP/443** (mobile carrier NAT/QoS,
  restrictive Wi-Fi, some censorship regimes actively deprioritize UDP).
  Nothing in this project assumes Hysteria2 will work on every network —
  see `docs/TELEGRAM_RESILIENCE_PLAN.md` and every per-client doc's
  advice to test Hysteria2 independently, never assume it inherits
  REALITY's reachability.
- **When UDP/443 is unavailable**: the manual `selector` outbound
  (`render.rs`) still lists the REALITY (TCP) endpoint and defaults to
  it — Hysteria2 being entirely blocked on a network does not make the
  profile unusable, it just means that one option in the list fails
  while REALITY remains selectable. Verified structurally by
  `render::tests` (the selector always includes every endpoint tag
  regardless of which transports are actually reachable) — not the same
  claim as a real network blocking UDP and REALITY still working, which
  requires a real device test (see `docs/DEVICE_ACCEPTANCE_TESTS.md`'s
  "Network switch" column and the Telegram matrix's IPv4/IPv6/handover
  rows).

## Failover / selection — honest framing

The `auto` group is sing-box's own `urltest`: a plain-HTTPS
latency/success race against `https://www.gstatic.com/generate_204`,
re-checked every minute. It is:

- **Latency/availability selection** — picks whichever configured
  transport currently completes that one HTTPS request fastest.
- **Not censorship-aware** — it has no concept of DPI, active probing,
  Telegram-specific reachability, or throughput. A transport that wins
  the race is not necessarily the right choice under active censorship;
  see `docs/TELEGRAM_RESILIENCE_PLAN.md` for why REALITY is the
  deterministic default instead of `auto`.
- **Never the sole option**: the manual `select` group always lists
  every real endpoint plus `auto`, and `route.final` points at `select`
  (not `auto`) — so a user who never touches the proxy-group UI still
  gets the deterministic REALITY default, and `auto`/individual
  transports remain manually selectable regardless of profile. See
  `SelectionProfile` in `render.rs`.

## Subscription security recap

(Fully covered by existing automated tests — restated here for
completeness, not re-litigated.)

- The subscription URL (`/sub/<token>`) is a bearer credential — anyone
  with it can import the profile. `services/subscription` never logs the
  raw token (`deploy/lib/check-no-secret-logging.sh`, run in CI) and
  returns a **generic 404** for unknown, disabled, or expired tokens —
  never a distinguishing error that would let an attacker enumerate
  valid tokens.
  (`unknown_token_returns_generic_404`,
  `disabled_user_token_returns_404_not_a_distinguishable_error` in
  `services/subscription/src/lib.rs`.)
- Every subscription response (success or error) carries
  `Cache-Control: no-store` — no caching by any intermediary under this
  project's control (`no_store_headers` middleware).
- A disabled/removed user immediately stops receiving a valid
  subscription response (404) — the distinction between "token revoked"
  (still 404s, subscription unusable) and "user disabled but the
  already-live REALITY/Hysteria2 credentials keep working until
  rotated/disabled at the server" is spelled out per-command in
  `docs/clients/HIDDIFY_IOS.md`'s blast-radius table — the two are
  different operations with different effect, not interchangeable.

## What has NOT been verified (see `docs/DEVICE_ACCEPTANCE_TESTS.md`)

- Real DNS-leak test on a connected device (no column exists yet for
  this — add one when a real test is run).
- Real IPv6-preferring-network client behavior.
- Real UDP-blocked-network behavior (Hysteria2 failing while REALITY
  keeps working, confirmed on an actual restrictive network rather than
  inferred from server-side config structure).
- MTU/fragmentation failures under real network conditions — none
  reported; if one is, record it in `docs/DEVICE_ACCEPTANCE_TESTS.md`
  and only then consider a conservative override.

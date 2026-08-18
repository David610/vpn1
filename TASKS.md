# TASKS.md

Status legend: `[ ]` not started · `[~]` in progress · `[x]` completed · `[!]` blocked/deferred (with reason)

## Phase 0 — Repo audit & architecture
- [x] Inspect repository (empty repo, fresh start)
- [x] PLAN.md
- [x] docs/ARCHITECTURE.md
- [x] docs/THREAT_MODEL.md
- [x] docs/TRANSPORT_MODEL.md
- [x] docs/RENDEZVOUS_DESIGN.md
- [x] docs/SECURITY_MODEL.md
- [x] docs/PRIVACY_MODEL.md
- [x] docs/FAILURE_CLASSIFICATION.md
- [x] docs/DECISION_ENGINE.md
- [x] docs/DEPLOYMENT.md
- [x] docs/TEST_STRATEGY.md
- [x] docs/ADR/0001-language-choice.md
- [x] docs/ADR/0002-transport-portfolio.md
- [x] docs/ADR/0003-transport-runtime-deferred.md
- [x] docs/ADR/0004-rendezvous-design.md
- [x] docs/ADR/0005-telemetry-policy.md
- [x] docs/ADR/0006-relay-topology.md
- [x] docs/ADR/0007-persistence.md
- [x] docs/ADR/0008-signing-hierarchy.md

## Phase 1 — Core foundations
- [x] Workspace Cargo.toml
- [x] crates/common (ids, error types, time buckets)
- [x] crates/crypto (ed25519 signing/verify via `ed25519-dalek`; three-tier key hierarchy; `Secret<T>` no-Debug wrapper). Session-layer crypto (TLS/QUIC, using `rustls`'s `ring` backend) lives in `transport-native`, not here.
- [x] crates/config (signed bundle schema, validation, expiry, revocation) + tests
- [x] crates/transport-api (Transport trait, capability negotiation) + tests
- [x] crates/network-state (failure categories, observation types)
- [x] crates/failure-classifier (state machine) + unit + property tests
- [x] crates/policy (endpoint/transport confidence scoring, quarantine) + tests

## Phase 2 — Local vertical slice
- [x] crates/transport-native: `direct-tls` (rustls) stream transport
- [x] crates/transport-native: `noise-quic` (quinn) datagram-oriented transport
- [x] services/relay-agent: ingress + egress forwarding (TCP/QUIC -> upstream)
- [x] apps/client-daemon: local SOCKS5-ish loopback proxy entrypoint driving transport+engine
- [x] tests/: end-to-end local test service reachable client -> ingress -> egress -> test HTTP server

## Phase 3 — Adaptive connection engine
- [x] Endpoint + transport scoring wired into client-daemon
- [x] Non-deterministic fallback (weighted, jittered) instead of fixed order
- [x] Quarantine on repeated failure, decay over time
- [x] Failure classification wired to real connect() error paths
- [x] Simulated failure integration tests (blocked transport / blocked endpoint)

## Phase 4 — Signed rendezvous
- [x] services/rendezvous: issue signed, expiring, limited relay subset
- [x] rendezvous-client crate: fetch + verify + cache + emergency-bundle fallback
- [x] key rotation model documented + implemented (root -> release -> bundle signing key)

## Phase 4b — Production key management (ADR-0008 tooling)
- [x] `apps/keytool` offline signing-ceremony CLI: `root-init`,
      `release-issue`, `bundle-issue`, `revoke-issue`, `verify-chain`.
      Never opens a socket; only reads/writes local files.
- [x] `crypto::KeyPair::save_to_file` / `load_from_file`: hex-encoded key
      files written mode 0600, load refuses any file with group/other
      permission bits set (`CryptoError::InsecureKeyPermissions`).
- [x] `config::revocation::SignedRevocationList`: revocation lists signed
      by the release key (chains to root), independently verifiable by
      any holder regardless of delivery channel.
- [x] `services/rendezvous --key-dir/--release-cert-file`: loads a
      persisted bundle key + cert chain instead of generating an
      ephemeral hierarchy every boot (ephemeral path kept for local dev,
      now logs `warn` not `info`). `--revocation-list-file` serves the
      signed list verbatim at `GET /v1/revocation-list`.
- [x] `services/relay-agent --identity-dir`: persists the relay's
      TLS/QUIC identity (cert mode 0644, key mode 0600) across restarts
      so previously-issued bundles' `cert_sha256_hex` pins don't go stale.
- [x] Full chain tested for real against the actual `vpn-keytool` binary
      and real files on disk (`apps/keytool/tests/ceremony.rs`): sign
      with a persisted hierarchy, verify via `config::verify_bundle` on a
      fresh check, rotate the bundle key, issue a signed revocation
      naming the old key, confirm the old key's signature is now
      rejected (`ConfigError::RevokedKey`) while the new key still
      verifies. Also covers `verify-chain` and refusal to overwrite an
      existing root key.
- [~] Revocation-list *serving* is wired (rendezvous endpoint), but
      `rendezvous-client`/`apps/cli` do not yet fetch it automatically —
      today a caller must pass a `RevocationList` in explicitly (see
      `RendezvousClient::get_bundle`). Wiring an automatic
      fetch-and-verify-then-use-for-every-bundle-check path is the
      natural next step; not done this session for scope reasons, not
      because of a technical blocker.

## Phase 5 — Sandboxed transport runtime
- [!] WASM/WASI transport runtime — deferred, documented in ADR-0003 and
      TRANSPORT_MODEL.md with the security boundary spec a follow-up must
      satisfy. Not stubbed as fake-working code.

## Phase 6 — Multiple real transport families
- [x] Two independent families implemented (direct-tls, noise-quic)
- [!] Third family (e.g. obfs4/Snowflake adapter) — not started, evaluated
      in ADR-0002, left for follow-up (external project integration needs
      separate legal/license review time this session doesn't have).

## Phase 7 — Measurement plane
- [x] telemetry crate: typed, minimal event schema (no destinations/payloads)
- [x] docs/TELEMETRY_DICTIONARY.md
- [!] Aggregation/collection service — not started (documented as future work)

## Phase 8 — Relay separation
- [x] relay-agent supports combined ingress+egress and split ingress->egress

## Phase 9 — Linux networking integration
- [!] TUN device + routing + kill-switch firewall integration — still not
      implemented (follow-up session priority, not attempted this session:
      time was spent on Priority 1 key-management tooling, which this
      session's branch/task explicitly led with). Interface
      (`KillSwitch` trait) and policy remain defined and unit tested
      against a mock backend only; real nftables backend documented as
      follow-up in DEPLOYMENT.md. Re-checked this session:
      `ip`/`tc`/network-namespace tooling is still absent from the
      sandbox (see Phase 11 below), which would also have blocked testing
      a real backend even if implemented.

## Phase 10 — CLI and diagnostics
- [x] apps/cli: `transports`, `config-verify`, `diagnostics` (no daemon control-plane IPC exists yet, so `connect`/`disconnect`/`status` against a *running* daemon are not implemented — see docs/DEPLOYMENT.md and the CLI's own module doc comment)

## Phase 11 — Security testing
- [x] fuzz targets: config bundle parser, rendezvous response parser
- [x] property tests: state machine invariants, scoring bounds, serialization round-trips
- [~] tc netem hostile-network tests: script + `#[ignore]`d test written (`tests/hostile_network/`) and reviewed; still not executed — re-checked this session (`which ip tc` both fail, uid 0 but `iproute2` is simply not installed in this sandbox image), so the situation is unchanged from the prior session, not newly re-verified as fixable. Failure-independence *is* proven without netem via `tests/failure_independence.rs` (deterministic connection-refused simulation), which is a real but weaker substitute — see docs/TEST_STRATEGY.md.
- [~] cargo-fuzz targets (`fuzz/`) still not executed — re-checked this
      session: only the `stable` rustup toolchain is installed, no
      nightly, and `cargo-fuzz` was not present. Proptest-based substitute
      tests (`crates/config` `signed_bundle_json_parsing_never_panics_on_arbitrary_bytes`,
      `expiry_check_never_panics`) remain the documented fallback and run
      on every `cargo test`.

## Phase 12 — Performance
- [x] criterion benchmarks: config bundle verify (`crates/config/benches/verify.rs`), scoreboard observe+select (`crates/policy/benches/scoring.rs`)

## Phase 13 — UX
- [!] Desktop GUI — explicitly deferred per spec ("only after core works";
      out of scope for this session's time budget)

## Final
- [x] cargo fmt / clippy / test clean
- [x] Final security self-review notes in docs/THREAT_MODEL.md §Review
- [x] Final engineering report delivered to user

## Phase 14 — Hiddify/VLESS-REALITY/Hysteria2 compatibility stack

See `docs/COMPATIBILITY_IMPLEMENTATION_PLAN.md` for the full plan.

- [x] docs/COMPATIBILITY_VERSIONS.md (pinned sing-box 1.13.14, syntax sources)
- [x] docs/COMPATIBILITY_IMPLEMENTATION_PLAN.md
- [x] crates/compat-config: CompatUser/CompatEndpoint/CompatTransport
      types, kept fully separate from `config`/`transport-api` (spec §5)
- [x] crates/compat-config: credential generation (UUID v4, Hysteria2
      password, REALITY short_id, 160-bit subscription token),
      constant-time token verification, tested
- [x] crates/compat-config: VLESS/Hysteria2 URI rendering + sing-box
      client subscription JSON rendering, tested against current
      sing-box config schema
- [x] crates/compat-config: sing-box server config rendering
      (disabled/expired users excluded — revocation), atomic
      validate-then-apply with backup, `CompatibilityBackend` trait for
      future Xray swap-in (spec §53), tested
- [x] apps/admin (`vpn-admin`): user create/list/enable/disable/
      rotate-token/remove/subscription, `init` (REALITY keypair via
      real `sing-box generate reality-keypair`, refuses to overwrite
      without `--rotate`), `render-config`; end-to-end CLI tests
- [x] services/subscription: `GET /sub/{token}` (formats: singbox, uri,
      hiddify), loopback-only, generic 404 on unknown/disabled/expired
      token, per-IP rate limiting, tested
- [x] deploy/almalinux/: install.sh, update.sh (auto-rollback),
      uninstall.sh, firewall.sh, health-check.sh, render-config.sh,
      hardened systemd units, deployment.toml template — written and
      shellcheck/`bash -n`-clean, **not executed against a real host**
      (sandbox has no root network capability / dnf / real VPS)
- [x] docs/CLIENT_COMPATIBILITY.md, docs/HIDDIFY_ANDROID.md,
      docs/ALMALINUX_DEPLOYMENT.md, docs/COMPATIBILITY_SECURITY_REVIEW.md
- [!] Real Hiddify/v2rayNG import validation — not performed (no Android
      device, no public VPS/DNS/TLS cert available in this session);
      documented as the required manual acceptance test in
      `docs/CLIENT_COMPATIBILITY.md`, not claimed as done.
- [!] Network-level failure-independence test for this transport pair
      (UDP-blocked / TCP-reset scenarios) — not executed, same
      `iproute2`/root-network-namespace limitation as the native
      stack's `tests/hostile_network/` (see Phase 11 above);
      `deploy/almalinux/acceptance-test.sh` documents the exact
      commands for a privileged runner without executing them.

## Phase 15 — Production hardening pass

See `docs/PRODUCTION_HARDENING_PLAN.md` for the full issue-by-issue
writeup (root cause, impact, fix, test) and the final engineering
report delivered at the end of that session for exactly what's
implemented-vs-verified.

- [x] Filesystem ownership fixed so `sing-box` can actually read the
      REALITY private key and Hysteria2 TLS cert/key it needs to start
      (previously group-owned `vpn-subscription`/`root`, never
      `sing-box`)
- [x] `config.json` (contains REALITY private key, VLESS UUIDs,
      Hysteria2 passwords in cleartext) now always written 0640
      root:sing-box, including its `.bak` copy; `update.sh` rollback no
      longer hardcodes 0644
- [x] `apply_config_atomically` now `fsync`s the written file and the
      parent directory after rename
- [x] User mutations (`create`/`disable`/`enable`/`remove`/`rotate-*`)
      now reload sing-box and verify it's active, restoring the
      previous config and reporting failure if reload/health fails —
      previously they only rewrote `config.json` with no reload at all
- [x] New `vpn-admin user rotate-vless`/`rotate-hysteria`/
      `rotate-credentials` commands
- [x] User IDs now 128-bit UUIDv4-based (`user_<uuid>`), not the
      previous 32-bit REALITY-short-id-generator reuse
- [x] Hysteria2 `masquerade` (type `file`) configured
- [x] `install.sh` restructured into 15 explicit numbered stages;
      `render-config || true` removed (a failed render now aborts
      install); Hysteria2 TLS cert/key required before services start
      (fails with exact setup commands, no ACME auto-provisioning per
      task constraint); nginx reverse proxy + subscription rate
      limiting + no-cache headers auto-configured when the subscription
      TLS cert is present
- [x] `deploy/almalinux/acceptance-test.sh` added (ownership/effective
      access, services, listeners, cert validity, reverse proxy,
      no-public-listener checks)
- [x] CI: `cargo audit` now blocking (no `|| true`); new
      `singbox-validate` job downloads the pinned real sing-box binary
      and runs `sing-box check` against a real rendered config
- [x] sing-box license corrected (GPL-3.0-only, not MIT) in
      `docs/COMPATIBILITY_VERSIONS.md`
- [x] Subscription responses: `Cache-Control: no-store`,
      `X-Content-Type-Options: nosniff` on every `/sub/*` response
- [~] All of the above is implemented and unit/integration-tested in
      this sandbox but **not executed against a real AlmaLinux 9 host,
      VPS, or Android/Hiddify client** — see
      `docs/PRODUCTION_HARDENING_PLAN.md` status markers.

## Phase 16 — End-user UX completion pass

See `docs/IMPLEMENTATION_AUDIT.md` for the full audit this phase was
scoped from (what already existed vs. what was genuinely missing).

- [x] `vpn-admin user create --qr` / `rotate-token --qr` / `user qr
      NAME`: terminal QR code of the subscription URL. PNG file output
      not implemented (kept the dependency footprint to the `qrcode`
      crate's unicode renderer only — see audit doc for the tradeoff).
- [x] `vpn-admin user create --json`: machine-readable
      `{id,name,enabled,subscription_url}`, no server secrets.
- [x] `vpn-admin version`: own version + configured sing-box binary's
      reported version.
- [x] `vpn-admin status`: service active/inactive, active/disabled user
      counts, config presence, Hysteria2 cert expiry — no secrets.
- [x] `vpn-admin doctor`: numbered `[OK]`/`[WARN]`/`[FAIL]` diagnostic
      checks (sing-box binary + `sing-box check`, REALITY/Hysteria2
      material present and not world-readable, user store parses,
      certificate expiry, systemd unit state, firewalld state); exits
      non-zero on any `[FAIL]`; a check needing an unavailable tool is
      `[WARN]`, never a faked pass.
- [x] `vpn-admin backup` / `restore`: tar of users store + deployment
      config + REALITY key material + Hysteria2 TLS material, written
      mode 0600; restore validates the users file parses and the
      REALITY private key is present *before* touching live state, then
      applies through the same validate→apply→reload→rollback path as
      every other mutating command.
- [x] Second `[[bin]]` target `vpn` (same `main.rs`/clap parser as
      `vpn-admin`) — ergonomic end-user command name, `vpn-admin` keeps
      working unchanged.
- [x] `docs/clients/`: `HIDDIFY_IOS.md`, `HIDDIFY_MAGICOS.md`,
      `HIDDIFY_LINUX.md`, `V2RAYNG_ANDROID.md`, `README.md` index
      (existing `docs/HIDDIFY_ANDROID.md` left in place, cross-linked).
- [x] `docs/DEVICE_ACCEPTANCE_TESTS.md`: explicit platform × protocol
      matrix, all cells "not yet tested" (honest — no real device/VPS in
      this sandbox), plus the exact commands to run the test for real.
- [x] New CLI integration tests: `version`, `status`, `doctor` (failure
      case), `user create --json`, `user create --qr`, `user qr`,
      `backup`/`restore` round-trip.
- [~] None of the new `doctor`/`status` checks that depend on
      `openssl`/`firewall-cmd`/`systemctl` being real were exercised
      against a live system in this sandbox — they degrade to `[WARN]`
      here (verified by test — see `doctor_reports_missing_singbox_binary_as_failure`)
      and need a real AlmaLinux host to exercise the `[OK]` paths.

## Phase 17 — Telegram reliability pass

See `docs/TELEGRAM_RESILIENCE_PLAN.md` for the full investigation,
confirmed issues vs. probable-but-unproven weaknesses, and an explicit
statement that this pass does NOT claim Telegram is fixed under Russian
censorship — there is no way to verify that from outside Russia.

- [x] Deterministic transport default: `render_singbox_client_subscription`
      now emits a manual `selector` outbound (default: REALITY) alongside
      the pre-existing `urltest` `auto` group; `route.final` points at the
      selector, not at `auto`. `auto`/Hysteria2 remain fully selectable.
      Tested (`crates/compat-config/src/render.rs`); docs updated
      (`docs/CLIENT_COMPATIBILITY.md`, `docs/HIDDIFY_ANDROID.md`,
      `docs/clients/HIDDIFY_IOS.md`,
      `docs/INCIDENT_2026-08-10_REALITY_HANDSHAKE_TIMEOUT.md`).
- [x] `vpn doctor`: new public-hostname/IPv6-policy check (A/AAAA
      resolution + AAAA-conditional IPv6 egress probe), new multiple-
      sing-box-binary version-consistency check, permanent `[INFO]`
      reminder that `auto`/`urltest` is not a Telegram-specific test.
      Tested (`apps/admin/src/main.rs` unit tests +
      `apps/admin/tests/cli.rs` integration tests).
- [x] `vpn doctor --telegram`: server-side-only Telegram-oriented
      summary, ending in the exact disclaimer specified by the
      investigation (never claims Russian DPI/client verification).
      Tested.
- [x] `vpn doctor --report [--report-output PATH]`: sanitized diagnostic
      bundle; `redact_secrets` strips UUIDs and hex/base64url-shaped
      tokens (no regex dependency added) without corrupting non-ASCII
      text. 5 unit tests + 3 integration tests, including a real-secret-
      never-appears assertion against a freshly `init`'d deployment.
- [x] `docs/TELEGRAM_TROUBLESHOOTING.md`: 8-step client-side procedure
      (Telegram's own proxy, per-transport testing, the 9-function
      checklist, Android/iOS-specific checks, IPv6-leak detection,
      controlled MTU experiments, evidence collection with an explicit
      never-share-this list).
- [x] `docs/DEVICE_ACCEPTANCE_TESTS.md`: new Telegram x transport x
      function matrix, all cells honestly "not yet tested."
- [x] Hysteria2 Salamander obfuscation audited: mechanism was already
      correctly designed (optional, explicit, safe rotation, never
      silently enabled) — no code change needed there; diagnostic
      framing improved (`doctor --telegram`'s summary, troubleshooting
      doc cross-reference).
- [!] Multi-node (multiple independent VPS endpoints in one
      subscription) — design documented in
      `docs/TELEGRAM_RESILIENCE_PLAN.md` §K, deliberately NOT
      implemented this pass. The subscription renderer already
      generalizes to N labeled endpoints with zero code changes
      (verified by this pass's own tests); the genuinely missing piece
      is credential-distribution/cross-host-trust design for
      `DeploymentConfig`/`vpn-admin`/`services/subscription`, which
      deserves its own focused security review rather than a late
      addition to this pass. Interim zero-code mitigation documented:
      run two independent single-node deployments and give each user two
      subscription profiles.
- [!] Automatic Hysteria2 Salamander enablement for brand-new
      installs — evaluated, not implemented; needs its own review of
      `install.sh`'s first-boot subscription-generation timing rather
      than a late addition to this pass.
- [!] Global MTU/MSS override — deliberately not implemented; see
      `docs/TELEGRAM_RESILIENCE_PLAN.md` §J for why (cannot help
      Hysteria2/QUIC at all, no evidence it's the actual cause, wrong
      value degrades every user). Controlled, revertible, client-side
      experiment procedure documented instead.
- [~] None of this pass's new checks were exercised against a real VPS,
      real Hiddify/Android/iOS device, or a real Russian network — see
      `docs/TELEGRAM_RESILIENCE_PLAN.md` §5 "Remaining limitations."
      `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D
      warnings`, and `cargo test --workspace` all run clean in this
      sandbox (3 pre-existing, unrelated `apps/admin` integration-test
      failures reproduce identically on `main` without this pass's
      changes — a missing `vpn-subscription` system group in this
      sandbox, not a regression).

## Phase 16 — YouTube-app playback investigation follow-up

Prompted by a real production report: iPhone + Hiddify, YouTube's native
app failed to play video over both VLESS+REALITY and Hysteria2 while
Safari and ordinary HTTPS worked. See the accompanying diagnosis
(35-hypothesis classification, ranked experiments) for full detail; this
phase implements what could be safely, honestly fixed from the repo
alone — no real device or packet capture was available.

- [x] Hysteria2 has never had a live protocol self-test — `vpn doctor
      --protocol` dialed only REALITY's TCP/443 handshake with a real
      throwaway sing-box client; there was no Hysteria2/QUIC equivalent
      at all, so a Hysteria2-only regression (wrong on-disk password,
      a listener that opens the UDP port but never completes a QUIC
      handshake, a sing-box UDP/QUIC defect) could pass every existing
      health check. Added `check_l5_l6_hysteria2_protocol_selftest` /
      `run_hysteria2_client_selftest` (`apps/admin/src/main.rs`),
      reported as its own "L5-6-H2" line, gated the same way as the
      REALITY self-test (`--protocol` / `--require-protocol`). Kept
      deliberately coarser than REALITY's outcome (`Pass` /
      `Inconclusive` only, never a confident "rejected" verdict) because
      this project has not catalogued sing-box's exact client-side error
      string for a Hysteria2 authentication failure — see
      `Hysteria2SelfTestOutcome`'s doc comment.
- [x] `packet_encoding: "xudp"` pinned explicitly on the REALITY
      outbound (`crates/compat-config/src/render.rs`) — **correction,
      not a fix**: sing-box's VLESS outbound already defaults this
      field to `"xudp"` ("UDP packet encoding, xudp is used by default"
      — sing-box's own docs), discovered only after an initial pass
      mistakenly treated its absence as the likely cause of the
      playback bug and shipped this exact change as if it were a fix.
      It is kept because pinning a used default explicitly is
      harmless/defensive, but it changes no runtime behavior, and the
      hypothesis it was meant to address is weakened, not confirmed.
      Separately documented (`docs/CLIENT_PROTOCOL_BEHAVIOR.md`): the
      real Hiddify iOS onboarding URL is `?format=hiddify`, which is
      byte-identical to `?format=uri` (plain share links) — this field
      lives only in `?format=singbox`'s native JSON, so it may not even
      reach a real Hiddify user who followed the documented setup flow.
      Switching the documented onboarding URL to `?format=singbox` was
      considered and rejected: `docs/ALMALINUX_DEPLOYMENT.md` already
      documents, with reasoning, that Hiddify's bundled sing-box fork
      can strict-unmarshal that format incorrectly and silently fail to
      import (fetch succeeds, neither transport ever dials) — a worse
      failure mode than the one this phase investigated.
- [!] MTU/PMTU — re-evaluated, still deliberately not automated. No new
      lever exists beyond what `docs/TELEGRAM_RESILIENCE_PLAN.md` §J
      already covers; wiring `vpn-benchmark.sh`'s existing MTU/PMTU
      probe into a routine/always-on check was considered and rejected
      because that probe measures the VPS's OWN uplink to a fixed
      target (documented in the script itself as NOT the same as a real
      client's path MTU) — surfacing it as part of a "healthy" report
      would manufacture exactly the false confidence this project
      otherwise avoids.
- [!] DNS handling — re-evaluated, still deliberately not touched.
      Added a `dns` block to the generated config was considered and
      rejected without new evidence that Hiddify's importer would even
      honor one from a fetched subscription (untested, and the
      project's own prior reasoning for omitting it still stands — see
      `docs/CLIENT_PROTOCOL_BEHAVIOR.md`). Added the previously-missing
      "DNS leak" and "Streaming (QUIC-heavy app)" columns to
      `docs/DEVICE_ACCEPTANCE_TESTS.md` instead, since a real test has
      still never been run and there was no column to record one.
- [!] IPv6 handling — re-evaluated; `check_public_hostname_and_ipv6_policy`
      (existing) already correctly distinguishes "no AAAA", "AAAA +
      egress confirmed", "AAAA + egress broken", and "AAAA + egress
      unknown" and only the broken case is fatal. No gap found worth
      changing; client-side IPv6 leak behavior remains entirely
      Hiddify's own, untestable from here.
- [~] None of this phase's changes were exercised against a real
      device, real Hiddify build, or a packet capture — see the
      accompanying diagnosis's experiment plan for what a real device
      test should check next. `cargo fmt --check`, `cargo clippy
      --workspace --all-targets -- -D warnings`, and `cargo test
      --workspace` all run clean (the same pre-existing, sandbox-only
      `apps/admin` `cli` integration-test failures noted in Phase 15
      reproduce identically without this phase's changes).

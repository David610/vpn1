# Implementation Status (v1.0 baseline)

Compact engineering handoff. Full boundary definition: `docs/SUPPORTED_PRODUCT.md`.
Release-readiness evidence (PASS/FAIL/UNVERIFIED matrix): `docs/ACCEPTANCE.md`
if present, otherwise the latest PR final-response acceptance pass.
Read `docs/SUPPORTED_PRODUCT.md` first; do not re-audit the repo from scratch.

## Supported scope (summary)

AlmaLinux 9 x86_64, <=10 users, one VPS, upstream sing-box, VLESS+REALITY
TCP/443 primary, Hysteria2 UDP/443 optional, Hiddify/sing-box-compatible
clients only, custom domain default. Native adaptive stack
(`client-daemon`, `transport-native`, `policy`, `failure-classifier`,
`network-state`, `rendezvous-client`, `telemetry`, `services/rendezvous`,
`services/relay-agent`) is a separate, out-of-scope product surface for
v1.0 — see `deploy/local/run-dev-slice.sh` for its dev-only entry point.

## Supported file/test surface (avoid full-workspace runs when only this changed)

- Installer: `install.sh` (bootstrap, checksum-verifies the release
  source archive for any pinned `VPN1_VERSION`) -> `deploy/almalinux/
  install.sh` (real implementation, builds `-p admin -p subscription`
  only).
- Uninstall: `uninstall.sh` -> `deploy/almalinux/uninstall.sh` ->
  offline entry point `bin/vpn1-uninstall` (persisted to
  `/opt/vpn1/bin/vpn1-uninstall`).
- Update/repair/render: `deploy/almalinux/update.sh`, `render-config.sh`,
  `health-check.sh`, `acceptance-test.sh`, `certbot-deploy-hook.sh`.
- Release: `.github/workflows/release.yml` publishes per-arch binary
  tarballs + a checksum-manifested `vpn1-src.tar.gz` source archive +
  combined `SHA256SUMS`, all fetched/verified by `install.sh`.
- Shared shell libs: `deploy/lib/*.sh` plus `deploy/lib/versions.env`
  (one authoritative sing-box version/checksum/arch source).
- Rust crates in the supported dependency closure: `crates/common`,
  `crates/compat-config`, `apps/admin`, `services/subscription`.
- Rust tests: `crates/compat-config/tests/*` + `src/**` unit tests,
  `apps/admin/tests/*`, `services/subscription/tests/*`.
- Shell tests: `deploy/lib/tests/*.sh` (20 files).
- Recovery: `docs/RECOVERY.md` (manual disaster-recovery procedure),
  `vpn-admin user links <id>` (out-of-band profile delivery independent
  of the subscription hostname).
- CI gates (`.github/workflows/ci.yml`): `fmt`, `clippy`, `test`
  (workspace-wide — see Known CI scope note), `audit`, `docs`, `shell`,
  `secret-logging-check`, `license-check`, `singbox-validate` (real
  pinned `sing-box` + real REALITY/Hysteria2 handshake).
- **FAST GATE**: `bash deploy/lib/fast-gate.sh` — one canonical command
  for all of the above (supported-crate scope only).
- **DESTRUCTIVE lifecycle gate**: `deploy/almalinux/lifecycle-acceptance.sh`
  — disposable AlmaLinux 9 host only, over SSH; never run against production.

## Known CI scope note (documented, not changed)

`fmt`/`clippy --workspace`/`cargo build|test --workspace` build the whole
workspace including out-of-scope native adaptive crates. `singbox-validate`
and `deploy/lib/fast-gate.sh` already scope to the supported crates only.
Splitting the workspace-wide CI jobs would touch CI trust/release
plumbing for a runner-minutes-only win; deferred.

## Checkpoint 7 (small-deployment revocation, recovery, operational hardening) — completed this session

- **New `vpn-admin user revoke <id>`**: the one clear emergency command
  for a leaked/compromised user (Checkpoint 7 §4). Disables the user,
  applies+reloads live through the existing fail-closed
  `apply_users_and_save` transaction, then verifies the result instead of
  only asserting it: reads the just-applied live config back to confirm
  the user's VLESS UUID/Hysteria2 password are structurally absent, and
  where a sing-box binary is available, actually runs a real REALITY
  handshake self-test using the revoked user's OLD VLESS UUID and
  confirms the live server rejects it (reusing the existing
  `run_reality_client_selftest` harness `doctor --protocol` already
  used). Prints exactly `VPN access revoked.` / `Existing imported
  profiles for this user are no longer authorized.` only once the reload
  actually succeeded — never when degraded/not-live. Mints no credential.
- **New `vpn-admin user reset-credentials <id> [--qr]`**: the recovery/
  reissue half (Checkpoint 7 §5). Rotates VLESS UUID + Hysteria2 password
  + subscription token together (the complete set needed to invalidate
  every previously imported profile), applies+reloads live, and only
  enables the user once that succeeded — a degraded (not-live) apply
  reverts the enabled bit back to `false` on disk rather than leaving the
  user "enabled" with credentials the running server hasn't actually
  picked up. Deployment-wide REALITY keys and the shared Hysteria2
  obfuscation password are deliberately untouched (separate, wider-blast-
  radius commands already exist for those: `init --rotate`,
  `hysteria-obfs-rotate`).
- **Existing `disable`/`rotate-token`/`rotate-vless`/`rotate-hysteria`/
  `rotate-credentials` were audited, not rewritten**: their blast-radius
  wording (added in a prior session) already correctly states what does
  and does not change per command, including `rotate-token`'s existing
  explicit "does NOT change the VLESS UUID or Hysteria2 password"
  warning — left unchanged, confirmed adequate by re-reading against
  Checkpoint 7 §6's requirement.
- **Disabled/expired-user exclusion (Checkpoint 7 §8/§9) audited, found
  already correct**: `render_singbox_server_config` already filters
  `users.iter().filter(|u| u.is_active(now_unix))` — a disabled or
  expired user is unconditionally absent from the live authorization
  config, not something `revoke`/`reset-credentials` had to newly
  implement. `services/subscription` already returns a generic 404 for a
  disabled user's token (existing tests:
  `disabled_user_token_returns_404_not_a_distinguishable_error`).
  `vpn-expiry-reconcile.timer` already runs
  `render-config --require-applied` every minute, which already fails
  the unit (visible in `systemctl status`/`doctor`) if reconciliation
  cannot actually apply. None of this needed changing — reused as-is.
- **`vpn doctor`: two new checks**. (1) Subscription HTTPS certificate
  expiry (`/etc/letsencrypt/live/<subscription_host>/fullchain.pem`) —
  previously only the Hysteria2 certificate was checked; the subscription
  reverse-proxy cert (a separate lineage, see the "Two independent TLS
  certificates" doc note) had no visibility at all. WARN <14 days, FAIL
  if expired, WARN (not FAIL) if absent (a valid state before the
  operator provisions it). (2) Disk-free-space diagnostic (`[RES]` tag,
  new — not one of the existing L1-L6 protocol layers), via a real
  `statvfs(2)` call (`disk_free_bytes()`) on the filesystem backing
  `/etc/vpn`: OK >=1GiB, WARN 256MiB-1GiB, WARN (not FAIL — vpn1 does not
  stop a running server over disk space alone) <256MiB.
- **Systemd resource hardening (Checkpoint 7 §10-12)**: added
  `MemoryHigh=75%` (a soft, proportional-to-host-size reclaim governor,
  NOT a hard `MemoryMax` — there is no single safe fixed byte value
  across the VPS sizes this project supports, see the unit files' own
  comments) to both `sing-box.service` and `vpn-subscription.service`.
  `LimitNOFILE=65535` (sing-box), `Restart=on-failure`/`RestartSec=2`
  (both), and `TasksMax` at systemd's own scaling default were all
  already present/sufficient — audited, not changed.
- **Backup/restore security (Checkpoint 7 §19/§20) audited, found already
  correct**: `cmd_backup` creates the archive mode `0600` via
  `OpenOptions::create_new` (refuses to clobber a pre-existing file or
  follow a symlink), prints an explicit "contains secrets" label, and
  never logs its contents; `cmd_restore` already validates (parses,
  rejects symlink/FIFO/device entries, checks the REALITY keypair
  cryptographically) before applying anything, through the same
  render→validate→apply→reload→rollback path as every other mutating
  command. No changes made — confirmed by the existing
  `backup_then_restore_round_trips_users`,
  `restore_never_widens_permissions_on_restored_secrets`,
  `restore_rejects_archive_containing_a_symlink`, and
  `backup_refuses_to_clobber_a_preexisting_destination` tests, which
  still pass.
- **Docs**: `docs/RECOVERY.md` gained a top-of-file incident playbook
  (scenarios A-D: one user leaked, subscription endpoint blocked, server
  broken but SSH works, server/IP lost — the last pointing at the
  existing full VPS-loss procedure) and an explicit `rotate-token` vs.
  `revoke` comparison table. `docs/ALMALINUX_DEPLOYMENT.md`'s credential-
  rotation table and "Disabling / removing a user" section were updated
  to reference `revoke`/`reset-credentials` and restate the same
  distinction; its `doctor` section now mentions the new cert/disk checks.
- **New tests**: 4 CLI tests in `apps/admin/tests/cli.rs`
  (`revoke_disables_user_states_revocation_and_verifies_structurally`,
  `revoke_does_not_claim_revocation_when_not_reloaded_live`,
  `reset_credentials_rotates_everything_needed_and_leaves_reality_and_other_users_unchanged`,
  `reset_credentials_leaves_user_disabled_when_not_reloaded_live`) and 2
  unit tests for `disk_free_bytes()` in `main.rs` — all `VERIFIED-TEST`
  (real, if faked/mocked, sing-box+systemctl; `disk_free_bytes` compared
  against real `df` output). New shell test
  `deploy/lib/tests/test-systemd-resource-limits.sh`, wired into
  `.github/workflows/ci.yml`'s `shell` job and picked up automatically by
  `deploy/lib/fast-gate.sh`'s glob.
- **What was deliberately NOT done**: no quota/traffic-accounting system,
  no per-user database, no DPI/abuse scoring, no protocol changes,
  `cargo audit`/full-workspace `cargo test`/real-VPS runs were not
  re-executed this checkpoint beyond the crates actually touched
  (`admin`) — see Verification below for exactly what ran.
- **UNVERIFIED** (no disposable AlmaLinux 9 host/real device available
  this session): a real Hiddify/sing-box client actually losing/regaining
  connectivity as a direct result of `revoke`/`reset-credentials`; the
  `MemoryHigh=75%` governor's real effect under actual memory pressure on
  a live host; the disk-space/cert-expiry doctor checks against a real
  `/etc/letsencrypt` layout.

## Checkpoint 6 (release/bootstrap/documentation consistency, first-release readiness) — completed this session

Audit found the release contract itself (installer/updater/CI agreement on
source, binaries, sing-box pin, single-version resolution) already
internally consistent and documented honestly — Checkpoints 1-5 and the
prior "Checkpoint 9" (see "Completed checkpoints" below) had already fixed
the real defects there (unverified bootstrap source, mixed-release
binaries, no-release stable-channel fallback). Two real, previously
unverified defects were found and fixed in `.github/workflows/release.yml`
itself, which had never been exercised by a real tag push:

- **`workflow_dispatch` could build/publish a mismatched commit**: the
  `build` job's `actions/checkout@v4` has no explicit `ref:`, so it checks
  out `github.sha` — for `workflow_dispatch` that is whichever ref the
  operator selected in the "Use workflow from" dropdown, **not**
  necessarily the tag named in the `tag` input. A release triggered this
  way could silently build current-branch HEAD while labeling/publishing
  it as an unrelated version tag (Checkpoint 6 §8's exact failure mode).
  Fixed with a new `validate-tag` job that fails closed unless
  `github.ref_type == 'tag' && github.ref_name == inputs.tag`.
- **Release publication was never gated by CI**: `release.yml` built and
  published from a green compile alone — a red `fmt`/`clippy`/`test`/
  `shellcheck`/`cargo audit`/`singbox-validate`/real-interop run at the
  tagged commit would not have blocked publication (Checkpoint 6 §9's
  requirement). Fixed by adding `workflow_call:` to `ci.yml`'s triggers
  (additive; does not change its existing `push`/`pull_request` behavior)
  and a new `gate` job in `release.yml` that calls `ci.yml` as a reusable
  workflow; `build` now `needs: [gate]`. This reuses the canonical job
  graph instead of duplicating any check.
- **A release candidate could be silently auto-installed as "latest
  stable"**: `install.sh`'s stable channel resolves `/releases/latest`,
  which GitHub already excludes prereleases from — but `release.yml`
  never set `prerelease:` on the GitHub Release it publishes. Fixed:
  `prerelease: ${{ contains(tag, '-') }}` marks any SemVer-prerelease tag
  (e.g. `v1.0.0-rc.1`) as a GitHub prerelease, so only an explicit
  `--version v1.0.0-rc.1` pin resolves it — a normal stable install can
  never land on an RC by surprise (Checkpoint 6 §19).

All three are `VERIFIED-CODE` (read/YAML-lint verified; the actual
GitHub Actions execution of `release.yml` remains `UNVERIFIED` — this
repository has never pushed a real tag). Static regression coverage
for all three was added to
`deploy/lib/tests/test-release-archive-contract.sh` — `VERIFIED-TEST`.

`docs/PRODUCTION_ACCEPTANCE_REPORT.md` had one stale claim ("falls back
to `main` with an explicit warning if no release has been tagged yet")
left over from before the no-release-fallback behavior was fixed (prior
session, see "Completed checkpoints" #9 below) — corrected to match the
current fail-closed bootstrap. Every other audited doc (README,
`docs/SUPPORTED_PRODUCT.md`, `docs/ALMALINUX_DEPLOYMENT.md`, this file)
already stated the current behavior consistently; no other drift found.
`docs/FINAL_PRODUCTION_AUDIT.md`'s similar-sounding old claim was left
alone — it is explicitly commit-pinned/dated as a historical audit
document, not live operator documentation.

**First release version**: no tag has ever been pushed. Given the
destructive AlmaLinux lifecycle gate and all real-device acceptance
(`docs/DEVICE_ACCEPTANCE_TESTS.md`) remain `UNVERIFIED` (no disposable
host/device available in any session so far), a final `v1.0.0` tag would
overclaim. The evidence supports, at most, a **release candidate**
(e.g. `v1.0.0-rc.1`) — an immutable artifact to actually run the
lifecycle/device acceptance passes against, now that `release.yml` is
gated and tag/commit-correct. No tag was pushed this session: publication
requires explicit authorization per this checkpoint's own instructions,
which was not given.

**Working tree**: clean before and after this checkpoint's edits; all
changes committed to `claude/vpn1-release-readiness-c538l9`. See git log
for the exact commit.

## Checkpoint 5 (repair/harden the destructive lifecycle acceptance harness) — completed this session

`deploy/almalinux/lifecycle-acceptance.sh` had six real defects making a
PASS from it untrustworthy; all six are fixed, none by wording changes:

- **Failure-injection env var reached `curl`, not the installer**: stage
  10 used `sudo VPN1_LIFECYCLE_GATE_ABORT_AFTER=... curl | bash` — `sudo`
  scoped the var to `curl`'s own exec, never to `bash` on the other side
  of the pipe. Fixed by moving the var to the `bash` side (matching the
  pattern already correct in every other stage), and added an assertion
  that partial `/opt/vpn1`/`/etc/vpn` state exists after the "abort"
  (proof the hook fired mid-install, not that curl/SSH merely failed).
- **"Offline uninstall" downloaded code from GitHub**: every uninstall
  call in the harness used `curl .../uninstall.sh | bash`. Now uses
  `sudo /opt/vpn1/bin/vpn1-uninstall --yes` exclusively (stages 10 and
  11), with a best-effort `iptables REJECT` to `github.com`/
  `raw.githubusercontent.com` around the offline-uninstall call as
  additional proof of no outbound dependency.
- **SSH testing assumed port 22**: added `--ssh-port`, threaded through
  to `install.sh --ssh-port`, used in `SSH_OPTS`, and the baseline check
  now greps the configured port instead of a hardcoded `:22`.
- **Update never proved the version changed**: the update stage now
  captures `install-state.json` before/after and `fail_required`s if
  they're identical — a same-checkout rebuild can no longer be reported
  as a real update.
- **Cleanup was checked only superficially**: uninstall residue is now
  compared against a sanitized pre-install host baseline (services,
  units, listeners, accounts, nginx/certbot-hook presence, locks) instead
  of two path checks.
- **Command failures were swallowed / client-vs-host properties
  conflated**: unguarded `ssh_run` command substitutions that could abort
  the whole script under `set -e` are now `|| true`-guarded so one probe
  failing doesn't hide the rest of the report; the existing client/device
  exclusion (Hiddify/iOS/Android/MagicOS — Checkpoint 8) is preserved
  and now explicitly reported as `UNVERIFIED` rather than just a comment.
- **Reboot only checked `health-check.sh`**: now independently verifies
  sshd, sing-box, vpn-subscription, nginx, a vpn1 timer, the 443
  listener, `install-state.json`, and `vpn-admin doctor --protocol`.

New: a `VPN1_LIFECYCLE_GATE_ABORT_AFTER` hook was added to `update.sh`
(mirroring `install.sh`'s existing one), fired after SWITCH/migration
begins, enabling a real failed-update-rollback stage (7b) that asserts
sshd/sing-box/vpn-subscription/protocol/`install-state.json` are restored
to their pre-update values. `PASS`/`FAIL`/`UNVERIFIED` are now tracked as
three distinct outcomes; the exit summary prints exactly `LIFECYCLE GATE:
PASS` or `LIFECYCLE GATE: FAIL`, and a non-zero UNVERIFIED count is
called out so a PASS is never read as full v1.0 release readiness.

12 new fixture/regression tests were added
(`deploy/lib/tests/test-lifecycle-acceptance-harness.sh`, run against the
real script with a mocked `ssh`/`sleep` recording every invocation — not
comment-grepping) proving: destructive opt-in is required; `--host` is
required; localhost/production-host targets are refused; a non-numeric
`--ssh-port` is rejected; SSH is invoked with the configured port, not a
hardcoded 22, and `install.sh` receives `--ssh-port`; the abort-hook env
var reaches the `bash` side of the pipe (regression guard against the
fixed bug reappearing); offline uninstall uses the local binary, not
`curl | bash`; a no-op update is detected and failed; a required-stage
failure can never produce `LIFECYCLE GATE: PASS`; UNVERIFIED items are
reported distinctly from PASS/FAIL. A second fixture test
(`deploy/lib/tests/test-update-release-fixture-verification.sh`) extracts
`update.sh`'s real checksum-verification lines (not a reimplementation)
and exercises them against two distinct local fixture releases with
immutable version IDs, separate content, and real sha256 checksums,
proving the verification contract is fail-closed against tampering and
malformed manifests — marked `VERIFIED-TEST`; a real GitHub release A->B
transition remains `UNVERIFIED` until a first tagged release exists.

**Real execution status**: the harness itself was repaired and its logic
proven with fixture tests in this sandbox (no disposable AlmaLinux 9 host
available here, and no destructive opt-in context established, so the
real destructive lifecycle was correctly NOT run automatically per this
checkpoint's own instructions). Actually running it against a real
disposable host remains `UNVERIFIED`, same as before this checkpoint —
this checkpoint fixed the harness's trustworthiness, not the fact that it
still needs to be run for real.

## Checkpoint 4 (strict fresh-install success semantics) — completed this session

- **Subscription HTTPS is now mandatory, not best-effort**:
  `require_subscription_tls()` used to warn and set
  `SUBSCRIPTION_TLS_READY=0` on certificate failure, letting
  `configure_nginx()` silently skip the vhost while the installer still
  finished and printed the normal success banner. It now `exit 1`s with
  the same actionable diagnosis `require_hysteria_tls()` already gave —
  there is no supported advanced/manual opt-out in this architecture,
  so none was invented.
- **Initial user creation is now mandatory on a fresh/pending-onboarding
  install, and correctly repair-safe**: `ensure_first_user()` used to
  `warn` and continue on creation failure, and auto-created a default
  user whenever the store was empty regardless of fresh vs. repair. It
  now: (a) `die`s on creation failure for a fresh/not-yet-accepted
  install (a fresh install must produce at least one usable onboarding
  credential); (b) NEVER auto-creates or rotates anything on a repair of
  an install whose manifest already reached `"accepted"`, even with zero
  users (operator's user state is theirs); (c) on a pending-install
  retry that already has a user from an earlier failed attempt, mints
  ONLY a fresh subscription token via the existing `rotate-token` path
  (raw tokens are never persisted, so a lost one needs a fresh mint) —
  VLESS/Hysteria2 credentials are never touched. Distinguishing these
  three cases needed a new `PRIOR_ACCEPTANCE_STATE` captured in
  `preflight_stage`, before this run's own `write_install_state_manifest`
  calls overwrite the prior value.
- **New end-to-end subscription verification through nginx/TLS**:
  `verify_subscription_through_nginx()` fetches the actual
  `/sub/<token>?format=hiddify` URL for the onboarding user via
  `curl --resolve HOST:PORT:127.0.0.1` against the real configured
  hostname (real TLS hostname/expiry verification, never `-k`) and
  cross-checks the response against the CURRENT on-disk REALITY public
  key/short_id (reusing existing state files rather than a second
  profile parser) — proving the client-facing path (user state ->
  vpn-subscription -> nginx HTTPS -> renderer -> returned profile) is
  live and current, not just that the loopback backend's `/healthz`
  responds. Runs for a fresh/pending-onboarding install; a repair of an
  already-accepted install does not re-mint a token to re-run it (that
  duty is covered by `doctor --protocol`'s existing L4 live-process
  coherence check on every run instead).
- **`accepted` is written only after every server-side gate**:
  `print_status()` now hard-gates on `SUBSCRIPTION_HTTPS_OK`, `NGINX_OK`,
  and (for a non-repair run) `SUBSCRIPTION_FETCH_OK` — in addition to the
  data-plane/backend gates that already existed — strictly BEFORE
  `write_install_state_manifest "accepted"` runs (previously the write
  happened first, then the gates were checked).
- **Success banner now separates SERVER-SIDE VERIFIED from STILL
  UNVERIFIED** (real device/network/provider-firewall properties) per
  the checkpoint's evidence-boundary requirement — never claims
  "production-ready" or similar from a local result.
- Note: `deploy/almalinux/health-check.sh` already did a real
  `curl --resolve` HTTPS request against the subscription vhost with the
  real hostname (no `-k`) and `vpn-admin doctor`'s L4 checks already
  included a live-process state-fingerprint comparison that catches a
  stale `vpn-subscription` process — both pre-existing, correct, and
  left unchanged; this checkpoint's new work is specifically the
  profile-CONTENT verification through nginx and the mandatory-vs-
  best-effort gating described above.
- Hysteria2 has no "disabled" representation anywhere in the current
  codebase (always rendered/required) — section 12's "explicitly
  disabled must not be reported as failure" case does not apply; no such
  mode was invented, per the checkpoint's own instruction not to add one
  that doesn't already exist.
- New test file `deploy/lib/tests/test-fresh-install-acceptance.sh`:
  fail-closed TLS requirement, fresh/pending/repair user-management
  branching (including the rotate-token-only recovery path) exercised
  against a mocked `vpn` binary, `extract_subscription_url()` parsing
  both `user create`'s and `user rotate-token`'s real (differently
  worded) output, and gate-ordering (accepted-after-checks) checks.
- **UNVERIFIED** (no disposable AlmaLinux 9 host available this
  session): the new mandatory subscription-HTTPS/user/nginx-fetch gates
  have not been exercised against a real cert/nginx/sing-box stack —
  only via mocked functional tests and static ordering checks.

## Checkpoint 3 (transactional release-to-release updater) — completed this session

- **Old model (replaced)**: `deploy/almalinux/update.sh` rebuilt
  whatever source happened to be checked out at `/opt/vpn1` via
  `cargo build`, unconditionally required Cargo/Rust, never resolved or
  fetched a target release, never touched the sing-box binary, and
  never wrote the install-state manifest (so `vpn1_version` went stale
  after every update).
- **New model**: `deploy/almalinux/update.sh --version vX.Y.Z` (or
  `--latest` / `--repair`) is a real STAGE -> PREPARE -> SWITCH ->
  ACTIVATE -> VERIFY -> COMMIT transaction. Production path requires no
  Cargo/Rust: it downloads and SHA-256-verifies the target release's
  source archive (reusing `install.sh`'s bootstrap trust model) and
  prebuilt binaries (reusing `fetch_release_binaries()`'s asset/
  checksum contract) into a staging directory under `/opt`, and fails
  closed with "Nothing live has been changed" if either is missing or
  fails verification — never a silent fallback to a source build.
  sing-box is staged/verified and swapped too, only when the target
  release pins a different version. `--dev-rebuild` (or
  `VPN1_CHANNEL=dev`) is the explicit, structurally separate escape
  hatch that keeps the old Cargo-rebuild-from-local-source behavior for
  development/testing.
- Source tree swap is an atomic same-filesystem rename
  (`/opt/vpn1` <-> a staged/previous directory under `/opt`), not an
  in-place overwrite — the previous release stays fully intact until
  SWITCH, and rollback renames it straight back.
- `install-state.json` is only rewritten at COMMIT, strictly after
  `doctor --protocol --require-protocol` passes — a failed update never
  updates the authoritative version record.
- Rollback restores binaries, systemd units, helper scripts, the
  sing-box binary (if changed), and the previous `/opt/vpn1` source
  tree, then re-renders (never rewinds) `users.json`/REALITY material
  with the restored tooling, and reports exactly one of `UPDATE FAILED —
  PREVIOUS RELEASE RESTORED AND VERIFIED` or `UPDATE FAILED — ROLLBACK
  ALSO FAILED` (never a bare "update failed").
- Interrupted-transaction detection: a `TRANSACTION_MARKER` written in
  PREPARE (before the first live mutation) makes a subsequent
  invocation refuse with precise recovery instructions instead of
  starting a new update on top of unknown state; a stale
  `/opt/.vpn1-update-staging.*`/`/opt/.vpn1-prev-*` directory left by a
  killed prior run is detected the same way.
- Same-version requests exit cleanly ("Already at vX.Y.Z...") with zero
  mutation unless `--repair` is given; `--repair` re-fetches and
  re-verifies the *currently recorded* release's own material rather
  than resolving a different version.
- Transaction-only backups/staging directories are removed on
  successful commit (never a permanent backup product) and reused
  (never blindly overwritten) if a prior interrupted transaction is
  detected first.
- `deploy/almalinux/lifecycle-acceptance.sh`'s `--update-to-ref` path
  fixed to actually invoke `update.sh --dev-rebuild` (the old
  `VPN1_REF=...` env var it passed was silently ignored by update.sh —
  a genuine tagged-release A->B lifecycle run remains a separate,
  UNVERIFIED gap pending a first real release, see below).
- New test file `deploy/lib/tests/test-update-transactional.sh`;
  extended `test-update-conditional-restart.sh` and
  `test-state-schema-migration.sh` for the new two-code-path
  (production/dev-rebuild) structure. All static/source-inspection —
  update.sh itself needs root/systemd/a real deployment/network access,
  the same constraint the pre-existing update.sh tests already had.
- **UNVERIFIED** (no disposable AlmaLinux 9 host, no tagged release
  published this session): a real release A -> B production update has
  never been executed end-to-end; every failure-injection scenario
  listed in the checkpoint spec is verified only by static/structural
  inspection of the transaction ordering, not by actually killing the
  process mid-transaction against a live host.

## Checkpoint 1 (SSH/firewall/rollback safety) — completed this session

- **SSH/firewall ordering fixed**: firewalld used to be activated
  (`systemctl enable --now firewalld`) in `packages_stage` with only its
  distro-default rules (which cover the `ssh` **service**, i.e. port 22
  only), 12 stages before `firewall_stage` added a custom sshd port —
  an active window where a custom-port SSH session/new connections
  could be locked out. Fixed: `activate_firewalld_ssh_safe()`
  (`deploy/almalinux/install.sh`) starts firewalld and adds the
  confirmed SSH port's allow rule(s) as one atomic sequence, and never
  touches an already-active firewalld's existing configuration.
  `deploy/almalinux/firewall.sh` (also independently invocable) applies
  the same ordering when run standalone.
- **SSH port detection now fails closed**: `preflight_detect_ssh_port()`
  (`deploy/lib/preflight.sh`) no longer falls back to 22 when `sshd -T`/
  `sshd_config`/live-listener detection is all inconclusive — it returns
  1 with nothing printed. New canonical `preflight_resolve_ssh_port()`
  is the single implementation used by `install.sh`, `firewall.sh`, and
  `firewall-ufw.sh`; it accepts an explicit `VPN1_SSH_PORT` override
  (`install.sh --ssh-port PORT` / `VPN1_SSH_PORT=`), validated via
  `preflight_validate_port`. Inconclusive detection with no override now
  `die`s before any firewall mutation, naming the fix.
- **Rollback ownership tracking now starts before the first mutation**:
  `ownership_mark INSTALL_ATTEMPTED` / `ownership_set_baseline_once
  OPT_VPN1_PRE_EXISTED` used to run AFTER `persist_source_tree` (creates
  `/opt/vpn1`) and `install_idn_support` (installs `libidn2` on RHEL) —
  a failure inside either mutation looked like "nothing mutated yet" to
  `on_fatal_error`'s rollback trap and left it stranded. Both now run
  before those two calls in `preflight_stage`.
- IDN normalization (`чёрт.com` -> `xn--p1aen4b.com`) re-verified
  end-to-end with a real `idn2` binary installed in the dev sandbox
  (`deploy/lib/tests/test-idn-punycode.sh`) — `install_idn_support()`
  (installs `libidn2` for the RHEL family) already ran before
  `resolve_host_config()` in `preflight_stage`; added static regression
  coverage for that ordering plus the rhel-family package name.
- New/extended tests (`deploy/lib/tests/test-installer-hardening.sh`,
  `test-preflight-ordering.sh`, `test-idn-punycode.sh`): SSH detection
  on port 22/2222 (mocked `sshd -T`), fixture `sshd_config`, fail-closed
  with no override, explicit-override accept/reject, listener-fallback
  code path (structural — real match needs a real `sshd` process,
  UNVERIFIED), firewall.sh/firewall-ufw.sh fail-closed + canonical-call
  checks, `activate_firewalld_ssh_safe()` ordering/preservation checks,
  ownership-mark-before-first-mutation ordering.
- **UNVERIFIED** (no disposable AlmaLinux 9 host available this
  session): real custom-SSH-port lockout avoidance on a live host;
  `deploy/almalinux/lifecycle-acceptance.sh` was not run.

## Checkpoint 2 (ownership-safe complete uninstall) — completed this session

- **`/etc/vpn` is no longer blindly `rm -rf`'d**: install.sh now records
  `ETC_VPN_PRE_EXISTED` before ever creating `/etc/vpn` (stage 8).
  uninstall.sh's cleanup is now ownership-gated: `0` (vpn1 created the
  whole tree) -> full removal; `1` (pre-existing) or unset/ambiguous
  (pre-checkpoint-2 install, no record) -> remove only vpn1's own
  entries (`deployment.toml`, `compat/`), preserving everything else —
  defaulting to preservation whenever ownership can't be proven.
- **Fixed-name system resources (systemd units, certbot renewal hook,
  nginx vhost) are now ownership-tracked**: new
  `install_fixed_path_with_ownership()` helper backs up (once) whatever
  already occupied a fixed path before vpn1 wrote there, and records
  whether it pre-existed. uninstall.sh's new `restore_or_remove_fixed_path()`
  restores the exact backup when something pre-existed, removes the
  file when vpn1 created it, and leaves it untouched (never guesses)
  when no ownership record exists at all.
- **Fixed a real ordering bug**: `OPT_VPN1_PRE_EXISTED` (and the new
  fixed-path `PRE_EXISTED` facts) used to be read via `ownership_get`
  *after* `$STATE_DIR_ROOT` (`/var/lib/vpn1`, where the manifest itself
  lives) had already been `rm -rf`'d — silently returning the
  "not pre-existing" default every time, so `/opt/vpn1` was ALWAYS
  treated as vpn1-created (even on the rare host where it genuinely
  pre-existed) and a correctly-restored pre-existing fixed path could
  misreport as residue. Fixed by caching every such fact before that
  removal.
- **Truthful residue verification**: uninstall.sh now collects
  `CRITICAL_RESIDUE` (active vpn1 services, running processes, live
  secrets/credentials, vpn1 binaries, vpn1-owned firewall exposure
  still open after removal was attempted, a vpn1-created `/opt/vpn1`
  still present) separately from `NONCRITICAL_RESIDUE` (a package the
  package manager refused to remove, a userdel/groupdel failure, an
  ambiguous pre-existing fixed path left alone). Cleanup never aborts
  on the first non-fatal failure (this script has no `-e`); the final
  banner prints `UNINSTALL COMPLETE` only when `CRITICAL_RESIDUE` is
  empty, `UNINSTALL INCOMPLETE` (nonzero exit) otherwise. Two
  previously-fatal `die`s on a corrupted firewall-ownership record are
  now `warn` + critical-residue entries so the rest of cleanup still runs.
- **Package names validated before the package manager**: `PKGS_INSTALLED_BY_VPN1`
  entries are filtered through `is_safe_pkg_name()` before `dnf remove`/
  `apt-get remove`; anything not shaped like a real package name is
  skipped and reported as non-critical residue instead of being passed
  through.
- **Legacy uninstall compatibility fixed**: the online bootstrap
  (`uninstall.sh`) previously forwarded `--yes` unconditionally to a
  local `/opt/vpn1/deploy/almalinux/uninstall.sh`. The actual
  pre-`07f8b72` layout (real historical commit `d8a4c87`, verified via
  `git show`) never had a `--yes` flag or any confirmation prompt at
  all — it understood only `--purge-state`/`--purge-firewall` and
  rejected any other flag outright, exactly the failure this was filed
  about. New `run_legacy_uninstaller()` detects which interface the
  local copy actually supports (via `grep`) and translates: drops the
  meaningless `--yes` and adds `--purge-state --purge-firewall` for
  that historical layout; forwards unchanged for the current one.
- **Version-aware damaged-`/opt/vpn1` recovery**: when no local copy is
  usable at all, the bootstrap now reads `/var/lib/vpn1/install-state.json`
  for the exact installed `vpn1_repo`/`vpn1_version` and fetches that
  immutable tag (`refs/tags/$VPN1_REF`) instead of the mutable `main`
  branch, unless the operator passed an explicit `--ref` or no pinned
  version was ever recorded (dev/unreleased install).
- New test file `deploy/lib/tests/test-uninstall-ownership-checkpoint2.sh`:
  `/etc/vpn` preservation with a sentinel file, fixed-path
  restore/remove/ambiguous-preserve, package-name validation
  (accept/reject), the `OPT_VPN1_PRE_EXISTED` ordering fix, and legacy
  flag translation exercised against the **real** historical script
  from `git show d8a4c87:deploy/almalinux/uninstall.sh` (not an
  invented approximation).
- **UNVERIFIED** (no disposable AlmaLinux 9 host available this
  session): the canonical offline command
  (`sudo /opt/vpn1/bin/vpn1-uninstall --yes`) has not been exercised
  against a real install with real systemd/firewalld/SELinux/dnf state,
  nor with outbound networking disabled to prove offline-completeness
  for real.

## Completed checkpoints (one line each — see git log for detail)

1. v1.0 boundary + supported code surface documented (`docs/SUPPORTED_PRODUCT.md`).
2. Canonical FAST GATE + DESTRUCTIVE lifecycle gate (SSH-only, requires `--i-understand-this-is-destructive`).
3. Reproducible installs: `deploy/lib/versions.env` single-sourced; stable channel refuses unpinned branch fallback.
4. Persistent state versioning/migration: `deployment.toml`/`users.json` schema versions + `vpn-admin config validate|migrate`.
5. Installer hardening audit: enforced custom-domain default (`--allow-ip-hostname` required to opt out non-interactively), SSH-port fixture seam, REALITY-init idempotency test.
6. Uninstall hardening: offline `bin/vpn1-uninstall` entry point, confirmation-gated, root-controlled-path + manifest re-validation checks, ownership mode-check bug fixed.
7. Client protocol behavior audit: real sing-box interop suite run (9/9 pass); `docs/CLIENT_PROTOCOL_BEHAVIOR.md` written; subscription-has-no-dns/inbounds and dual-stack-bind regression tests added.
8. Censorship-resilience/recovery honesty audit: added out-of-band `vpn-admin user links`, `docs/RECOVERY.md`, structural Hysteria2-unavailable render test, honest single-VPS/IP-blocking limitations documented.
9. PR merge-readiness pass: fixed the production bootstrap's unverified-source-download gap (`install.sh` now SHA-256-verifies a `release.yml`-published `vpn1-src.tar.gz` for any pinned version), corrected README domain-default and REALITY-decoy claims to match actual installer behavior, shrank this file.

## Blockers

- `cargo test -p admin --test cli` has 5 failures **only when run as
  root** (this sandbox is root): `apply_restored_file_policy()` does a
  real `getgrnam("vpn-subscription")` lookup when `geteuid()==0`, and
  that group doesn't exist outside a real installed host. Pre-existing;
  does not fail in CI (non-root runner). `deploy/lib/fast-gate.sh`
  therefore reports FAIL when run as root; PASS expected in CI/any
  non-root dev environment.

## Important UNVERIFIED items (require real VPS/network/client testing)

- Public reachability, provider firewall correctness.
- Real VLESS+REALITY / Hysteria2 connectivity from an actual Hiddify
  client on a real device.
- Full clean-VPS install -> update -> migrate -> rollback -> uninstall
  lifecycle, including SSH-preservation and non-default-SSH-port
  survival, on real AlmaLinux 9 (no disposable host available this
  session — `lifecycle-acceptance.sh` was repaired and its own logic
  fixture-tested this checkpoint, but not run against a real host; see
  Checkpoint 5).
- Certificate renewal (`certbot renew --dry-run`) on a real host — the
  harness now attempts it and reports the real result or `UNVERIFIED` if
  provider conditions prevent it, but this has not actually run.
- A real tagged release has never been published — the checksum-verified
  bootstrap path (checkpoint 9) is fixture/unit-tested, not exercised
  against a real GitHub Release.
- DNS leak prevention, IPv6 correctness, kill-switch behavior,
  censorship resistance against a real adversary in a real country.

## Canonical verification commands (supported product)

```bash
# FAST GATE — one command, run after every change (see Blockers re: root)
bash deploy/lib/fast-gate.sh

# DESTRUCTIVE lifecycle gate — DISPOSABLE ALMALINUX 9 HOST ONLY, over SSH.
# Prerequisites: passwordless-sudo SSH access to a throwaway AlmaLinux 9
# x86_64 VM/VPS you can afford to wipe and reboot; it must NOT be your
# configured production host (the script refuses that, and refuses
# localhost/no --host, by construction). Optional --ssh-port exercises a
# non-default SSH port end-to-end instead of assuming 22; optional
# --update-to-ref exercises update.sh's --dev-rebuild transactional path
# (a real tagged-release A->B transition remains UNVERIFIED until a first
# GitHub release exists — see Important UNVERIFIED items below).
./deploy/almalinux/lifecycle-acceptance.sh \
  --host root@DISPOSABLE-HOST --i-understand-this-is-destructive \
  [--ssh-port 2222] [--update-to-ref BRANCH]

# offline uninstall — no network access needed
sudo /opt/vpn1/bin/vpn1-uninstall --yes

# production update — transactional, checksum-verified, no Cargo/Rust required
sudo /opt/vpn1/deploy/almalinux/update.sh --version vX.Y.Z
sudo /opt/vpn1/deploy/almalinux/update.sh --latest      # resolve latest stable tag
sudo /opt/vpn1/deploy/almalinux/update.sh --repair       # reconcile the current release, no version change

# out-of-band recovery — no subscription domain needed
vpn-admin user links <user_id>
```

See `docs/RECOVERY.md` for the full disaster-recovery procedure.

## Next logical checkpoint

Push the first real `vX.Y.Z` release tag (exercises `release.yml` +
the new checksum-verified bootstrap path for the first time for real),
then run `deploy/almalinux/lifecycle-acceptance.sh` against a real
disposable AlmaLinux 9 host AND, on that same host, work through
`docs/DEVICE_ACCEPTANCE_TESTS.md` with at least one real Hiddify device.
This remains the single highest-value gap across every checkpoint:
SSH preservation, rollback, idempotency, ACME restoration, config
migration, offline uninstall, release-integrity verification, AND real
client connectivity are all code-read/unit/fixture verified only, never
exercised end-to-end. Until then, pick one concrete supported-product
defect/gap and fix it with minimum churn, running
`deploy/lib/fast-gate.sh` after every change.

# ALMALINUX_DEPLOYMENT.md

Production runbook for the Hiddify/VLESS-REALITY/Hysteria2 compatibility
stack. Despite the filename/directory name (kept for backwards
compatibility with existing links), this deployment path now supports
the RHEL family (AlmaLinux 9, Rocky Linux 9, RHEL 9, Amazon Linux 2023)
and the Debian family (Ubuntu 22.04/24.04, Debian 12/13) — see
`deploy/lib/os.sh`.

### Support matrix — three tiers, not two

`OS_SUPPORT` (see `deploy/lib/os.sh`) has three distinct values. Do not
read "ci-tested" as a synonym for "tested" — it is a materially weaker
claim, and the installer's own preflight warning says so at runtime too.

| OS | Family | `OS_SUPPORT` | Basis |
|---|---|---|---|
| AlmaLinux 9 | RHEL | `tested` | exercised as the primary development/CI target |
| Rocky Linux 9 | RHEL | `tested` | same install path as AlmaLinux 9 (dnf/firewalld) |
| RHEL 9 | RHEL | `tested` | same install path as AlmaLinux 9 |
| Amazon Linux 2023 | RHEL | `ci-tested` | automated unit/fixture coverage only, no live-host run — see below |
| Ubuntu 22.04 / 24.04 | Debian | `tested` | exercised as a development/CI target |
| Debian 12 / 13 | Debian | `tested` | same install path as Ubuntu (apt/ufw) |
| anything else | — | `untested` | installer warns and continues; no guarantee |

- **`tested`** — genuinely exercised as a development/CI target (AlmaLinux
  9, Rocky 9, RHEL 9, Ubuntu 22.04/24.04, Debian 12/13).
- **`ci-tested`** — Amazon Linux 2023 only. Covered by automated
  static/unit tests (`deploy/lib/tests/test-amazon-linux-2023.sh`), which
  `source` the real `deploy/lib/os.sh` and exercise the real `detect_os()`
  against a fixture `/etc/os-release` (`ID=amzn`/`ID_LIKE=fedora`
  correctly mapping to the RHEL family), plus the real
  `install_dependencies_rhel()`'s `curl-minimal`/`curl` package-conflict
  handling — it has **not** been verified end to end against a real
  Amazon Linux 2023 EC2 instance (no such host was available while this
  support was added). In particular, whether `firewalld` is actually
  installable from AL2023's default `dnf` repos on a stock EC2 image has
  not been confirmed live; if it isn't, `packages_stage` will fail loudly
  at `dnf install` rather than silently degrading — check
  `journalctl`/the installer's own error output if that happens, and
  please report back so this matrix can be corrected (and, once a real
  run succeeds, so this can be upgraded to `tested`).
- **`untested`** — everything else; installer warns and continues, no
  automated coverage at all.

Every
command below is copy-pasteable. This deploys the compatibility
(sing-box) data plane only — the native `direct-tls`/`noise-quic` stack
stays on `deploy/local/` (see `docs/COMPATIBILITY_IMPLEMENTATION_PLAN.md`
§14).

**Most installs should use the one-command bootstrap** described in the
top-level [`README.md`](../README.md#quick-install):

```bash
curl -fsSL https://raw.githubusercontent.com/David610/vpn1/main/install.sh \
  | sudo REALITY_HANDSHAKE_SERVER=www.google.com bash
```

That command resolves the latest tagged release, downloads the source
archive `release.yml` published for that exact tag, verifies it against
that release's `SHA256SUMS` manifest (refusing to extract/run anything
if the asset, manifest, or checksum don't match — see
`download_verified_source_release()` in the top-level `install.sh`),
auto-detects your public IP, issues a real (non-self-signed) TLS
certificate automatically via [sslip.io](https://sslip.io) + certbot,
and runs everything below for you. `fetch_release_binaries()` in
`deploy/almalinux/install.sh` prefers a prebuilt, checksum-verified
release binary for your exact version/architecture and only falls back
to building from that same exact-tag source (via `rustup` + `cargo
build`) when no matching release asset exists — source and binaries are
always the same immutable, checksum-verified version either way. The
bootstrap (`install.sh`) resolves this version BEFORE downloading
anything: a production (default/stable-channel) install that finds no
tagged release refuses to run rather than silently falling back to
mutable, unverified branch source.

**Trust boundary, stated exactly**: the very first `curl install.sh |
sudo bash` fetch is plain HTTPS from `raw.githubusercontent.com` with no
extra signature — that step's trust is "HTTPS + GitHub account
security," same as any curl-pipe-to-shell installer, and this doc does
not claim more than that. What the checksum verification above adds is
SHA-256 integrity checking of the release payload once a tag is
resolved: it catches a corrupted or tampered-in-transit download, not a
compromise of the GitHub release itself (someone who can edit/replace a
release could republish a matching archive+checksum pair together). No
code-signing infrastructure is implemented for v1.0.

**As of this writing, no `vX.Y.Z` tag has ever been pushed to this repo,
so the plain `curl | sudo bash` command above currently refuses to run**
with an error explaining the two options: pin `--version vX.Y.Z` once a
release exists, or explicitly opt into unpinned branch-source
development mode with `VPN1_CHANNEL=dev` (never for a real deployment —
see the top-level README's Quickstart for the exact command). Publishing
the first tagged release is a manual, human, one-time operational action
(`git tag vX.Y.Z && git push --tags`, or an equivalent GitHub release) —
no code change in this repository can complete that step by itself, and
none has been attempted here. `release.yml`'s packaging/checksum logic
has been reviewed and is exercised by
`deploy/lib/tests/test-release-archive-contract.sh`, but "the fast path
is wired up correctly" and "the fast path has actually been used by a
real install" are two different claims; only the first is true today.
The rest of this document describes what that one-liner does internally,
and how to run every stage manually if you want full control (your own
domain, hand-provisioned certs, etc).
`REALITY_HANDSHAKE_SERVER` has no universal safe default: the example is
only a starting selection, and installation succeeds only after the real
sing-box protocol acceptance test returns application data. Do not use
`www.microsoft.com` with the pinned sing-box build; its current TLS flight
exceeds the underlying REALITY implementation's record budget.
`--reality-handshake-server`/`REALITY_HANDSHAKE_SERVER` is validated in
**preflight**, before any package/certificate/user/directory is touched
— a missing or invalid value fails immediately with zero host mutation
(interactive installs are prompted for it instead of failing, unless
`--non-interactive` is also passed). `PUBLIC_HOST`/`--domain` is
validated at the same time, including a check that its DNS actually
resolves to this VPS before any certificate is requested for it —
domains that are stale, still point elsewhere, or sit behind a
proxy/CDN are rejected with a precise error before certbot/firewall
changes happen, since REALITY/Hysteria2 need to terminate the raw
connection on this host directly.

## Prerequisites (manual path)

- A fresh, supported VPS with a public IPv4 (IPv6 optional), root SSH
  access.
- Optionally, a domain name pointed at the VPS (an A record for both
  `vpn.example.com` and, if different, `sub.example.com`) if you don't
  want the automatic `sslip.io`-based hostname. REALITY's disguise
  handshake target does not need a domain at all — VLESS+REALITY works
  identically either way.
- A Rust toolchain installed (e.g. via `rustup`) if you want to force a
  from-source build instead of the installer's prebuilt-release path.
- A TLS certificate for `sub.example.com` (Let's Encrypt via a reverse
  proxy — see "Subscription HTTPS" below), unless you let the installer
  provision one automatically. REALITY itself does **not** need a
  certificate for `vpn.example.com` (it dials a real site's TLS
  handshake as a disguise; sing-box owns that logic).

## Two independent TLS certificates — do not confuse them

This deployment uses **two separate TLS certificates for two separate
purposes**. They are not interchangeable, and this doc previously
described them loosely enough to invite confusion — being explicit here
on purpose:

| | Hysteria2 TLS | Subscription HTTPS |
|---|---|---|
| Hostname (example) | `vpn.example.com` | `sub.example.com` |
| Port | `443/udp` | `8443/tcp` |
| Consumed by | `sing-box` directly (`tls.certificate_path`/`key_path` on the `hysteria2` inbound) | `nginx` (reverse proxy in front of the loopback-only Rust subscription service) |
| File location | `/etc/vpn/compat/hysteria/{cert,key}.pem` | `/etc/letsencrypt/live/<SUBSCRIPTION_HOST>/{fullchain,privkey}.pem` |
| Ownership | `root:sing-box 0640` | managed by certbot, read by nginx (root) |

They **may** reuse the same domain/certificate if `PUBLIC_HOST` and
`SUBSCRIPTION_HOST` are the same value and you deliberately copy one
cert to both locations — nothing in this stack assumes that silently.
By default `install.sh` treats them as fully independent and requires
both to be separately provisioned before it will start the
corresponding service.

(VLESS+REALITY needs **no certificate at all** — REALITY dials a real
site's TLS handshake as a disguise; sing-box owns that logic entirely.)

## Certificates

Both certificates above must exist **before** running `install.sh` —
the installer does not run an ACME client for you (task requirement:
don't hand-roll a second ACME integration; a single explicit operator
step is simpler and has fewer moving parts for a boring V1). Provision
them with certbot (or your own ACME client of choice):

```bash
sudo dnf install -y certbot
# Hysteria2 cert (consumed directly by sing-box):
sudo certbot certonly --standalone -d vpn.example.com \
  --non-interactive --agree-tos -m admin@vpn.example.com
sudo install -d -m 0750 -o root -g sing-box /etc/vpn/compat/hysteria
sudo install -m 0640 -o root -g sing-box \
  /etc/letsencrypt/live/vpn.example.com/fullchain.pem /etc/vpn/compat/hysteria/cert.pem
sudo install -m 0640 -o root -g sing-box \
  /etc/letsencrypt/live/vpn.example.com/privkey.pem /etc/vpn/compat/hysteria/key.pem

# Subscription HTTPS cert (consumed by nginx) — same command, different
# hostname; skip if SUBSCRIPTION_HOST equals PUBLIC_HOST and you intend
# to reuse the cert above instead.
sudo certbot certonly --standalone -d sub.example.com \
  --non-interactive --agree-tos -m admin@sub.example.com
```

`install.sh`'s "certificates" stage refuses to start `sing-box.service`
if the Hysteria2 cert/key are missing or invalid (`openssl x509
-checkend`) — it prints the exact commands above and exits non-zero
rather than starting a service that is guaranteed to fail. If the
subscription cert isn't present yet, install still completes (the
compatibility transport doesn't depend on it) but the nginx vhost is
left unconfigured and the final status explicitly says `SUBSCRIPTION
HTTPS: NOT CONFIGURED` — re-run `install.sh` once the cert exists.

Renewal: certbot's systemd timer handles both certs automatically.
After the Hysteria2 cert renews, re-copy it into
`/etc/vpn/compat/hysteria/` (preserving `root:sing-box 0640`) and
`sudo systemctl reload-or-restart sing-box` — a `certbot renew` deploy
hook is the natural way to automate this on a real host, not
implemented by this repo. After the subscription cert renews, `nginx -s
reload` is enough (TLS termination lives entirely in nginx, no
compatibility-stack service needs to restart).

**TCP/80 must stay reachable from the public internet long-term, not
just during the initial install.** Both certificates above use the
HTTP-01 challenge, which certbot's renewal timer re-runs automatically
roughly every 60 days for the lifetime of this deployment — if TCP/80
becomes unreachable from outside (a cloud-provider security group rule
removed after the initial install, a host firewall change, etc.),
renewal will silently start failing until someone notices the
certificate is approaching expiry. `install.sh` only opens TCP/80
*temporarily* during the install itself (see "Cloud provider firewalls /
security groups" below) — it does not leave it open permanently, since
vpn1's own protocols (VLESS+REALITY, Hysteria2, the subscription HTTPS
vhost) never use port 80. Either:
  - permanently allow inbound TCP/80 at both the host firewall layer
    (vpn1 manages this) and, if applicable, the separate cloud-provider
    firewall layer (vpn1 does not manage this — see below), or
  - switch to a different ACME challenge method (e.g. DNS-01) that
    doesn't need port 80 open at all — not implemented by this repo;
    you would configure it directly in certbot/your ACME client and
    point `install_certbot_renewal_hook`'s deploy hook at the resulting
    lineage the same way.

### Cloud provider firewalls / security groups

vpn1's firewall stages (`firewall.sh`/`firewall-ufw.sh`) only manage
this **host's own** firewall (`firewalld` or `ufw`). Most cloud
providers (AWS EC2 security groups, GCP firewall rules, Azure NSGs, ...)
enforce a **separate**, network-level firewall in front of the VM that
vpn1 cannot see or change — both layers must independently allow a port
before traffic reaches the service. If automatic certificate issuance
fails, or Hysteria2/VLESS+REALITY seem to work locally but no client can
ever connect, check the cloud-provider layer first:

- Allow inbound TCP/80 (temporarily, for ACME HTTP-01 — see above for
  why it may need to stay open long-term) from `0.0.0.0/0`, or at least
  from Let's Encrypt's validation servers/your own testing IP.
- Allow inbound TCP/443 and UDP/443 (VLESS+REALITY and Hysteria2)
  permanently from `0.0.0.0/0`.
- Allow inbound TCP on your `SUBSCRIPTION_PORT` (default `8443`)
  permanently from `0.0.0.0/0`.

Test external reachability from a **different** machine than the VPS
itself (a check run from the VPS only proves loopback works, not that
the internet can reach it):

```bash
curl -sS --max-time 5 http://<host>/ -o /dev/null -w '%{http_code}\n'   # TCP/80, during ACME issuance
curl -sS --max-time 5 https://<host>:8443/ -o /dev/null -w '%{http_code}\n'   # subscription HTTPS
```

Any HTTP response code (even an error like 404) means the port is
reachable from outside; a timeout or connection-refused means it is
not — check the cloud-provider firewall layer next.

## Fresh install (manual, own domain)

```bash
git clone <this-repo-url> vpn1 && cd vpn1
sudo PUBLIC_HOST=vpn.example.com SUBSCRIPTION_HOST=sub.example.com \
  REALITY_HANDSHAKE_SERVER=www.google.com \
  ./deploy/almalinux/install.sh
```

Explicit stages (each logged as `[install] === [N/17] ... ===`; any
stage failing aborts the script before "Install complete." is ever
printed):

1. preflight (root, OS/arch detection, disk/RAM/connectivity/DNS,
   port-conflict checks, existing-install detection)
2. OS packages (`dnf` on RHEL family, `apt` on Debian family — incl.
   `nginx`, `firewalld`/`ufw`, `certbot`)
3. host configuration (uses `PUBLIC_HOST` if set; otherwise
   auto-detects the public IP and assigns an `sslip.io` hostname)
4. vpn1 binaries (prebuilt release if available and checksum-verified;
   otherwise `cargo build --release`, auto-installing `rustup` if
   `cargo` is missing)
5. sing-box installation (pinned version, checksum-verified when
   published, `LICENSE` copied alongside the binary)
6. users/groups (`vpn-subscription`, `sing-box` service accounts)
7. directories (ownership matrix below)
8. certificates (Hysteria2 TLS required — auto-issued via certbot when
   no domain was manually supplied; subscription TLS optional — see
   "Certificates" above)
9. REALITY keys (`vpn-admin init`, re-owned to `root:sing-box`/
   `root:vpn-subscription` per file)
10. server config (`vpn-admin render-config` — **not** wrapped in
    `|| true`; a render/validate failure aborts install)
11. nginx/subscription HTTPS (auto-configured if the subscription cert
    is present; skipped with a clear status otherwise)
12. firewall (`firewalld` on RHEL family, `ufw` on Debian family: SSH,
    443/tcp, 443/udp, 8443/tcp only)
13. SELinux (RHEL family only — fcontext labeling for the binary and
    secret-serving directories)
14. systemd (unit install + daemon-reload)
15. validation + start (`sing-box check`, then enable + start both
    services)
16. first user + acceptance test (auto-creates a `default` user if none
    exists yet; `vpn-health-check` must pass)
17. summary (prints the subscription URL and, if `qrencode` is
    installed, a terminal QR code)

### File ownership (docs/PRODUCTION_HARDENING_PLAN.md #1)

Every path is owned by the group that actually needs to read it at
runtime — `sing-box` (`User=sing-box`) and `vpn-subscription`
(`User=vpn-subscription`) never share a group, and neither can read the
other's secrets:

| Path | Owner | Mode | Read by |
|---|---|---|---|
| `/etc/vpn/compat/reality/private.key` | `root:sing-box` | `0640` | sing-box |
| `/etc/vpn/compat/reality/public.key`, `short_id.txt` | `root:vpn-subscription` | `0640` | vpn-subscription |
| `/etc/vpn/compat/users/users.json` | `root:vpn-subscription` | `0640` | vpn-subscription |
| `/etc/vpn/compat/hysteria/{cert,key}.pem` | `root:sing-box` | `0640` | sing-box |
| `/etc/vpn/compat/sing-box/config.json` | `root:sing-box` | `0640` | sing-box |

Verify this on a live host with
`sudo ./deploy/almalinux/acceptance-test.sh` (checks both nominal
ownership/mode *and* effective `sudo -u <user> test -r <path>` access).

## Creating the first user

```bash
sudo vpn-admin --config /etc/vpn/deployment.toml user create --name test
```

Prints:

```
User ID:
  user_xxxxxxxx

IMPORTANT:
  The User ID above is NOT a credential and NOT your subscription token.
  ...

Hiddify subscription URL (this IS the credential — treat it like a password):
  https://sub.example.com:8443/sub/<token>?format=hiddify
```

The `?format=hiddify` query parameter is required, not cosmetic: a bare
`/sub/<token>` (no `format`) is served as native sing-box JSON, which
Hiddify's bundled sing-box fork can strict-unmarshal incorrectly and
silently fail to import (the subscription fetch succeeds, but neither
transport ever dials). `?format=hiddify` serves the plain
`vless://`/`hysteria2://` share-link representation instead, which
Hiddify's importer builds outbounds from directly. Native sing-box
clients (not Hiddify) should use `?format=singbox` instead — see
"Testing with Hiddify" below.

This URL is shown exactly once (spec §26 — only the token's hash is
persisted). Copy it now. The User ID printed above it is a separate,
non-secret account identifier (`vpn-admin user <id> ...`) — it is never
accepted as a `/sub/` path segment, so never substitute it into the
subscription URL.

## Testing with Hiddify

See `docs/HIDDIFY_ANDROID.md` for the end-user steps. As the operator,
you can sanity-check the subscription body yourself first:

```bash
curl -s "https://sub.example.com:8443/sub/<token>?format=singbox" | jq .
curl -s "https://sub.example.com:8443/sub/<token>?format=uri"
```

## Service status / logs

```bash
systemctl status sing-box vpn-subscription
journalctl -u sing-box -f
journalctl -u vpn-subscription -f
sudo vpn-health-check
```

## Firewall

```bash
sudo ./deploy/almalinux/firewall.sh
sudo firewall-cmd --list-all
sudo ss -tulpn
```

## Incident: a user's credentials leaked

```bash
sudo vpn-admin user revoke user_xxxxxxxx              # stop it now
sudo vpn-admin user reset-credentials user_xxxxxxxx --qr   # reissue safely
```

`revoke` is the one clear emergency command — see `docs/RECOVERY.md`
section A for the full incident playbook and exactly why `rotate-token`
alone does NOT stop an already-imported profile from connecting (it only
stops the subscription URL from being *fetched*). `reset-credentials`
rotates the VLESS UUID, Hysteria2 password, and subscription token
together and only re-enables the user once that's confirmed live;
deployment-wide REALITY keys are untouched.

## Disabling / removing a user

```bash
sudo vpn-admin --config /etc/vpn/deployment.toml user disable user_xxxxxxxx
sudo vpn-admin --config /etc/vpn/deployment.toml user remove user_xxxxxxxx
```

`disable` has the identical live effect as `revoke` above — `revoke` is
the same operation with incident-oriented output and does the extra work
of actually trying to verify the old credentials are rejected rather than
only asserting it.

Both commands render + validate + apply the new config, then reload
`sing-box` (`systemctl reload-or-restart`) and verify it comes back
active — the command does not report success until the running server
has actually stopped accepting the old credentials. If the reload
itself fails, the previous config is restored and reloaded back, and
the command exits non-zero explaining exactly that (see
`docs/PRODUCTION_HARDENING_PLAN.md` #4/#7) — it never prints "user
disabled successfully" while the old credentials are still live.

## Credential rotation

| What | Command | Client impact |
|---|---|---|
| Subscription token ONLY (URL fetch/refresh) | `vpn-admin user rotate-token <id>` | Old subscription URL 404s. **Does NOT revoke already-imported VLESS/Hysteria2 credentials** — they keep connecting until separately rotated/disabled. Use `user revoke` instead if the concern is an already-imported profile, not just the URL. |
| Full incident revocation | `vpn-admin user revoke <id>` | Disables the user; both transports AND the subscription URL stop working, verified (not just asserted) live. See "Incident" above. |
| Reissue after revoke | `vpn-admin user reset-credentials <id>` | Rotates VLESS UUID + Hysteria2 password + subscription token together, then re-enables. See "Incident" above. |
| VLESS UUID only | `vpn-admin user rotate-vless <id>` | User must re-import; Hysteria2 credentials unaffected. |
| Hysteria2 password only | `vpn-admin user rotate-hysteria <id>` | User must re-import; VLESS credentials unaffected. |
| Both VLESS UUID + Hysteria2 password (user stays enabled throughout) | `vpn-admin user rotate-credentials <id>` | User must re-import both transports. |
| REALITY keypair (deployment-wide) | `vpn-admin init --rotate` | **Every** client using this server must re-import (spec §12/§30: high impact, do this deliberately, rarely — do not use this for a single leaked user, see "Incident" above). |
| TLS certificate (Hysteria2) | manual re-copy + `systemctl reload-or-restart sing-box` (see "Certificates" above) | None — same cert, just renewed. |
| TLS certificate (subscription reverse proxy) | `certbot renew` (automatic) + `nginx -s reload` | None — reverse proxy only. |

All `rotate-*`/`disable`/`enable`/`remove`/`revoke`/`reset-credentials`
commands go through the same render→validate→apply→reload→verify→
rollback-on-failure path.

## Updating

```bash
sudo ./deploy/almalinux/update.sh
```

Builds, validates the re-rendered sing-box config, restarts services,
runs the health check, and automatically rolls back binaries + config
if the health check fails (spec §48/§49).

## Backup

Back up:

- `/etc/vpn/deployment.toml`
- `/etc/vpn/compat/reality/` (REALITY private key — losing this means
  regenerating and every client re-importing)
- `/etc/vpn/compat/users/users.json`
- Reverse proxy TLS/ACME state (e.g. `/etc/letsencrypt/`)

Do **not** need to back up: `/etc/vpn/compat/sing-box/config.json`
(regenerable from `users.json` + the REALITY key via
`vpn-admin render-config`), logs, `target/`.

Restore: reinstall the OS packages/binaries with `install.sh` (it will
skip secret generation if the restored files are already present at
their expected paths — `reality/private.key` existing is what triggers
the "refuse to overwrite" path), copy the backed-up `/etc/vpn` tree
back into place with correct ownership/permissions, then
`./deploy/almalinux/render-config.sh`.

## Rollback

See `deploy/almalinux/update.sh` — it keeps a timestamped backup under
`/etc/vpn/backups/` and rolls back automatically on health-check
failure. To roll back manually to a specific backup:

```bash
sudo cp /etc/vpn/backups/<timestamp>/vpn-admin /usr/local/bin/vpn-admin
sudo cp /etc/vpn/backups/<timestamp>/vpn-subscription-svc /usr/local/bin/vpn-subscription-svc
sudo cp /etc/vpn/backups/<timestamp>/config.json /etc/vpn/compat/sing-box/config.json
sudo systemctl restart vpn-subscription
sudo systemctl reload-or-restart sing-box
```

## Uninstall

Primary, offline path — installed by every normal install, no network
access required:

```bash
sudo /opt/vpn1/bin/vpn1-uninstall --yes
```

`--yes` skips the interactive confirmation prompt (this is irreversible
— it deletes live credentials/secrets — so a run without `--yes`, with a
terminal attached, asks first). Online fallback, only needed if
`/opt/vpn1` is missing or damaged:

```bash
curl -fsSL https://raw.githubusercontent.com/David610/vpn1/main/uninstall.sh | sudo bash -s -- --yes
```

This removes **everything** vpn1 created by default — `/etc/vpn`
(REALITY private key, `users.json`, TLS material), `/opt/vpn1`,
`/var/lib/vpn1`, all vpn1 systemd units, the nginx vhost, the sing-box
binary (if vpn1 installed it), certbot's vpn1 renewal hook and any
certificate lineages vpn1 issued, vpn1's firewall rules, the Rust
toolchain (if vpn1 installed it), and vpn1's kernel network tuning
(restored to the host's pre-vpn1 baseline via
`deploy/lib/perf-tuning.sh`'s rollback). There is no `--purge-state`/
`--purge-firewall` opt-in anymore — complete removal is simply what
"uninstall" means now. It is ownership-aware: anything that already
existed on the host before vpn1 (nginx, certbot, firewalld/ufw, a
pre-existing Rust toolchain, unrelated certificates, pre-existing users)
is left alone or restored to its previous enabled/state, never deleted.
Manifest-sourced values (certificate hostnames, the Rust toolchain path)
are re-validated before any destructive use, so a corrupted ownership
record is reported and left alone rather than acted on blindly. It
refuses to run from a directory it does not itself control (not
root-owned, or group/world-writable) as a defense-in-depth check. Safe
to run more than once. It prints a checklist at the end for the one
thing it genuinely cannot touch: your cloud provider's network-level
firewall/security group, if you opened one for vpn1 there.

`deploy/almalinux/uninstall.sh` is the real implementation both entry
points above hand off to — running it directly works identically.

## Acceptance test

```bash
sudo ./deploy/almalinux/acceptance-test.sh
```

Verifies OS version, SELinux enforcing, firewalld active, file
ownership/permissions (nominal *and* effective per-user access via
`sudo -u <user> test -r/-w`), both services active, `sing-box check`,
Hysteria TLS cert validity/expiry, the subscription reverse proxy
reachable over HTTPS, and that ports 1080/9000/9100 are not publicly
listening. Never prints secrets. Exits non-zero on any required
failure. Distinguishes a container smoke test (package/script syntax
only) from a real VM/VPS run (SELinux/firewalld/systemd/low-port
behavior) — see the script's own header comment.

## SELinux troubleshooting

`install.sh` labels the sing-box binary and the directories it reads
from (`fcontext` + `restorecon`), which should be sufficient on a
stock AlmaLinux 9 policy. If `sing-box` still fails to start or bind
443 with SELinux enforcing, check for AVC denials before doing anything
else:

```bash
sudo ausearch -m AVC -ts recent
sudo journalctl -u sing-box --since "5 min ago"
```

If a denial appears, generate the smallest policy addition for exactly
that denial (`audit2allow`) rather than disabling enforcement:

```bash
sudo ausearch -m AVC -ts recent | audit2allow -M vpn-compat-local
sudo semodule -i vpn-compat-local.pp
```

**`setenforce 0` is not an acceptable production fix** — it disables
SELinux confinement for the entire host, not just this service.

## `sudo: vpn-admin: command not found` despite the binary existing

`install.sh` installs `vpn-admin` (and its `vpn` alias, and
`vpn-health-check`) to `/usr/local/bin`, which is on a normal
interactive login shell's `PATH`. But `sudo` does **not** use your
shell's `PATH` — it uses its own `secure_path`, and AlmaLinux/RHEL's
default `/etc/sudoers` `secure_path` is typically just
`/sbin:/bin:/usr/sbin:/usr/bin`, which does **not** include
`/usr/local/bin`. So `vpn-admin ...` (no `sudo`) finds the binary fine,
but `sudo vpn-admin ...` reports "command not found" — this is a `sudo`
policy default, not a broken install. Confirm with:

```bash
which vpn-admin              # e.g. /usr/local/bin/vpn-admin — found
sudo which vpn-admin         # command not found — confirms this is the secure_path issue
sudo grep secure_path /etc/sudoers
```

Two ways to fix it, in order of preference:

1. **Simplest, no config change**: always give `sudo` the full path:
   ```bash
   sudo /usr/local/bin/vpn-admin --config /etc/vpn/deployment.toml doctor
   sudo /usr/local/bin/vpn-health-check
   ```
2. **If you want bare `sudo vpn-admin ...` to work**, add
   `/usr/local/bin` to `secure_path` via `sudo visudo` (never hand-edit
   `/etc/sudoers` directly — `visudo` validates syntax before saving and
   prevents a broken file from locking you out of `sudo` entirely):
   ```bash
   sudo visudo
   # find the line starting with `Defaults    secure_path = ...`
   # and add `:/usr/local/bin` to the end of the existing list, e.g.:
   #   Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin
   ```

`install.sh` deliberately does **not** make this change itself —
editing `sudo`'s security policy from an installer is too invasive for
a script to decide on the operator's behalf; this is a one-time,
operator-approved edit.

## Verifying a client can actually connect, not just that the server looks healthy

`vpn-admin doctor` (no flags) checks L1-L4 (process state, config/key/cert
validity including both TLS certificates' expiry — Hysteria2's and the
subscription reverse proxy's — listeners, and that the subscription
service's rendered keys agree with what's on disk) plus a `[RES]` disk-
space check on the filesystem backing `/etc/vpn` — it does **not** prove
a real client can complete a REALITY handshake. Run:

```bash
sudo vpn-admin doctor --protocol
```

to also spin up a throwaway `sing-box` client against this server's own
REALITY listener on loopback and report `[L5-6]`. See the `Doctor`
command's `--help` text for exactly what this does and does not prove
— it is best-effort and reports `[WARN]`, never `[FAIL]`, on an
inconclusive result, so a `[WARN]` there is not itself proof of a
broken server; a `[FAIL]` anywhere in `[L1]`-`[L4]` is.

## Known limitations of this deployment doc

This runbook and the scripts it documents are syntax-checked
(`bash -n`/`shellcheck deploy/almalinux/*.sh`, both clean) and the
underlying Rust logic (ownership/permission modes, reload/rollback,
credential generation) is unit- and integration-tested. The scripts
themselves have **not been executed against a real AlmaLinux 9 host, a
real VPS, or a real domain/DNS/TLS setup** in this development
session — this sandbox has no root network capability, no `dnf`, and
no real VPS. Treat the first real run (`install.sh` followed by
`acceptance-test.sh`) as the actual validation pass, and record the
outcome in `docs/CLIENT_COMPATIBILITY.md`'s manual acceptance log —
do not treat this document's existence as proof of a validated
deployment.

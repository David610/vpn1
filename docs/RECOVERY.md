# RECOVERY.md

Concise operator playbook for the four incident/recovery scenarios a
`<=10`-user single-VPS deployment (`docs/SUPPORTED_PRODUCT.md`)
realistically faces. A/B/C are quick, in-place operations over SSH; D is
the full VPS-loss procedure below.

## A. One user's credentials leaked

**Do this in two steps, not one.** Rotating the subscription token alone
does NOT revoke an already-imported VLESS/Hysteria2 profile — see
"`rotate-token` vs. `revoke`" below if that distinction isn't obvious yet.

```bash
sudo vpn-admin user revoke <user-id>              # step 1: stop it NOW
sudo vpn-admin user reset-credentials <user-id> --qr   # step 2: reissue safely
```

`revoke` disables the user, applies + reloads the live sing-box
authorization, and verifies (structurally, and with a real REALITY
handshake self-test where possible) that the old credentials are
actually rejected — it prints `VPN access revoked.` only once that's
true, and never mints a new credential itself.

`reset-credentials` rotates the VLESS UUID, Hysteria2 password, AND
subscription token together (the complete set needed to invalidate every
previously imported profile), applies + reloads live, and only then
re-enables the user and prints a fresh subscription URL/QR. It does
**not** rotate deployment-wide REALITY keys or the shared Hysteria2
obfuscation password — those have a much larger blast radius (every
user, not just this one) and are separate, deliberate operations (`vpn-admin
init --rotate`, `vpn-admin hysteria-obfs-rotate`) for a deployment-wide
compromise, not a single leaked profile.

Relay the new QR/subscription URL to the user through any channel other
than the one that leaked the old one.

### `rotate-token` vs. `revoke` — do not confuse these

| | `rotate-token` | `revoke` |
|---|---|---|
| Subscription URL | invalidated | invalidated (disabled user's subscription 404s) |
| Already-imported VLESS UUID | **still works** | rejected |
| Already-imported Hysteria2 password | **still works** | rejected |
| Use when | the URL itself leaked (e.g. pasted somewhere) but the profile was never imported by anyone untrusted | credentials may already be in use by someone who shouldn't have them |

If in doubt, `revoke` — it is the strictly wider action and `reset-credentials`
recovers from it in one more command.

## B. Subscription endpoint blocked/broken (server itself is fine)

```bash
sudo vpn-admin user links <user-id> --qr
```

Prints the VLESS+REALITY/Hysteria2 connection URIs directly from server
key material — no dependency on the subscription HTTP service or its
hostname. Relay the printed URI(s) to the user out of band.

## C. Server broken but SSH still works

```bash
sudo vpn-admin doctor          # what's actually broken (L1-L4)
sudo vpn-admin doctor --protocol   # + a real REALITY handshake self-test
sudo ./deploy/almalinux/update.sh --repair   # same-version repair, transactional
sudo journalctl -u sing-box -u vpn-subscription --no-pager -n 200
```

## D. Server/IP lost entirely

The full VPS-loss disaster-recovery procedure, below. Deliberately a
**manual rebuild + credential rotation**, not automated backup/restore or
multi-node failover — see `docs/COMPATIBILITY_SECURITY_REVIEW.md`'s "As a
censor blocking the VPS's IP/ASN" for why a single VPS can't design
around a full IP block, and why v1.0 does not attempt to.

There is exactly one recovery procedure. It is not a fleet operation,
it does not talk to the old VPS, and it does not require the old VPS to
still be reachable.

## Procedure

1. **Provision a fresh AlmaLinux 9 x86_64 VPS.** A different provider
   and/or different ASN than the blocked one, if IP/ASN blocking is why
   you're doing this — reusing the same provider's IP range risks the
   same block.
2. **Point (or configure) a domain at the new VPS's IP.** This can be
   the same domain name as before (update its DNS record) or a new one
   — if the domain itself was blocked (not just the IP), use a new
   domain.
3. **Run the one-command installer** (`docs/ALMALINUX_DEPLOYMENT.md`)
   on the new VPS. This is the same immutable, pinned-version installer
   used for a first-time install — recovery is not a special code path.
4. **Create fresh users / rotate credentials.** `vpn-admin user create`
   for each of your `<=10` users. Do not attempt to copy `users.json`
   or key material from the old VPS — a compromised or seized VPS's
   secrets must be treated as burned, not reused.
5. **Redistribute fresh profiles out of band.** `vpn-admin user create
   --qr` (or `vpn-admin user links` if the subscription domain
   specifically — not the VPS itself — is what's still blocked/down)
   over SSH, then relay the QR code / URI to each user through whatever
   channel is currently working for you and them. This is manual by
   design — v1.0 does not build a distribution platform for a `<=10`-
   person family/friend group.
6. **Verify at least one real client actually connects** through the
   new VPS before telling everyone it's ready — `sudo vpn-admin doctor
   --protocol` proves the server's own listeners work, but only a real
   device import (`docs/DEVICE_ACCEPTANCE_TESTS.md`) proves an end user
   can actually get online through it.
7. **Revoke/retire the old VPS.** If it's still reachable, run
   `sudo /opt/vpn1/bin/vpn1-uninstall --yes` on it and terminate the
   instance with the provider. If it's not reachable (seized, provider
   already killed it, etc), there's nothing more to do on that box —
   its secrets are already burned by step 4, since the new VPS never
   reused them.

## What this deliberately does not do

- No encrypted backup/restore of `users.json` or REALITY/Hysteria2 key
  material — rebuilding with fresh credentials is simpler and safer for
  this deployment's threat model than restoring possibly-compromised
  secrets from a blocked/seized host.
- No automatic failover, no standby VPS, no multi-node control plane,
  no rendezvous/fleet system. Recovery is a person running the
  installer once, not an orchestration layer reacting to an outage.
- No new subscription/distribution infrastructure — step 5 reuses the
  existing `vpn-admin user create --qr` / `vpn-admin user links`
  commands, run manually over SSH.

## Status

This procedure has not been executed end-to-end against a real second
VPS in this session — see `docs/IMPLEMENTATION_STATUS.md` for what is
verified versus documented-but-untested. The individual pieces it
depends on (installer idempotency/fresh-install correctness, `user
create --qr`, `user links`, `vpn1-uninstall`) each have their own
targeted tests; the full 7-step sequence as a single rehearsed
disaster-recovery drill is UNVERIFIED.

Scenario A (`user revoke` / `user reset-credentials`, added Checkpoint
7): the disable/re-enable/credential-rotation mechanics and their
transactional apply/rollback behavior are `VERIFIED-TEST` (real, if
faked, sing-box + systemctl in `apps/admin/tests/cli.rs`); an actual real
device losing/regaining connectivity as a result is `UNVERIFIED` until a
real Hiddify device test exists (`docs/DEVICE_ACCEPTANCE_TESTS.md`).

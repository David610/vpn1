# Client onboarding docs

Per-platform instructions for importing a vpn1 subscription into a
compatible client. All of these assume the administrator has already run
`vpn-admin user create --name <you>` (or `vpn user create ...` — same
binary, see `apps/admin/Cargo.toml`) and handed you a subscription URL
(`https://sub.example.com:8443/sub/<token>`) or a QR code of it
(`vpn-admin user create --qr` / `vpn-admin user qr <name>`).

You do not need to understand UUIDs, REALITY keys, Hysteria2 passwords,
ports, JSON, sing-box, VLESS, or TLS certificates to use any of these —
the subscription URL/QR carries everything the client needs.

| Platform | Client | Doc |
|---|---|---|
| iOS / iPadOS | Hiddify | [HIDDIFY_IOS.md](HIDDIFY_IOS.md) |
| Android | Hiddify | [`docs/HIDDIFY_ANDROID.md`](../HIDDIFY_ANDROID.md) (Russian, existing) |
| Android | v2rayNG (VLESS-only fallback) | [V2RAYNG_ANDROID.md](V2RAYNG_ANDROID.md) |
| HONOR MagicOS | Hiddify | [HIDDIFY_MAGICOS.md](HIDDIFY_MAGICOS.md) |
| Linux | Hiddify | [HIDDIFY_LINUX.md](HIDDIFY_LINUX.md) |
| Windows / macOS | Hiddify | See [HIDDIFY_LINUX.md](HIDDIFY_LINUX.md) — the desktop app is the same across all three desktop OSes; menu labels are near-identical. Windows/macOS-specific quirks have not been observed/tested and are not claimed here. |

See [CLIENT_DIAGNOSTICS.md](CLIENT_DIAGNOSTICS.md) for a small
cross-platform script to measure your own real network path to the VPN
server (latency, loss, throughput, PMTU) — useful when performance
feels wrong and you want data to compare, not guesses.

See `docs/DEVICE_ACCEPTANCE_TESTS.md` for the honest per-platform
validation status (none of these have been tested against a real device
in this development environment — see that document for exactly what
that means and how to run the test yourself).

UI label names below reflect the Hiddify app's publicly documented
behavior at the time this was written; Hiddify updates its UI
periodically; if a label has moved, the underlying steps (import
profile, allow VPN permission, connect) do not change.

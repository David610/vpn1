//! `vpn-admin`: administration CLi for compatibility (VLESS+REALITY /
//! Hysteria2) users. Operates entirely on the local `users.json` store
//! plus the rendered sing-box config (spec §15/§16) — no PostgreSQL, no
//! separate control-plane service. Never prints secrets in a normal
//! listing (spec §15); the raw subscription token is shown exactly once,
//! at `create` or `rotate-token` time, because only its hash is persisted
//! (spec §26).

mod lock;
mod service;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use common::UnixSeconds;
use compat_config::deployment::DeploymentConfig;
use compat_config::model::{CompatUser, Hysteria2ServerParams, RealityServerParams};
use compat_config::render::render_singbox_client_subscription;
use compat_config::secret::SecretString;
use compat_config::server::{
    apply_config_atomically, config_backup_path, render_singbox_server_config,
    CompatibilityBackend, ServerPorts, SingBoxBackend,
};
use compat_config::{credentials, store};
use serde_json::json;
use service::CompatibilityServiceManager;
use std::net::ToSocketAddrs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "vpn-admin",
    about = "Compatibility (Hiddify/VLESS-REALITY/Hysteria2) user administration"
)]
struct Cli {
    /// Path to the deployment configuration (spec §36).
    #[arg(long, default_value = "/etc/vpn/deployment.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate missing server secrets (REALITY keypair, short_id) via
    /// the real `sing-box` binary. Refuses to overwrite an existing
    /// REALITY key unless `--rotate` is passed (spec §37).
    Init {
        #[arg(long)]
        rotate: bool,
    },
    /// Regenerate and atomically apply the sing-box server config from
    /// the current user store, without changing any user.
    RenderConfig {
        /// Exit non-zero if the rendered config actually differs from
        /// what's live (i.e. reconciliation was attempted) but could
        /// not be fully applied — missing sing-box binary, systemctl
        /// unavailable, sing-box.service not installed, or a reload
        /// failure. Without this flag those conditions only print a
        /// warning and exit 0 (kept lenient for manual/dev/CI use,
        /// where "sing-box isn't installed yet" is expected, not a
        /// failure). `vpn-expiry-reconcile.service` — the once-a-minute
        /// timer that is the only thing keeping expired users'
        /// authorization in sync with the live server — passes this,
        /// because on a real deployment every one of those conditions
        /// is a genuine regression, and reporting success while
        /// silently failing to reconcile is exactly the failure mode
        /// this flag exists to close. A no-op ("already current, no
        /// reload needed") is always success, with or without this
        /// flag — this only changes what happens when reconciliation
        /// was actually attempted and did not complete.
        #[arg(long)]
        require_applied: bool,
    },
    /// Print vpn-admin's own version and the configured sing-box
    /// binary's reported version, if present.
    Version,
    /// Summarize the current deployment: service state, user counts,
    /// config presence. Does not print secrets.
    Status,
    /// Run diagnostic checks and print `[OK]`/`[WARN]`/`[FAIL]` for each,
    /// each line tagged with the layer it actually covers (L1 process /
    /// L2 config-key-cert / L3 listeners / L4 subscription-coherence /
    /// L5-6 protocol handshake) so an operator can see at a glance what
    /// was, and was not, actually verified — "service active + config
    /// valid + port open" (L1-L3) is NOT the same claim as "a real
    /// client can authenticate" (L5-6). Exits non-zero if any check
    /// fails. Checks that need a tool not present on this host are
    /// reported `[WARN] ... not available`, not silently skipped or
    /// faked as passing.
    Doctor {
        /// Also run the best-effort L5/L6 protocol self-test: spin up
        /// the real `sing-box` binary as a throwaway client against this
        /// server's own VLESS+REALITY listener on loopback, using the
        /// live REALITY public key/short_id, to prove (not just infer)
        /// that a real client can complete a handshake. Off by default
        /// because it spawns a subprocess and does real network I/O;
        /// the always-on L1-L4 checks are pure file/struct comparisons.
        /// Unavailable or inconclusive checks are warnings unless
        /// `--require-protocol` is also supplied.
        #[arg(long)]
        protocol: bool,
        /// Make an unavailable or inconclusive protocol self-test a hard
        /// failure. The installer uses this after creating the first user so
        /// it cannot bless an untested REALITY decoy.
        #[arg(long, requires = "protocol")]
        require_protocol: bool,
        /// Run the standard checks, then print an additional
        /// Telegram-oriented summary (transport/obfuscation state,
        /// server-side network sanity) ending in an explicit disclaimer.
        /// This NEVER claims to test Telegram itself, Russian DPI
        /// compatibility, or client-side (Hiddify/TUN) behavior — it is
        /// server-side diagnostics only, framed for the specific
        /// troubleshooting flow in docs/TELEGRAM_TROUBLESHOOTING.md.
        #[arg(long)]
        telegram: bool,
        /// Print a sanitized diagnostic bundle (versions, service
        /// state, listeners, hostname resolution, transport/obfuscation
        /// status, certificate expiry, firewall summary, a redacted
        /// tail of recent sing-box/vpn-subscription log lines) suitable
        /// for sharing when asking for help. Secrets (private keys,
        /// VLESS UUIDs, Hysteria2/obfuscation passwords, subscription
        /// tokens) are redacted — see `redact_secrets`. Writes to
        /// stdout, or to `--report-output PATH` (mode 0600) if given.
        #[arg(long)]
        report: bool,
        #[arg(long, requires = "report")]
        report_output: Option<PathBuf>,
        /// Print an interactive client-acceptance checklist after the
        /// standard server-side checks: what a Hiddify/iOS (or other
        /// client) user must verify ON THE DEVICE — this process cannot
        /// reach into a phone, so every line here is something the human
        /// operator checks and fills in by hand, never something this
        /// command probes itself. Exists because "Hiddify shows
        /// connected" and "the device's system traffic is actually
        /// routed through the VPN" are different claims, and conflating
        /// them is the single most common support failure for this
        /// deployment — see docs/clients/HIDDIFY_IOS.md.
        #[arg(long)]
        client: bool,
        /// Print host/kernel/network performance MEASUREMENTS — CPU
        /// model, vCPU count, load average, %steal, RAM/swap, current
        /// vs. available TCP congestion control, qdisc, UDP socket
        /// buffer ceilings, UDP/TCP error counters, sing-box's own CPU
        /// share and effective nice/rlimits — never a
        /// recommendation, never a pass/fail verdict, and never a
        /// substitute for `vpn benchmark`'s actual throughput numbers
        /// (see docs/PERFORMANCE_OPTIMIZATION_PLAN.md, which explains
        /// why: this command cannot tell you whether the bottleneck is
        /// this host or the network path to it — only a real transfer
        /// can). A metric this process cannot read on the running
        /// kernel/host is printed as `unavailable`, never guessed or
        /// omitted silently. Read-only; changes nothing.
        #[arg(long)]
        performance: bool,
    },
    /// Back up the minimum state needed to rebuild this deployment
    /// (users, credential metadata, REALITY keys, Hysteria2 TLS
    /// material) into a single tar archive written mode 0600. Contains
    /// secrets — treat the output file as sensitive.
    Backup {
        /// Destination path. Defaults to
        /// `vpn1-backup-<unix-seconds>.tar` in the current directory.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Restore a backup produced by `backup`. Validates the archive
    /// contents (users file parses, REALITY private key present) before
    /// touching any live state, then applies the restored config through
    /// the same validate-then-apply-then-reload path as every other
    /// mutating command — a corrupt or incompatible backup is rejected
    /// by `sing-box check` rather than silently installed.
    Restore { archive: PathBuf },
    /// Enable (first run) or rotate (subsequent runs) the shared Hysteria2
    /// salamander obfuscation password. Obfuscation hides the Hysteria2/
    /// QUIC handshake's protocol signature from DPI/traffic classifiers —
    /// resisting the class of active-probing/fingerprinting-based
    /// blocking that plain (un-obfuscated) Hysteria2 is most exposed to.
    /// Validates the candidate config with the real sing-box binary,
    /// applies it, reloads sing-box, and restarts vpn-subscription (which
    /// caches the obfs password at startup, same as the REALITY public
    /// key) — fully rolled back on any failure. Every existing client's
    /// Hysteria2 profile must be re-imported afterward, exactly like
    /// `init --rotate`/`user rotate-hysteria`.
    HysteriaObfsRotate,
    #[command(subcommand)]
    User(UserCommands),
    #[command(subcommand)]
    Config(ConfigCommands),
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Read-only: report the on-disk schema state of deployment.toml and
    /// users.json — FRESH/CURRENT (nothing to do), MIGRATION_REQUIRED
    /// (legacy schema found, recoverable via `config migrate`), or
    /// INVALID (corrupted, or a schema newer than this binary supports —
    /// needs a backup restore or a newer vpn-admin). Never changes
    /// anything. Exit code: 0 = FRESH/CURRENT, 2 = MIGRATION_REQUIRED,
    /// 3 = INVALID.
    Validate,
    /// Migrate deployment.toml/users.json to the schema this vpn-admin
    /// understands: backs up the original (mode 0600) before touching
    /// anything, validates the migrated state (including a real
    /// render-config + `sing-box check` when a REALITY key and sing-box
    /// binary are already present), and only then commits atomically.
    /// Idempotent — safe to re-run; a no-op if already current. Refuses
    /// (leaving all state untouched) on corrupted input or a schema
    /// newer than this binary supports.
    Migrate,
}

#[derive(Subcommand)]
enum UserCommands {
    Create {
        #[arg(long)]
        name: String,
        /// Optional unix-seconds expiry.
        #[arg(long)]
        expires_at: Option<i64>,
        /// Print a terminal QR code of the subscription URL alongside
        /// the normal output.
        #[arg(long)]
        qr: bool,
        /// Print `{"id","name","enabled","subscription_url"}` as JSON
        /// instead of the human-readable form. Never includes server
        /// private keys.
        #[arg(long)]
        json: bool,
    },
    List,
    /// Print a terminal QR code encoding a user's subscription URL. The
    /// raw subscription token is never persisted (only its hash is), so
    /// this mints a *fresh* token the same way `rotate-token` does —
    /// there is no way to QR-encode a still-valid previously-issued
    /// token without knowing it, by design. The previous subscription
    /// URL stops working.
    Qr {
        user_id: String,
    },
    /// Print this user's VLESS+REALITY and Hysteria2 connection URIs
    /// directly (`vless://...`, `hysteria2://...`), computed from the
    /// server's own key material with no dependency on the subscription
    /// HTTP service or its hostname. Out-of-band recovery path for when
    /// the subscription domain/IP is blocked, rate-limited, or simply
    /// down but the REALITY/Hysteria2 listeners themselves still work:
    /// run this over SSH and relay the printed URIs to the user through
    /// any other channel (paste, QR, etc). Read-only — unlike `qr`/
    /// `rotate-token`, it does not mint a new subscription token or
    /// change any credential.
    Links {
        user_id: String,
        /// Print a terminal QR code for each URI as well.
        #[arg(long)]
        qr: bool,
    },
    Enable {
        user_id: String,
    },
    Disable {
        user_id: String,
    },
    RotateToken {
        user_id: String,
        /// Print a terminal QR code of the new subscription URL.
        #[arg(long)]
        qr: bool,
    },
    /// Rotate only the VLESS UUID. Applies + reloads sing-box so the
    /// previous UUID stops working immediately.
    RotateVless {
        user_id: String,
    },
    /// Rotate only the Hysteria2 password. Applies + reloads sing-box so
    /// the previous password stops working immediately.
    RotateHysteria {
        user_id: String,
    },
    /// Rotate both the VLESS UUID and Hysteria2 password. Does not touch
    /// REALITY server keys or the subscription token — use `init
    /// --rotate` / `rotate-token` for those separately, since they have
    /// different blast radii.
    RotateCredentials {
        user_id: String,
    },
    Remove {
        user_id: String,
    },
    /// Print connection material for a user. The subscription URL itself
    /// requires the raw token, which (by design, spec §26) is not
    /// persisted — only shown at `create`/`rotate-token` time. This
    /// prints everything else plus a reminder of that fact.
    Subscription {
        user_id: String,
    },
}

/// Every command that reads-then-writes `users.json` and/or
/// `config.json` — i.e. everything except the pure-read commands
/// (`version`, `status`, `doctor`, `user list`, `user subscription`) —
/// must hold the system-wide state lock for its entire duration
/// (docs/FINAL_PRODUCTION_AUDIT.md P0-4). `user qr` mutates (it rotates
/// the token, same as `rotate-token`) and is included.
fn command_mutates_state(cmd: &Commands) -> bool {
    !matches!(
        cmd,
        Commands::Version
            | Commands::Status
            | Commands::Doctor { .. }
            | Commands::User(UserCommands::List)
            | Commands::User(UserCommands::Subscription { .. })
            | Commands::Config(ConfigCommands::Validate)
    )
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = DeploymentConfig::load(&cli.config)
        .with_context(|| format!("loading deployment config from {:?}", cli.config))?;

    // Held for the ENTIRE duration of a mutating command — not just the
    // file write — so two concurrent `vpn-admin` invocations can never
    // interleave their load->mutate->persist->apply->reload sequences.
    let _state_lock = if command_mutates_state(&cli.command) {
        Some(lock::acquire_state_lock().context(
            "acquiring vpn1 state lock (another vpn-admin/install/update operation is in progress)",
        )?)
    } else {
        None
    };

    match cli.command {
        Commands::Init { rotate } => cmd_init(&cfg, rotate),
        Commands::RenderConfig { require_applied } => cmd_render_config(&cfg, require_applied),
        Commands::Version => cmd_version(&cfg),
        Commands::Status => cmd_status(&cfg),
        Commands::Doctor {
            protocol,
            require_protocol,
            telegram,
            report,
            report_output,
            client,
            performance,
        } => cmd_doctor(
            &cfg,
            protocol,
            require_protocol,
            telegram,
            report,
            report_output.as_deref(),
            client,
            performance,
        ),
        Commands::Backup { output } => cmd_backup(&cfg, &cli.config, output),
        Commands::Restore { archive } => cmd_restore(&cfg, &cli.config, &archive),
        Commands::HysteriaObfsRotate => cmd_hysteria_obfs_rotate(&cfg),
        Commands::Config(ConfigCommands::Validate) => cmd_config_validate(&cfg, &cli.config),
        Commands::Config(ConfigCommands::Migrate) => cmd_config_migrate(&cfg, &cli.config),
        Commands::User(UserCommands::Create {
            name,
            expires_at,
            qr,
            json,
        }) => cmd_user_create(&cfg, &name, expires_at, qr, json),
        Commands::User(UserCommands::List) => cmd_user_list(&cfg),
        Commands::User(UserCommands::Qr { user_id }) => cmd_user_qr(&cfg, &user_id),
        Commands::User(UserCommands::Links { user_id, qr }) => cmd_user_links(&cfg, &user_id, qr),
        Commands::User(UserCommands::Enable { user_id }) => {
            cmd_user_set_enabled(&cfg, &user_id, true)
        }
        Commands::User(UserCommands::Disable { user_id }) => {
            cmd_user_set_enabled(&cfg, &user_id, false)
        }
        Commands::User(UserCommands::RotateToken { user_id, qr }) => {
            cmd_user_rotate_token(&cfg, &user_id, qr)
        }
        Commands::User(UserCommands::RotateVless { user_id }) => {
            cmd_user_rotate_vless(&cfg, &user_id)
        }
        Commands::User(UserCommands::RotateHysteria { user_id }) => {
            cmd_user_rotate_hysteria(&cfg, &user_id)
        }
        Commands::User(UserCommands::RotateCredentials { user_id }) => {
            cmd_user_rotate_credentials(&cfg, &user_id)
        }
        Commands::User(UserCommands::Remove { user_id }) => cmd_user_remove(&cfg, &user_id),
        Commands::User(UserCommands::Subscription { user_id }) => {
            cmd_user_subscription(&cfg, &user_id)
        }
    }
}

fn cmd_init(cfg: &DeploymentConfig, rotate: bool) -> Result<()> {
    std::fs::create_dir_all(cfg.reality_dir())?;
    std::fs::create_dir_all(cfg.hysteria_dir())?;
    std::fs::create_dir_all(cfg.users_file().parent().unwrap())?;

    let priv_path = cfg.reality_private_key_file();
    let pub_path = cfg.reality_public_key_file();
    let sid_path = cfg.reality_dir().join("short_id.txt");
    let deployment_exists = cfg.singbox_config_file().exists();

    if priv_path.exists() {
        if !rotate {
            // A PARTIAL keyset is not a healthy "already initialised" state.
            // Returning Ok here when public.key/short_id.txt are missing left
            // install.sh's subsequent `chown` of those files failing under
            // `set -e` on every re-run, with no way out except deleting the
            // private key (which invalidates every client) — a permanent
            // installer deadlock. Say so instead of reporting success.
            if !pub_path.exists() || !sid_path.exists() {
                bail!(
                    "REALITY key material at {:?} is incomplete: private.key exists but {}. \
                     This is a partially-written keyset (an interrupted `init`), not a healthy \
                     deployment, and the public half cannot be recovered from the private half \
                     here. Re-run with `--rotate` to generate a fresh, coherent keypair — note \
                     that this invalidates every existing client's configuration and they must \
                     re-import their subscription.",
                    cfg.reality_dir(),
                    match (pub_path.exists(), sid_path.exists()) {
                        (false, false) => "public.key and short_id.txt are both missing",
                        (false, true) => "public.key is missing",
                        _ => "short_id.txt is missing",
                    }
                );
            }
            println!(
                "REALITY key already present at {priv_path:?}; refusing to overwrite (pass --rotate to replace it deliberately — this breaks every existing client's connection until they re-import)."
            );
            return Ok(());
        }
        // A key already exists and this is a deliberate rotation: this
        // MUST go through the fully coordinated transactional flow
        // (docs/FINAL_PRODUCTION_AUDIT.md P0-5) — a bare key-file swap
        // here would leave the running sing-box serving the OLD private
        // key (clients still connect fine) while any freshly-restarted
        // subscription service would advertise the NEW public key
        // (clients using it fail REALITY's handshake matching), a silent
        // split-brain that is worse than doing nothing.
        return cmd_reality_rotate(cfg);
    }

    // Key material is absent. Whether a plain generate-and-write is safe
    // depends on whether anything is ALREADY RUNNING on the old material —
    // not on whether the private key file happens to exist.
    //
    // A rendered sing-box config means there is a live deployment: sing-box
    // is enforcing key material from that config and vpn-subscription has
    // the old public key cached in memory. Writing three files and exiting 0
    // here (which is what this path used to do) leaves disk, generated
    // config, and both running processes disagreeing — the exact split-brain
    // the `--rotate` branch above exists to prevent. Route it through the
    // same transactional flow.
    if deployment_exists {
        println!(
            "REALITY key material is missing but a rendered sing-box config already exists at \
             {:?} — treating this as a rotation so the new key is rendered, validated, and \
             loaded by the running services rather than silently diverging from them.",
            cfg.singbox_config_file()
        );
        return cmd_reality_rotate(cfg);
    }

    // First-ever generation on a host with no deployment yet: nothing is
    // running that depends on this material. Still written atomically and
    // durably, because a crash between these three files is what produces
    // the unrecoverable partial keyset handled above.
    let (private_key, public_key, short_id) = generate_reality_keypair(cfg)?;
    install_rotated_key_file(&priv_path, &private_key)?;
    install_rotated_key_file(&pub_path, &public_key)?;
    install_rotated_key_file(&sid_path, &short_id)?;
    // `install_rotated_key_file` preserves an EXISTING target's mode, but
    // these are first writes with no target to inherit from, so they land
    // 0600. The REALITY public key and short_id are not secrets and
    // `vpn-subscription` must be able to read them via its group (the
    // installer chowns them to root:vpn-subscription right after this) —
    // 0600 would leave that service unable to read its own material.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [&pub_path, &sid_path] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o640))
                .with_context(|| format!("setting mode 0640 on {p:?}"))?;
        }
    }
    fsync_dir(&cfg.reality_dir());
    println!("Generated REALITY keypair at {:?}", cfg.reality_dir());

    // Hysteria2 salamander obfuscation is enabled by default on every
    // fresh install (nothing is running yet, so — same reasoning as the
    // REALITY keypair above — a plain generate-and-write is safe here; an
    // existing deployment upgrading to this feature must use the explicit
    // `hysteria-obfs-rotate` command instead, which applies the change
    // through the running services rather than silently). Obfuscation
    // resists DPI/traffic-classifier fingerprinting of the bare Hysteria2/
    // QUIC handshake — one of the concrete, documented ways a censor can
    // selectively degrade specific traffic riding an otherwise-working
    // tunnel without needing to see inside it.
    let obfs_password = credentials::generate_hysteria2_obfs_password();
    let obfs_path = cfg.hysteria_obfs_password_file();
    install_rotated_key_file(&obfs_path, &obfs_password)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&obfs_path, std::fs::Permissions::from_mode(0o640))
            .with_context(|| format!("setting mode 0640 on {obfs_path:?}"))?;
    }
    fsync_dir(&cfg.reality_dir());
    println!("Generated Hysteria2 obfuscation password at {obfs_path:?}");

    println!(
        "Hysteria2 TLS certificate/key are not generated by vpn-admin — place a valid \
         certificate at {:?} and key at {:?} (see docs/ALMALINUX_DEPLOYMENT.md for the \
         ACME setup).",
        cfg.hysteria_dir().join("cert.pem"),
        cfg.hysteria_dir().join("key.pem")
    );
    Ok(())
}

fn generate_reality_keypair(cfg: &DeploymentConfig) -> Result<(String, String, String)> {
    let output = std::process::Command::new(&cfg.singbox_binary)
        .arg("generate")
        .arg("reality-keypair")
        .output()
        .with_context(|| {
            format!(
                "running {:?} generate reality-keypair (is sing-box installed at this path?)",
                cfg.singbox_binary
            )
        })?;
    if !output.status.success() {
        bail!(
            "sing-box generate reality-keypair failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let private_key = extract_field(&text, "PrivateKey")
        .context("could not parse PrivateKey from sing-box output")?;
    let public_key = extract_field(&text, "PublicKey")
        .context("could not parse PublicKey from sing-box output")?;
    credentials::validate_reality_keypair(&private_key, &public_key)
        .map_err(|error| anyhow::anyhow!(error))
        .context("sing-box generated an incoherent REALITY keypair")?;
    let short_id = credentials::generate_short_id();
    Ok((private_key, public_key, short_id))
}

/// Sibling backup path used only for the duration of one rotate
/// operation (created just before the risky part starts, removed on
/// success, restored-from on failure). Not a long-term backup mechanism
/// — see `vpn-admin backup` for that.
fn rotate_backup_path(p: &std::path::Path) -> std::path::PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".rotate-bak");
    std::path::PathBuf::from(s)
}

/// Copy `src` to its `.rotate-bak` sibling if `src` exists, preserving
/// mode/ownership exactly (needed to restore a byte-for-byte identical
/// file, including the group a service account depends on, if rotation
/// fails partway through).
fn backup_for_rotate(src: &std::path::Path) -> Result<Option<std::path::PathBuf>> {
    use std::io::Write;
    let bak = rotate_backup_path(src);
    if bak.exists() {
        bail!(
            "refusing to overwrite stale transaction backup {bak:?}; recover or remove it after \
             verifying the live file before retrying"
        );
    }
    if !src.exists() {
        return Ok(None);
    }
    let mut source = std::fs::File::open(src)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut backup = options
        .open(&bak)
        .with_context(|| format!("creating transaction backup {bak:?}"))?;
    std::io::copy(&mut source, &mut backup)
        .with_context(|| format!("backing up {src:?} to {bak:?}"))?;
    backup.flush()?;
    backup.sync_all()?;
    #[cfg(unix)]
    {
        let meta = std::fs::metadata(src)?;
        std::fs::set_permissions(&bak, meta.permissions())?;
        std::os::unix::fs::chown(
            &bak,
            Some(std::os::unix::fs::MetadataExt::uid(&meta)),
            Some(std::os::unix::fs::MetadataExt::gid(&meta)),
        )
        .ok(); // best-effort: non-root test environments can't chown to an arbitrary uid/gid
    }
    Ok(Some(bak))
}

/// Restore `dst` from its `.rotate-bak` sibling (written by
/// `backup_for_rotate`) if one exists, then remove the backup file.
fn restore_from_rotate_backup(dst: &std::path::Path) -> Result<()> {
    let bak = rotate_backup_path(dst);
    if bak.exists() {
        #[cfg(not(unix))]
        if dst.exists() {
            std::fs::remove_file(dst)?;
        }
        std::fs::rename(&bak, dst)
            .with_context(|| format!("atomically restoring {dst:?} from backup {bak:?}"))?;
        if let Some(parent) = dst.parent() {
            fsync_dir(parent);
        }
    }
    Ok(())
}

fn remove_rotate_backup(p: &std::path::Path) {
    let _ = std::fs::remove_file(rotate_backup_path(p));
}

/// Coordinated REALITY key rotation (docs/FINAL_PRODUCTION_AUDIT.md
/// P0-5): backup -> generate candidate -> render+validate candidate
/// config with the REAL sing-box binary -> atomically install key
/// material -> apply config -> reload sing-box -> restart subscription
/// (it caches the public key/short_id at startup, so a plain config
/// reload does not pick up new REALITY public material on its own) ->
/// verify both -> commit. Any failure after key material starts being
/// touched triggers a full rollback of key files AND config, followed by
/// reloading/restarting both services back to the previous state and
/// verifying that recovery actually worked — this function only returns
/// `Ok` if the end state is fully consistent, and its `Err` messages
/// always say whether rollback succeeded.
fn cmd_reality_rotate(cfg: &DeploymentConfig) -> Result<()> {
    let priv_path = cfg.reality_private_key_file();
    let pub_path = cfg.reality_public_key_file();
    let sid_path = cfg.reality_dir().join("short_id.txt");
    let config_target = cfg.singbox_config_file();

    if !cfg.singbox_binary.exists() {
        bail!(
            "cannot safely rotate: sing-box binary not found at {:?} — rotation requires \
             validating the candidate config with the real binary before installing new key \
             material (never rotate blind).",
            cfg.singbox_binary
        );
    }

    println!("Rotating REALITY key material...");
    let (candidate_priv, candidate_pub, candidate_sid) = generate_reality_keypair(cfg)?;

    let candidate_reality = RealityServerParams {
        private_key_hex: SecretString::new(candidate_priv.clone()),
        public_key_hex: candidate_pub.clone(),
        short_ids: vec![candidate_sid.clone()],
        handshake_server: cfg.reality.handshake_server.clone(),
        handshake_port: cfg.reality.handshake_port,
    };
    let users = store::load_users(&cfg.users_file())?;
    let hysteria = load_hysteria_params(cfg);
    let ports = ServerPorts {
        vless_reality_port: cfg.reality.listen_port,
        hysteria2_port: cfg.hysteria2.listen_port,
    };
    let now = UnixSeconds::now().0 as i64;
    let candidate_doc =
        render_singbox_server_config(&users, &candidate_reality, &hysteria, ports, now);

    let backend = SingBoxBackend {
        binary_path: cfg.singbox_binary.clone(),
    };

    // Validate the candidate BEFORE creating transaction backups or
    // touching any live file. A staging/check failure is therefore a pure
    // no-op and can never restore an unrelated persistent config.json.bak.
    let tmp_validate = config_target.with_extension("rotate-candidate.json");
    if let Err(e) = write_config_for_validation(&tmp_validate, &candidate_doc) {
        let _ = std::fs::remove_file(&tmp_validate);
        return Err(e).context("failed to stage candidate config; live state was not changed");
    }
    let validate_result = backend.validate(&tmp_validate);
    let _ = std::fs::remove_file(&tmp_validate);
    validate_result.context(
        "candidate config failed sing-box check; live state and transaction backups were not changed",
    )?;

    let singbox_mgr = CompatibilityServiceManager::default();
    let sub_mgr = CompatibilityServiceManager::new("vpn-subscription");
    if !offline_mutation_allowed()
        && (!singbox_mgr.is_available()
            || !singbox_mgr.is_unit_installed()
            || !sub_mgr.is_available()
            || !sub_mgr.is_unit_installed())
    {
        bail!(
            "refusing REALITY rotation: both sing-box.service and vpn-subscription.service must \
             be installed and controllable so the key change can be committed atomically"
        );
    }

    // Back up the whole keyset before mutation. If preparing any backup
    // fails, remove only backups created by this attempt and leave live
    // state untouched.
    let mut prepared = Vec::new();
    let mut existed = Vec::new();
    for path in [&priv_path, &pub_path, &sid_path] {
        match backup_for_rotate(path) {
            Ok(backup) => {
                existed.push(backup.is_some());
                if let Some(backup) = backup {
                    prepared.push(backup);
                }
            }
            Err(error) => {
                for backup in prepared {
                    let _ = std::fs::remove_file(backup);
                }
                return Err(error).context(
                    "failed to prepare complete REALITY rotation backup; live state was not changed",
                );
            }
        }
    }

    let config_applied = std::cell::Cell::new(false);

    let rollback = |reason: &str| -> String {
        let mut restore_ok = true;
        for (p, did_exist) in [&priv_path, &pub_path, &sid_path]
            .into_iter()
            .zip(existed.iter().copied())
        {
            let result = if did_exist {
                restore_from_rotate_backup(p)
            } else {
                std::fs::remove_file(p)
                    .or_else(|error| {
                        if error.kind() == std::io::ErrorKind::NotFound {
                            Ok(())
                        } else {
                            Err(error)
                        }
                    })
                    .map_err(anyhow::Error::from)
            };
            if result.is_err() {
                restore_ok = false;
            }
        }
        // apply_config_atomically already keeps target_path.bak from
        // its OWN last successful write — restore from that if our
        // candidate config was ever actually applied.
        if config_applied.get() {
            let cfg_backup = config_backup_path(&config_target);
            if !cfg_backup.exists() || std::fs::copy(&cfg_backup, &config_target).is_err() {
                restore_ok = false;
            }
        }
        let singbox_recovered = !singbox_mgr.is_available()
            || !singbox_mgr.is_unit_installed()
            || singbox_mgr.reload_and_verify().is_ok();
        let sub_recovered = !sub_mgr.is_available()
            || !sub_mgr.is_unit_installed()
            || sub_mgr.reload_and_verify().is_ok();
        if restore_ok && singbox_recovered && sub_recovered {
            format!(
                "REALITY rotation FAILED ({reason}). Previous key material and config were \
                 restored and both services were verified healthy on the PREVIOUS key — no \
                 client-visible change occurred."
            )
        } else {
            format!(
                "REALITY rotation FAILED ({reason}). ROLLBACK ALSO FAILED (files_restored={restore_ok}, \
                 sing-box_recovered={singbox_recovered}, subscription_recovered={sub_recovered}). \
                 The server may be in a broken/inconsistent state. Manual intervention required: \
                 check `systemctl status sing-box vpn-subscription`, `journalctl -u sing-box -u \
                 vpn-subscription`, and compare {:?}/{:?}/{:?} against their .rotate-bak siblings.",
                priv_path, pub_path, sid_path
            )
        }
    };

    // Install new key material — reuses the same rename-with-preserved-
    // ownership helper the atomic config/user-store writers use, so the
    // existing root:sing-box / root:vpn-subscription ownership carries
    // forward automatically (docs/FINAL_PRODUCTION_AUDIT.md P0-2).
    if let Err(e) = install_rotated_key_file(&priv_path, &candidate_priv) {
        bail!(rollback(&format!("failed to install new private key: {e}")));
    }
    if let Err(e) = install_rotated_key_file(&pub_path, &candidate_pub) {
        bail!(rollback(&format!("failed to install new public key: {e}")));
    }
    if let Err(e) = install_rotated_key_file(&sid_path, &candidate_sid) {
        bail!(rollback(&format!("failed to install new short_id: {e}")));
    }

    if let Err(e) = apply_config_atomically(&candidate_doc, &config_target, |p| backend.validate(p))
    {
        bail!(rollback(&format!("failed to apply candidate config: {e}")));
    }
    config_applied.set(true);

    let singbox_reloaded_live = if singbox_mgr.is_available() && singbox_mgr.is_unit_installed() {
        if let Err(e) = singbox_mgr.reload_and_verify() {
            bail!(rollback(&format!("sing-box reload failed: {e}")));
        }
        true
    } else {
        println!("warning: systemctl/sing-box.service not available — config written but sing-box was NOT reloaded.");
        false
    };

    // The subscription service reads the REALITY public key/short_id
    // ONCE at startup (services/subscription/src/main.rs) and has no
    // config-reload path — it MUST be restarted, not just reloaded, or
    // it keeps advertising the OLD public key to every client that asks
    // for a subscription after this point (docs/FINAL_PRODUCTION_AUDIT.md
    // P0-5's core scenario).
    let sub_restarted_live = if sub_mgr.is_available() && sub_mgr.is_unit_installed() {
        if let Err(e) = sub_mgr.reload_and_verify() {
            bail!(rollback(&format!(
                "subscription service restart failed: {e}"
            )));
        }
        true
    } else {
        println!("warning: systemctl/vpn-subscription.service not available — new public key written but subscription service was NOT restarted.");
        false
    };

    // `reload_and_verify` on both units only proves each PROCESS stayed up
    // — it says nothing about whether the NEW REALITY key material actually
    // authenticates a real client. A rotation that installs a broken
    // keypair (or any other protocol-breaking change) would otherwise be
    // reported as a full success here on `is-active` alone. Only run this
    // when both services claim to be live already — if either isn't, the
    // "not fully reloaded live" branch below already refuses to claim
    // success and this self-test would be probing a server that may not
    // even have the candidate key loaded yet.
    let handshake_verification = if singbox_reloaded_live && sub_restarted_live {
        verify_reality_handshake_or_warn(cfg, &users, &candidate_reality, cfg.reality.listen_port)
    } else {
        HandshakeVerification::NotRun(
            "sing-box/vpn-subscription were not both confirmed live-reloaded".to_string(),
        )
    };
    if let HandshakeVerification::Ran(RealitySelfTestOutcome::HandshakeRejected) =
        &handshake_verification
    {
        bail!(rollback(
            "new REALITY key material failed a real handshake self-test — a real Hiddify \
             client using this same key material would be rejected identically"
        ));
    }

    // Commit: only now is it safe to discard the rollback material.
    for p in [&priv_path, &pub_path, &sid_path] {
        remove_rotate_backup(p);
    }

    if singbox_reloaded_live && sub_restarted_live {
        let handshake_line = match handshake_verification {
            HandshakeVerification::Ran(RealitySelfTestOutcome::Pass) => {
                "Handshake verification: PASSED — a real handshake self-test against the new \
                 key material succeeded."
                    .to_string()
            }
            HandshakeVerification::Ran(RealitySelfTestOutcome::Inconclusive) => {
                "Handshake verification: INCONCLUSIVE — a real handshake was attempted but its \
                 result could not be read as pass or fail; inspect sing-box logs and re-run \
                 'vpn doctor --protocol' before assuming clients can connect."
                    .to_string()
            }
            HandshakeVerification::NotRun(reason) => format!(
                "Handshake verification: NOT RUN ({reason}) — this does NOT confirm a real \
                 client can connect with the new key material; re-run 'vpn doctor --protocol' \
                 once that's possible."
            ),
            HandshakeVerification::Ran(RealitySelfTestOutcome::HandshakeRejected) => {
                unreachable!("HandshakeRejected already bailed out above")
            }
        };
        println!(
            "REALITY key rotated and applied. {handshake_line} Every existing client's REALITY \
             profile is now invalid (server public key changed) until re-imported. \
             Subscription URLs are unaffected and still fetch/refresh normally; Hysteria2 \
             profiles are unaffected."
        );
    } else {
        println!(
            "REALITY key rotated on disk, but NOT fully reloaded live (see warning(s) above). \
             The RUNNING server may still accept the OLD public key until sing-box is actually \
             reloaded and vpn-subscription actually restarted — do not treat existing clients \
             as invalidated yet."
        );
    }
    Ok(())
}

/// Coordinated Hysteria2 obfuscation-password enable/rotate: generate
/// candidate -> render+validate candidate config with the REAL sing-box
/// binary -> atomically install the password file -> apply config ->
/// reload sing-box -> restart subscription (it caches the obfs password
/// at startup, same as REALITY's public key/short_id — see
/// `cmd_reality_rotate`'s doc comment for why a reload alone is not
/// enough) -> verify both -> commit. Any failure after the password file
/// starts being touched triggers a full rollback, mirroring
/// `cmd_reality_rotate` exactly (same helpers, same guarantees) but for
/// the single obfuscation secret instead of the REALITY keyset.
fn cmd_hysteria_obfs_rotate(cfg: &DeploymentConfig) -> Result<()> {
    let obfs_path = cfg.hysteria_obfs_password_file();
    let config_target = cfg.singbox_config_file();

    if !cfg.singbox_binary.exists() {
        bail!(
            "cannot safely enable/rotate Hysteria2 obfuscation: sing-box binary not found at \
             {:?} — this requires validating the candidate config with the real binary before \
             installing new material (never rotate blind).",
            cfg.singbox_binary
        );
    }

    std::fs::create_dir_all(cfg.reality_dir())?;
    println!("Enabling/rotating Hysteria2 obfuscation password...");
    let candidate_password = credentials::generate_hysteria2_obfs_password();

    let reality = load_reality_params(cfg)
        .context("loading current REALITY parameters (required to render a candidate config)")?;
    let mut candidate_hysteria = load_hysteria_params(cfg);
    candidate_hysteria.obfs_password = Some(SecretString::new(candidate_password.clone()));
    let users = store::load_users(&cfg.users_file())?;
    let ports = ServerPorts {
        vless_reality_port: cfg.reality.listen_port,
        hysteria2_port: cfg.hysteria2.listen_port,
    };
    let now = UnixSeconds::now().0 as i64;
    let candidate_doc =
        render_singbox_server_config(&users, &reality, &candidate_hysteria, ports, now);

    let backend = SingBoxBackend {
        binary_path: cfg.singbox_binary.clone(),
    };

    // Validate BEFORE touching any live file or backup — a staging/check
    // failure is a pure no-op (same discipline as `cmd_reality_rotate`).
    let tmp_validate = config_target.with_extension("obfs-rotate-candidate.json");
    if let Err(e) = write_config_for_validation(&tmp_validate, &candidate_doc) {
        let _ = std::fs::remove_file(&tmp_validate);
        return Err(e).context("failed to stage candidate config; live state was not changed");
    }
    let validate_result = backend.validate(&tmp_validate);
    let _ = std::fs::remove_file(&tmp_validate);
    validate_result.context(
        "candidate config failed sing-box check; live state and transaction backups were not changed",
    )?;

    let singbox_mgr = CompatibilityServiceManager::default();
    let sub_mgr = CompatibilityServiceManager::new("vpn-subscription");
    if !offline_mutation_allowed()
        && (!singbox_mgr.is_available()
            || !singbox_mgr.is_unit_installed()
            || !sub_mgr.is_available()
            || !sub_mgr.is_unit_installed())
    {
        bail!(
            "refusing Hysteria2 obfuscation rotation: both sing-box.service and \
             vpn-subscription.service must be installed and controllable so the change can be \
             committed atomically"
        );
    }

    let existed = obfs_path.exists();
    let backup = match backup_for_rotate(&obfs_path) {
        Ok(b) => b,
        Err(e) => {
            return Err(e).context(
                "failed to prepare obfs-password rotation backup; live state was not changed",
            )
        }
    };

    let config_applied = std::cell::Cell::new(false);
    let rollback = |reason: &str| -> String {
        let mut restore_ok = true;
        let result = if existed {
            restore_from_rotate_backup(&obfs_path)
        } else {
            std::fs::remove_file(&obfs_path)
                .or_else(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .map_err(anyhow::Error::from)
        };
        if result.is_err() {
            restore_ok = false;
        }
        if config_applied.get() {
            let cfg_backup = config_backup_path(&config_target);
            if !cfg_backup.exists() || std::fs::copy(&cfg_backup, &config_target).is_err() {
                restore_ok = false;
            }
        }
        let singbox_recovered = !singbox_mgr.is_available()
            || !singbox_mgr.is_unit_installed()
            || singbox_mgr.reload_and_verify().is_ok();
        let sub_recovered = !sub_mgr.is_available()
            || !sub_mgr.is_unit_installed()
            || sub_mgr.reload_and_verify().is_ok();
        if restore_ok && singbox_recovered && sub_recovered {
            format!(
                "Hysteria2 obfuscation rotation FAILED ({reason}). Previous state was restored \
                 and both services were verified healthy on it — no client-visible change occurred."
            )
        } else {
            format!(
                "Hysteria2 obfuscation rotation FAILED ({reason}). ROLLBACK ALSO FAILED \
                 (obfs_password_restored={restore_ok}, sing-box_recovered={singbox_recovered}, \
                 subscription_recovered={sub_recovered}). The server may be in a broken/\
                 inconsistent state. Manual intervention required: check `systemctl status \
                 sing-box vpn-subscription`, `journalctl -u sing-box -u vpn-subscription`, and \
                 compare {obfs_path:?} against its .rotate-bak sibling."
            )
        }
    };

    if let Err(e) = install_rotated_key_file(&obfs_path, &candidate_password) {
        if let Some(b) = backup {
            let _ = std::fs::remove_file(b);
        }
        bail!("failed to install new obfuscation password: {e}; live state was not changed");
    }
    if !existed {
        // `install_rotated_key_file` preserves an EXISTING target's
        // owner/group but has nothing to preserve on a first write, so it
        // lands root:root — use the same real chown+chmod
        // `cmd_restore` relies on (not just chmod) so `vpn-subscription`
        // can actually read this on its very first enable, without
        // depending on a later `install.sh` re-run. Safe to require the
        // group to exist here (unlike `cmd_init`'s fresh-install path):
        // this command already hard-requires both services to be
        // installed and controllable, which in practice means the
        // installer already created the `vpn-subscription` system group.
        if let Err(e) = apply_restored_file_policy(&obfs_path, "vpn-subscription") {
            bail!(rollback(&format!(
                "failed to set ownership/permissions on new obfuscation password file: {e}"
            )));
        }
    }

    if let Err(e) = apply_config_atomically(&candidate_doc, &config_target, |p| backend.validate(p))
    {
        bail!(rollback(&format!("failed to apply candidate config: {e}")));
    }
    config_applied.set(true);

    let singbox_reloaded_live = if singbox_mgr.is_available() && singbox_mgr.is_unit_installed() {
        if let Err(e) = singbox_mgr.reload_and_verify() {
            bail!(rollback(&format!("sing-box reload failed: {e}")));
        }
        true
    } else {
        println!("warning: systemctl/sing-box.service not available — config written but sing-box was NOT reloaded.");
        false
    };

    // Same reasoning as `cmd_reality_rotate`: vpn-subscription reads the
    // obfs password ONCE at startup into `AppState.endpoints` and has no
    // config-reload path.
    let sub_restarted_live = if sub_mgr.is_available() && sub_mgr.is_unit_installed() {
        if let Err(e) = sub_mgr.reload_and_verify() {
            bail!(rollback(&format!(
                "subscription service restart failed: {e}"
            )));
        }
        true
    } else {
        println!("warning: systemctl/vpn-subscription.service not available — new obfuscation password written but subscription service was NOT restarted.");
        false
    };

    remove_rotate_backup(&obfs_path);

    if singbox_reloaded_live && sub_restarted_live {
        println!(
            "Hysteria2 obfuscation password enabled/rotated and applied. Every existing \
             client's Hysteria2 profile is now invalid until re-imported — the obfuscation \
             password changed."
        );
    } else {
        println!(
            "Hysteria2 obfuscation password rotated on disk, but NOT fully reloaded live (see \
             warning(s) above). The RUNNING server may still accept the OLD obfuscation \
             password until sing-box is actually reloaded and vpn-subscription actually \
             restarted — do not treat existing Hysteria2 clients as invalidated yet."
        );
    }
    Ok(())
}

fn write_config_for_validation(path: &std::path::Path, doc: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(doc)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

/// Overwrite `target` (which already exists — this is only used for
/// rotating already-installed key files) with `contents`, preserving the
/// existing owner/group exactly, via the same tmp-file+rename+
/// preserve-ownership pattern as `compat_config::store`/`server`. A bare
/// `std::fs::write` would truncate-in-place (not atomic) and a naive
/// tmp+rename would silently drop back to the writing process's own
/// group, both of which this project treats as bugs
/// (docs/FINAL_PRODUCTION_AUDIT.md P0-2) — this is the same fix applied
/// to the same class of write.
fn install_rotated_key_file(target: &std::path::Path, contents: &str) -> Result<()> {
    let mut tmp = target.as_os_str().to_owned();
    tmp.push(".rotate-tmp");
    let tmp_path = std::path::PathBuf::from(tmp);
    write_secret_file(&tmp_path, contents)?;
    // Preserve BOTH the existing mode and owner/group across the swap —
    // `write_secret_file` always writes 0600, but e.g. public.key/
    // short_id.txt are 0640 root:vpn-subscription (see
    // deploy/almalinux/install.sh's ownership matrix), and a bare rename
    // would otherwise silently downgrade them to 0600 root:root.
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(target) {
        std::fs::set_permissions(&tmp_path, meta.permissions())?;
    }
    compat_config::ownership::preserve_ownership_before_rename(&tmp_path, target)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    std::fs::rename(&tmp_path, target)?;
    Ok(())
}

fn extract_field(text: &str, field: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix(&format!("{field}:"))
            .or_else(|| line.strip_prefix(&format!("{field} ")))
            .map(|s| s.trim().to_string())
    })
}

#[cfg(unix)]
fn write_secret_file(path: &std::path::Path, contents: &str) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())?;
    // Durability matters here specifically because `config.json` IS fsynced
    // (see compat-config's `apply_config_atomically`). Without this, a power
    // loss just after a rotation can persist a config.json holding the NEW
    // private key while the key files revert to the OLD one — the more
    // durable write landing and the less durable one not.
    f.sync_all()?;
    Ok(())
}

/// Best-effort fsync of a directory, so a rename into it is durable. A
/// rename is not implicitly fsynced on Linux; without this the directory
/// entry can be lost even though the file contents were synced.
fn fsync_dir(dir: &std::path::Path) {
    if let Ok(handle) = std::fs::File::open(dir) {
        let _ = handle.sync_all();
    }
}

#[cfg(not(unix))]
fn write_secret_file(path: &std::path::Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;
    Ok(())
}

fn load_reality_params(cfg: &DeploymentConfig) -> Result<RealityServerParams> {
    let private_key_hex = std::fs::read_to_string(cfg.reality_private_key_file())
        .context("reality private key missing — run `vpn-admin init` first")?
        .trim()
        .to_string();
    let public_key_hex = std::fs::read_to_string(cfg.reality_public_key_file())?
        .trim()
        .to_string();
    credentials::validate_reality_keypair(&private_key_hex, &public_key_hex)
        .map_err(anyhow::Error::msg)
        .context("REALITY private.key/public.key coherence check failed")?;
    let short_id = std::fs::read_to_string(cfg.reality_dir().join("short_id.txt"))?
        .trim()
        .to_string();
    Ok(RealityServerParams {
        private_key_hex: SecretString::new(private_key_hex),
        public_key_hex,
        short_ids: vec![short_id],
        handshake_server: cfg.reality.handshake_server.clone(),
        handshake_port: cfg.reality.handshake_port,
    })
}

fn load_hysteria_params(cfg: &DeploymentConfig) -> Hysteria2ServerParams {
    let masquerade_dir = cfg.hysteria_dir().join("masquerade");
    // Absent on deployments that predate obfuscation support, or that were
    // installed before `cmd_init`/`cmd_hysteria_obfs_rotate` ran — reading
    // is best-effort, falling back to disabled rather than a hard failure
    // (a missing optional obfuscation secret must never block rendering
    // the rest of a valid config).
    let obfs_password = std::fs::read_to_string(cfg.hysteria_obfs_password_file())
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(SecretString::new);
    Hysteria2ServerParams {
        tls_cert_path: cfg
            .hysteria_dir()
            .join("cert.pem")
            .to_string_lossy()
            .into_owned(),
        tls_key_path: cfg
            .hysteria_dir()
            .join("key.pem")
            .to_string_lossy()
            .into_owned(),
        obfs_password,
        // Only advertise masquerade if the directory actually exists —
        // installer creates it with a placeholder file; local dev/test
        // setups that skip that step get no masquerade rather than a
        // sing-box config referencing a missing path.
        masquerade_dir_path: masquerade_dir
            .exists()
            .then(|| masquerade_dir.to_string_lossy().into_owned()),
        up_mbps: cfg.hysteria2.up_mbps,
        down_mbps: cfg.hysteria2.down_mbps,
    }
}

/// Render + validate + atomically apply the sing-box config from the
/// current user store, then reload the running service and verify it
/// came back up healthy. Never overwrites a known-working config with an
/// invalid one (spec §16), and never claims a user mutation (create/
/// disable/enable/remove/rotate) succeeded while the running server
/// still has the old credentials loaded — see
/// docs/PRODUCTION_HARDENING_PLAN.md #4/#7.
///
/// Authorization mutations are fail-closed unless an offline operator
/// explicitly sets `VPN1_ALLOW_OFFLINE_MUTATION=1`. Plain `render-config`
/// remains usable during installation before systemd is available.
fn offline_mutation_allowed() -> bool {
    std::env::var("VPN1_ALLOW_OFFLINE_MUTATION").as_deref() == Ok("1")
}

fn applied_config_stamp_path(target: &std::path::Path) -> PathBuf {
    target.with_extension("applied.sha256")
}

fn rendered_config_fingerprint(doc: &serde_json::Value) -> Result<String> {
    let canonical = serde_json::to_string(doc)?;
    Ok(credentials::hash_token(&canonical))
}

fn commit_applied_config_stamp(target: &std::path::Path, fingerprint: &str) -> Result<()> {
    let stamp = applied_config_stamp_path(target);
    let tmp = stamp.with_extension(format!("tmp.{}", std::process::id()));
    write_secret_file(&tmp, fingerprint)?;
    std::fs::rename(&tmp, &stamp)?;
    if let Some(parent) = stamp.parent() {
        fsync_dir(parent);
    }
    Ok(())
}

/// Returns whether the change was actually pushed to a LIVE, reloaded
/// sing-box process — `Ok(false)` covers every degraded path (missing
/// binary, missing keys, systemctl/unit unavailable) where the config
/// was at most written to disk, never proven live. Callers that print a
/// blast-radius claim ("already-imported profile rejected on next
/// handshake") must gate that claim on this being `true` — it is only
/// true in production; the various early-return warning paths below
/// are reachable in real deployments only when an operator explicitly
/// bypasses the live-apply requirement (`VPN1_ALLOW_OFFLINE_MUTATION=1`,
/// documented as dev/offline-only), or in local/CI dev.
fn render_and_apply_singbox_config(
    cfg: &DeploymentConfig,
    users: &[CompatUser],
    require_live_apply: bool,
) -> Result<bool> {
    let reality = match load_reality_params(cfg) {
        Ok(r) => r,
        Err(e) => {
            if require_live_apply && !offline_mutation_allowed() {
                return Err(e).context(
                    "refusing to commit an authorization mutation without a complete, coherent \
                     REALITY keyset; run `vpn-admin init` first",
                );
            }
            println!("warning: skipping sing-box config render/apply: {e}");
            return Ok(false);
        }
    };
    let hysteria = load_hysteria_params(cfg);
    let ports = ServerPorts {
        vless_reality_port: cfg.reality.listen_port,
        hysteria2_port: cfg.hysteria2.listen_port,
    };
    let now = UnixSeconds::now().0 as i64;
    let doc = render_singbox_server_config(users, &reality, &hysteria, ports, now);
    let candidate_fingerprint = rendered_config_fingerprint(&doc)?;

    let target = cfg.singbox_config_file();
    if !cfg.singbox_binary.exists() {
        if require_live_apply && !offline_mutation_allowed() {
            bail!(
                "refusing to commit an authorization mutation: sing-box binary not found at \
                 {:?}, so the candidate config cannot be validated or loaded. For an intentional \
                 offline/dev-only mutation set VPN1_ALLOW_OFFLINE_MUTATION=1 explicitly.",
                cfg.singbox_binary
            );
        }
        println!(
            "warning: {:?} not found; wrote nothing. Install sing-box, then run `vpn-admin render-config`.",
            cfg.singbox_binary
        );
        return Ok(false);
    }
    let backend = SingBoxBackend {
        binary_path: cfg.singbox_binary.clone(),
    };
    let mgr = CompatibilityServiceManager::default();
    let service_available = mgr.is_available() && mgr.is_unit_installed();
    if require_live_apply && !service_available && !offline_mutation_allowed() {
        bail!(
            "refusing to commit an authorization mutation: systemctl/sing-box.service is not \
             available, so vpn-admin cannot prove the running authorization state changed. \
             For an intentional offline/dev-only mutation set VPN1_ALLOW_OFFLINE_MUTATION=1."
        );
    }

    let target_already_matches = std::fs::read(&target)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .is_some_and(|current| current == doc);
    let applied_stamp_matches = std::fs::read_to_string(applied_config_stamp_path(&target))
        .is_ok_and(|stamp| stamp.trim() == candidate_fingerprint);
    if target_already_matches && applied_stamp_matches && service_available && mgr.is_active() {
        println!("sing-box authorization config is already current; no reload needed.");
        return Ok(true);
    }

    apply_config_atomically(&doc, &target, |p| backend.validate(p))
        .context("applying sing-box config")?;
    println!("sing-box config updated at {target:?} (validated by `sing-box check`).");

    if !mgr.is_available() {
        println!(
            "warning: systemctl not available; config written but sing-box was NOT reloaded. \
             On a real deployment this means the change has not taken effect yet — run \
             `systemctl reload-or-restart sing-box` manually."
        );
        return Ok(false);
    }
    if !mgr.is_unit_installed() {
        println!(
            "warning: sing-box.service is not installed on this host (expected in CI/local \
             dev); config written but not reloaded. On a real deployment this means the \
             change has not taken effect yet — run `deploy/almalinux/install.sh` (or \
             `systemctl reload-or-restart sing-box` if the unit already exists) manually."
        );
        return Ok(false);
    }

    if let Err(reload_err) = mgr.reload_and_verify() {
        let backup = config_backup_path(&target);
        let restored = backup.exists() && std::fs::copy(&backup, &target).is_ok();
        let recovery_reload_ok = restored && mgr.reload_and_verify().is_ok();
        bail!(
            "sing-box reload failed after applying the new config ({reload_err}). \
             The requested change did NOT take effect on the running server. \
             {}",
            if recovery_reload_ok {
                "Previous working config was restored and the service was reloaded back to it \
                 successfully — the server is running the PREVIOUS configuration now."
            } else {
                "Attempted to restore the previous config but that ALSO failed to reload — \
                 the service may be in a broken state. Manual intervention required: check \
                 `systemctl status sing-box` and `journalctl -u sing-box`."
            }
        );
    }
    // `reload_and_verify` only proves the sing-box PROCESS stayed up — it
    // is `systemctl is-active`, which passes for a syntactically valid but
    // protocol-broken REALITY config exactly as readily as for a correct
    // one (sing-box does not itself validate that its REALITY key material
    // can authenticate anything). Without this, a transaction can commit a
    // config that no real Hiddify client can ever complete a handshake
    // against as "reloaded and verified active." Best-effort: only a
    // definitive `HandshakeRejected` verdict blocks the commit; `None`
    // (no test user / no sing-box binary / harness setup failure) and
    // `Inconclusive` do not, since this self-test cannot always reach a
    // verdict (see `run_reality_client_selftest`'s doc comment) and must
    // not turn an environmental limitation into a false failure here.
    let handshake_verification =
        verify_reality_handshake_or_warn(cfg, users, &reality, ports.vless_reality_port);
    if let HandshakeVerification::Ran(RealitySelfTestOutcome::HandshakeRejected) =
        &handshake_verification
    {
        let backup = config_backup_path(&target);
        let restored = backup.exists() && std::fs::copy(&backup, &target).is_ok();
        let recovery_reload_ok = restored && mgr.reload_and_verify().is_ok();
        bail!(
            "sing-box reloaded and stayed active, but a real REALITY handshake self-test \
             against the just-applied config FAILED — a real Hiddify client using this same \
             key material would be rejected identically. The requested change did NOT take \
             effect safely. {}",
            if recovery_reload_ok {
                "Previous working config was restored and the service was reloaded back to it \
                 successfully — the server is running the PREVIOUS configuration now."
            } else {
                "Attempted to restore the previous config but that ALSO failed to reload — \
                 the service may be in a broken state. Manual intervention required: check \
                 `systemctl status sing-box` and `journalctl -u sing-box`."
            }
        );
    }
    commit_applied_config_stamp(&target, &candidate_fingerprint)
        .context("recording the config version verified live")?;
    let handshake_line = match handshake_verification {
        HandshakeVerification::Ran(RealitySelfTestOutcome::Pass) => {
            "including a real REALITY handshake self-test that PASSED".to_string()
        }
        HandshakeVerification::Ran(RealitySelfTestOutcome::Inconclusive) => {
            "a real REALITY handshake self-test was attempted but its result was INCONCLUSIVE \
             — this does NOT confirm a real client can connect; re-run 'vpn doctor --protocol'"
                .to_string()
        }
        HandshakeVerification::NotRun(reason) => format!(
            "no REALITY handshake self-test was run ({reason}) — this does NOT confirm a real \
             client can connect; re-run 'vpn doctor --protocol' once that's possible"
        ),
        HandshakeVerification::Ran(RealitySelfTestOutcome::HandshakeRejected) => {
            unreachable!("HandshakeRejected already bailed out above")
        }
    };
    println!("sing-box reloaded and verified active ({handshake_line}).");
    Ok(true)
}

#[cfg(unix)]
fn apply_restored_file_policy(path: &std::path::Path, group: &str) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
        .with_context(|| format!("setting restored-file mode on {path:?}"))?;
    // Non-root unit tests cannot change ownership. Production restore is
    // root-only and must set the exact service-readable owner/group even
    // when the destination did not exist before restore.
    if unsafe { libc::geteuid() } == 0 {
        let name = CString::new(group)?;
        let record = unsafe { libc::getgrnam(name.as_ptr()) };
        if record.is_null() {
            bail!("required service group {group:?} does not exist");
        }
        let gid = unsafe { (*record).gr_gid };
        std::os::unix::fs::chown(path, Some(0), Some(gid))
            .with_context(|| format!("setting root:{group} ownership on {path:?}"))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_restored_file_policy(_path: &std::path::Path, _group: &str) -> Result<()> {
    Ok(())
}

fn regenerate_singbox_config(cfg: &DeploymentConfig, require_live_apply: bool) -> Result<bool> {
    let users = store::load_users(&cfg.users_file())?;
    render_and_apply_singbox_config(cfg, &users, require_live_apply)
}

/// `applied` distinguishes a genuine no-op ("nothing changed") from a
/// change that was actually written+reloaded+verified live — both are
/// `true`. `false` means reconciliation was attempted (the rendered
/// config differs from what's live) but could not be fully applied; see
/// `require_applied`'s doc comment on `Commands::RenderConfig` for what
/// that does with this distinction.
fn cmd_render_config(cfg: &DeploymentConfig, require_applied: bool) -> Result<()> {
    let applied = regenerate_singbox_config(cfg, false)?;
    if !applied && require_applied {
        bail!(
            "reconciliation was attempted (the rendered sing-box config differs from what's \
             live) but could not be fully applied — see the warning(s) above for the specific \
             cause. Expired/disabled users' authorization may still be live on the running \
             server. This is not a transient no-op; investigate before the next scheduled \
             reconciliation."
        );
    }
    Ok(())
}

/// Read-only report of `deployment.toml`/`users.json`'s on-disk schema
/// state. `cfg` was already successfully loaded by `main()` before this
/// runs — a deployment.toml with a schema_version newer than this binary
/// supports never reaches here at all (`DeploymentConfig::load` already
/// refused it with a clear error; that IS the "INVALID" outcome for
/// deployment.toml, just surfaced earlier in the call chain rather than
/// through this command's own formatting).
///
/// Exit code doubles as the machine-readable "what mode did this
/// detect" signal `deploy/almalinux/update.sh`/`install.sh` act on:
/// 0 = nothing to do (FRESH or CURRENT), 2 = MIGRATION_REQUIRED (legacy
/// schema found, run `config migrate`), 3 = INVALID (corrupted or
/// unsupported-future state — needs a backup restore or a newer
/// vpn-admin, not something `config migrate` can fix).
fn cmd_config_validate(cfg: &DeploymentConfig, config_path: &std::path::Path) -> Result<()> {
    use compat_config::deployment::DEPLOYMENT_SCHEMA_VERSION;
    use compat_config::store::UsersSchemaState;

    let mut invalid = false;
    let mut migration_required = false;

    if cfg.schema_version == 0 {
        println!("deployment.toml ({config_path:?}): LEGACY (no schema_version marker)");
        migration_required = true;
    } else {
        println!(
            "deployment.toml ({config_path:?}): CURRENT (schema_version {DEPLOYMENT_SCHEMA_VERSION})"
        );
    }

    let users_path = cfg.users_file();
    match store::detect_users_schema(&users_path) {
        UsersSchemaState::Missing => {
            println!("users.json ({users_path:?}): MISSING (fresh install, no users yet)")
        }
        UsersSchemaState::Current => {
            println!("users.json ({users_path:?}): CURRENT")
        }
        UsersSchemaState::Legacy => {
            println!("users.json ({users_path:?}): LEGACY (pre-versioning bare-array format)");
            migration_required = true;
        }
        UsersSchemaState::Future(found) => {
            println!(
                "users.json ({users_path:?}): INVALID (schema_version {found} is newer than this vpn-admin supports)"
            );
            invalid = true;
        }
        UsersSchemaState::Corrupted(msg) => {
            println!("users.json ({users_path:?}): INVALID (corrupted: {msg})");
            invalid = true;
        }
    }

    if invalid {
        println!("MODE: INVALID");
        println!("Needs manual intervention: restore from a backup (see `vpn-admin restore`), or install a vpn-admin new enough to understand this state. `config migrate` cannot fix this — it only moves forward.");
        std::process::exit(3);
    }
    if migration_required {
        println!("MODE: MIGRATION_REQUIRED");
        println!("Run `vpn-admin config migrate` to normalize the state above.");
        std::process::exit(2);
    }
    println!("MODE: OK");
    Ok(())
}

/// Migrate `deployment.toml`/`users.json` to the schema this vpn-admin
/// understands. See `ConfigCommands::Migrate`'s doc comment for the
/// backup/validate/commit contract.
fn cmd_config_migrate(cfg: &DeploymentConfig, config_path: &std::path::Path) -> Result<()> {
    use compat_config::deployment::{migrate_deployment_toml, DeploymentMigrationOutcome};
    use compat_config::store::{migrate_users, UsersMigrationOutcome};

    match migrate_deployment_toml(config_path)
        .with_context(|| format!("migrating {config_path:?}"))?
    {
        DeploymentMigrationOutcome::Missing => {
            println!("deployment.toml ({config_path:?}): missing, nothing to migrate.")
        }
        DeploymentMigrationOutcome::AlreadyCurrent => {
            println!("deployment.toml ({config_path:?}): already current, no changes made.")
        }
        DeploymentMigrationOutcome::Migrated { backup_path } => {
            println!(
                "deployment.toml ({config_path:?}): migrated. Pre-migration backup: {backup_path:?}"
            );
        }
    }

    let users_path = cfg.users_file();
    match migrate_users(&users_path).with_context(|| format!("migrating {users_path:?}"))? {
        UsersMigrationOutcome::Missing => {
            println!("users.json ({users_path:?}): missing, nothing to migrate.")
        }
        UsersMigrationOutcome::AlreadyCurrent => {
            println!("users.json ({users_path:?}): already current, no changes made.")
        }
        UsersMigrationOutcome::Migrated { backup_path } => {
            println!(
                "users.json ({users_path:?}): migrated. Pre-migration backup: {backup_path:?}"
            );
        }
    }

    // Requirement: validate any generated sing-box configuration
    // affected by the migration. Re-reads deployment.toml fresh (the
    // in-memory `cfg` predates the migration above) so this reflects
    // what a subsequent command will actually load; reuses the same
    // validate-then-apply path every other mutating command goes
    // through (SingBoxBackend::validate via render_and_apply_singbox_config)
    // rather than a second, bespoke check.
    let reloaded = DeploymentConfig::load(config_path)
        .with_context(|| format!("reloading {config_path:?} after migration"))?;
    match regenerate_singbox_config(&reloaded, false) {
        Ok(_) => println!("sing-box config re-validated against migrated state: OK."),
        Err(e) => {
            println!(
                "warning: could not re-validate the sing-box config against migrated state: {e} \
                 (this is expected if sing-box/REALITY keys are not set up yet, e.g. before the \
                 first `vpn-admin init`)"
            );
        }
    }

    println!("MODE: OK (migration complete)");
    Ok(())
}

/// The URL printed/QR-encoded and explicitly labeled "Hiddify
/// subscription URL" everywhere in this CLI. It MUST carry
/// `?format=hiddify` explicitly: a bare `/sub/<token>` (no `format`
/// query parameter) is served by services/subscription as native
/// sing-box JSON (see services/subscription/src/lib.rs), not the
/// Hiddify/share-link representation — Hiddify's bundled sing-box fork
/// strict-unmarshals that JSON and silently drops fields/outbounds it
/// doesn't recognize (a version-coupling failure mode confirmed against
/// real hiddify-app issues), which is exactly the "fetch succeeds, never
/// dials" failure observed in production. `?format=hiddify` serves a
/// plain vless://+hysteria2:// share-link list instead, which Hiddify's
/// `ray2sing` importer builds outbounds from directly rather than
/// strict-unmarshalling a full sing-box config — the more broadly
/// compatible representation for this client.
///
/// services/subscription's own test
/// `hiddify_format_is_identical_to_uri_format` and
/// `hiddify_advertised_url_matches_served_format` (apps/admin/tests/
/// cli.rs) both assert this stays true — do not remove the query
/// parameter without updating both.
fn subscription_url(cfg: &DeploymentConfig, token: &str) -> String {
    format!(
        "https://{}:{}/sub/{}?format=hiddify",
        cfg.subscription_host, cfg.subscription.public_port, token
    )
}

/// The native sing-box JSON subscription URL (no `format` parameter maps
/// to this — see services/subscription/src/lib.rs), for sing-box-core
/// clients that are NOT Hiddify (e.g. sing-box itself, or another
/// front-end that consumes raw sing-box config directly).
fn subscription_url_singbox(cfg: &DeploymentConfig, token: &str) -> String {
    format!(
        "https://{}:{}/sub/{}?format=singbox",
        cfg.subscription_host, cfg.subscription.public_port, token
    )
}

/// Print a terminal QR code encoding `data`. QR codes intentionally
/// encode only the subscription URL, never the full server
/// configuration (spec §6). PNG file output is not implemented — kept
/// out to avoid pulling in an image-encoding dependency for a
/// convenience feature; terminal/unicode rendering covers the primary
/// onboarding flow (admin runs this over SSH and the end user scans the
/// terminal, or the admin re-types/pastes the URL shown alongside it).
fn print_qr(data: &str) -> Result<()> {
    let code = qrcode::QrCode::new(data.as_bytes()).context("encoding QR code")?;
    let image = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    println!("{image}");
    Ok(())
}

fn cmd_user_create(
    cfg: &DeploymentConfig,
    name: &str,
    expires_at: Option<i64>,
    qr: bool,
    json: bool,
) -> Result<()> {
    let mut users = store::load_users(&cfg.users_file())?;
    let previous_users = users.clone();
    // 128-bit CSPRNG id (spec: do not reuse the 32-bit REALITY short_id
    // generator as a user id). Collision detection is defense in depth
    // on top of 128 bits of entropy, not a load-bearing check.
    let mut id = credentials::generate_user_id();
    while users.iter().any(|u| u.id == id) {
        id = credentials::generate_user_id();
    }
    let token = credentials::generate_subscription_token();
    let user = CompatUser {
        id: id.clone(),
        name: name.to_string(),
        enabled: true,
        vless_uuid: credentials::generate_uuid_v4(),
        hysteria2_password: SecretString::new(credentials::generate_hysteria2_password()),
        subscription_token_hash_hex: credentials::hash_token(&token),
        created_at: UnixSeconds::now().0 as i64,
        expires_at,
    };
    users.push(user);
    apply_users_and_save(cfg, &previous_users, &users)?;

    let url = subscription_url(cfg, &token);
    if json {
        let out = serde_json::json!({
            "id": id,
            "name": name,
            "enabled": true,
            "subscription_url": url,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    println!("User ID:");
    println!("  {id}");
    println!();
    println!("IMPORTANT:");
    println!("  The User ID above is NOT a credential and NOT your subscription token.");
    println!("  It only names the account for `vpn-admin user <id> ...` commands.");
    println!("  Never put the User ID after /sub/ — that endpoint takes the subscription");
    println!("  token below, and a User ID there will always 404.");
    println!();
    println!("Hiddify subscription URL (this IS the credential — treat it like a password):");
    println!("  {url}");
    println!();
    println!(
        "This URL is shown once and cannot be recovered later — use \
         `vpn-admin user rotate-token {id}` to mint a new one if lost."
    );
    println!();
    println!(
        "Native sing-box clients (not Hiddify) should use the ?format=singbox variant instead:"
    );
    println!("  {}", subscription_url_singbox(cfg, &token));
    if qr {
        println!();
        println!("Scan this QR code in Hiddify (Add profile -> Scan QR code):");
        print_qr(&url)?;
    }
    println!();
    println!("Client: Hiddify (iOS/Android/MagicOS/Linux/Windows/macOS).");
    println!();
    println!("iPhone setup:");
    println!("  1. Install Hiddify from the App Store.");
    println!("  2. Scan the QR code above, or paste the subscription URL (Add profile).");
    println!("  3. When iOS asks \"Would Like to Add VPN Configurations\", tap Allow.");
    println!("  4. In Hiddify's settings, confirm Service Mode is VPN/TUN mode (not");
    println!("     \"Proxy Only\" — that mode never shows the iOS VPN icon or changes your");
    println!("     public IP by design).");
    println!("  5. Connect to REALITY first (the deterministic default).");
    println!("  6. Verify the iOS status bar/Control Center shows the VPN indicator, then");
    println!("     check your public IP changed to this server's IP.");
    println!("  7. Then test Hysteria2 the same way, selected explicitly.");
    println!();
    println!("Full walkthrough and troubleshooting: docs/clients/HIDDIFY_IOS.md");
    println!("Run `vpn-admin doctor --client` for an interactive on-device acceptance checklist.");
    Ok(())
}

fn cmd_user_list(cfg: &DeploymentConfig) -> Result<()> {
    let users = store::load_users(&cfg.users_file())?;
    println!("{:<20} {:<16} {:<8}", "ID", "NAME", "ENABLED");
    for u in &users {
        println!(
            "{:<20} {:<16} {:<8}",
            u.id,
            u.name,
            if u.enabled { "yes" } else { "no" }
        );
    }
    Ok(())
}

fn find_user_mut<'a>(users: &'a mut [CompatUser], id: &str) -> Result<&'a mut CompatUser> {
    users
        .iter_mut()
        .find(|u| u.id == id)
        .ok_or_else(|| anyhow::anyhow!("no such user: {id}"))
}

fn cmd_user_set_enabled(cfg: &DeploymentConfig, id: &str, enabled: bool) -> Result<()> {
    let mut users = store::load_users(&cfg.users_file())?;
    let previous_users = users.clone();
    find_user_mut(&mut users, id)?.enabled = enabled;
    let went_live = apply_users_and_save(cfg, &previous_users, &users)?;
    println!("{id}: enabled={enabled}");
    if !enabled {
        if went_live {
            println!(
                "This user is dropped from the rendered sing-box authorization config \
                 immediately: their REALITY and Hysteria2 credentials are both rejected on the \
                 next handshake attempt, and their subscription URL now 404s. This is the \
                 widest-blast-radius revocation short of `user remove` — unlike token/credential \
                 rotation, it stops an already-imported profile from connecting at all, with no \
                 re-import window."
            );
        } else {
            println!(
                "WARNING: the new config was written but NOT reloaded live (see the warning \
                 above) — this user's credentials are still accepted by the RUNNING server \
                 until that reload actually happens. Do not treat this as revoked yet."
            );
        }
    }
    Ok(())
}

fn cmd_user_rotate_token(cfg: &DeploymentConfig, id: &str, qr: bool) -> Result<()> {
    let mut users = store::load_users(&cfg.users_file())?;
    let token = credentials::generate_subscription_token();
    let hash = credentials::hash_token(&token);
    find_user_mut(&mut users, id)?.subscription_token_hash_hex = hash;
    store::save_users_atomic(&cfg.users_file(), &users)?;
    // Token rotation does not change VLESS/Hysteria2 credentials, so the
    // sing-box config is unaffected — no re-render needed.
    let url = subscription_url(cfg, &token);
    println!("New Hiddify subscription URL for {id}:");
    println!("  {url}");
    println!();
    println!("The previous subscription URL now 404s — it can no longer be used to FETCH or");
    println!("REFRESH this user's config. This does NOT change the VLESS UUID or Hysteria2");
    println!("password: an already-imported REALITY/Hysteria2 profile keeps connecting exactly");
    println!("as before, since those transport credentials are unchanged. Re-importing this new");
    println!("URL is only needed so the client can refresh in the future (some clients also drop");
    println!("saved servers on a failed refresh — re-import here avoids depending on that).");
    println!("Only `vpn-admin hysteria-obfs-rotate` changes the Hysteria2 obfuscation secret");
    println!("itself, which DOES require re-importing to keep the Hysteria2 profile working.");
    if qr {
        println!();
        println!("Scan this QR code in Hiddify (Add profile -> Scan QR code):");
        print_qr(&url)?;
    }
    Ok(())
}

/// `vpn-admin user qr NAME`: mints a fresh subscription token (see the
/// `UserCommands::Qr` doc comment for why this can't just re-derive an
/// existing one) and prints it as a terminal QR code.
fn cmd_user_qr(cfg: &DeploymentConfig, id: &str) -> Result<()> {
    println!(
        "Note: the subscription token is never stored in recoverable form, \
         so this mints a fresh one (like `rotate-token`) — the previous \
         subscription URL for this user stops working for fetch/refresh \
         (any already-imported profile keeps connecting; see below)."
    );
    println!();
    cmd_user_rotate_token(cfg, id, true)
}

/// `vpn-admin user links ID`: out-of-band recovery path (see the
/// `UserCommands::Links` doc comment). Builds the same
/// `standard_endpoints()` the subscription service and doctor L4 check
/// use, then renders this user's VLESS+REALITY / Hysteria2 URIs
/// directly — no HTTP fetch, no `subscription_host`/`subscription.
/// public_port` involved at all, so it keeps working even if the
/// subscription domain itself is what's blocked.
fn cmd_user_links(cfg: &DeploymentConfig, id: &str, qr: bool) -> Result<()> {
    let users = store::load_users(&cfg.users_file())?;
    let user = users
        .iter()
        .find(|u| u.id == id)
        .ok_or_else(|| anyhow::anyhow!("no such user: {id}"))?;
    if !user.enabled {
        println!("WARNING: user {id} is disabled — these URIs will not authenticate.");
        println!();
    }

    let reality = load_reality_params(cfg)?;
    let hysteria = load_hysteria_params(cfg);
    let short_id = reality.short_ids.first().cloned().unwrap_or_default();
    let endpoints = compat_config::render::standard_endpoints(
        &cfg.public_host,
        cfg.reality.listen_port,
        cfg.hysteria2.listen_port,
        &reality.public_key_hex,
        &short_id,
        &reality.handshake_server,
        hysteria.obfs_password.as_ref().map(|s| s.expose()),
    );

    println!("Out-of-band connection URIs for {id} (subscription service NOT required):");
    println!();
    for endpoint in &endpoints {
        let uri = match endpoint.transport {
            compat_config::model::CompatTransport::VlessReality => {
                compat_config::render::render_vless_reality_uri(user, endpoint)?
            }
            compat_config::model::CompatTransport::Hysteria2 => {
                compat_config::render::render_hysteria2_uri(user, endpoint)?
            }
        };
        println!("{}:", endpoint.label);
        println!("  {uri}");
        if qr {
            print_qr(&uri)?;
        }
        println!();
    }
    println!(
        "Paste one of the URIs above directly into Hiddify (Add profile -> paste config), or \
         relay it to the user through any channel other than the subscription URL. This does \
         not rotate or change any credential."
    );
    Ok(())
}

/// Common rotate-and-apply flow: mutate the user in-place via `mutate`,
/// save, render+validate+apply+reload (with rollback on failure — see
/// `regenerate_singbox_config`), and only then report success. `blast_radius`
/// is printed so an operator never has to guess which transport(s) an
/// already-imported client profile loses on this specific command —
/// see the per-command callers below for the exact scope of each.
fn rotate_and_apply(
    cfg: &DeploymentConfig,
    id: &str,
    what: &str,
    blast_radius: &str,
    mutate: impl FnOnce(&mut CompatUser),
) -> Result<()> {
    let mut users = store::load_users(&cfg.users_file())?;
    let previous_users = users.clone();
    mutate(find_user_mut(&mut users, id)?);
    let went_live = apply_users_and_save(cfg, &previous_users, &users)?;
    if went_live {
        println!("{id}: {what} rotated and applied to the running server.");
        println!("{blast_radius}");
    } else {
        println!("{id}: {what} rotated on disk, but NOT reloaded live (see the warning above).");
        println!(
            "WARNING: the running server still accepts the OLD {what} until a real reload \
             happens — none of the blast-radius claims below have taken effect yet:"
        );
        println!("{blast_radius}");
    }
    Ok(())
}

fn cmd_user_rotate_vless(cfg: &DeploymentConfig, id: &str) -> Result<()> {
    rotate_and_apply(
        cfg,
        id,
        "VLESS UUID",
        "Already-imported REALITY profiles for this user are rejected on the next handshake \
         (server no longer recognizes the old UUID) until re-imported. Hysteria2 and the \
         subscription URL are unaffected.",
        |u| {
            u.vless_uuid = credentials::generate_uuid_v4();
        },
    )
}

fn cmd_user_rotate_hysteria(cfg: &DeploymentConfig, id: &str) -> Result<()> {
    rotate_and_apply(
        cfg,
        id,
        "Hysteria2 password",
        "Already-imported Hysteria2 profiles for this user are rejected on the next handshake \
         (server no longer recognizes the old password) until re-imported. REALITY and the \
         subscription URL are unaffected.",
        |u| {
            u.hysteria2_password = SecretString::new(credentials::generate_hysteria2_password());
        },
    )
}

fn cmd_user_rotate_credentials(cfg: &DeploymentConfig, id: &str) -> Result<()> {
    rotate_and_apply(
        cfg,
        id,
        "VLESS UUID + Hysteria2 password",
        "Already-imported REALITY AND Hysteria2 profiles for this user are BOTH rejected on \
         the next handshake until re-imported. The subscription URL is unaffected and will \
         serve the new credentials once re-fetched.",
        |u| {
            u.vless_uuid = credentials::generate_uuid_v4();
            u.hysteria2_password = SecretString::new(credentials::generate_hysteria2_password());
        },
    )
}

/// Push a proposed user-store change to the running server, then publish it
/// to the subscription service only after live authorization is verified.
///
/// Every user mutation previously did `save_users_atomic(...)?;
/// regenerate_singbox_config(...)?;` with nothing compensating the first
/// call when the second failed — or when the process died between them.
/// The consequences were not symmetric or cosmetic:
///
///   * `user remove` / `user disable`: the user vanishes from the
///     authoritative store while the RUNNING server still authorizes them.
///     Revocation silently does not take effect, and because nothing
///     reconciles automatically, nothing ever notices.
///   * `user create`: the record is committed and the raw subscription
///     token — printed only AFTER the render — is lost forever.
///
/// If publishing users.json fails, the previous authorization document is
/// rendered and reloaded. The expiry reconciliation timer also repairs a
/// crash between these phases from the authoritative users.json state.
/// Returns whether the change reached a LIVE, reloaded sing-box process
/// (see `render_and_apply_singbox_config`'s doc comment) — callers that
/// print a blast-radius claim about credentials being rejected must
/// gate that claim on this.
fn apply_users_and_save(
    cfg: &DeploymentConfig,
    previous_users: &[CompatUser],
    users: &[CompatUser],
) -> Result<bool> {
    // Load the proposed authorization into sing-box before publishing the
    // new store to vpn-subscription. This makes the transition fail-closed:
    // a revocation reaches the protocol first, while a newly enabled
    // credential is not distributed until the protocol accepts it.
    let went_live = render_and_apply_singbox_config(cfg, users, true)?;

    if let Err(save_error) = store::save_users_atomic(&cfg.users_file(), users) {
        let rollback = render_and_apply_singbox_config(cfg, previous_users, true);
        bail!(
            "authorization config was loaded, but users.json could not be committed ({save_error}). {}",
            if rollback.is_ok() {
                "The previous authorization config was restored and reloaded successfully."
            } else {
                "ROLLBACK ALSO FAILED; running authorization may not match users.json. Run \
                 `vpn-admin render-config` and `vpn-admin doctor --protocol` immediately."
            }
        );
    }
    Ok(went_live)
}

fn cmd_user_remove(cfg: &DeploymentConfig, id: &str) -> Result<()> {
    let mut users = store::load_users(&cfg.users_file())?;
    let previous_users = users.clone();
    let before = users.len();
    users.retain(|u| u.id != id);
    if users.len() == before {
        bail!("no such user: {id}");
    }
    let went_live = apply_users_and_save(cfg, &previous_users, &users)?;
    println!("{id}: removed");
    if went_live {
        println!(
            "Same blast radius as `user disable`: REALITY and Hysteria2 credentials are both \
             rejected immediately, and the subscription URL 404s. Unlike disable, this is not \
             reversible with `user enable` — the account must be recreated from scratch."
        );
    } else {
        println!(
            "WARNING: the new config was written but NOT reloaded live (see the warning \
             above) — this user's credentials are still accepted by the RUNNING server until \
             that reload actually happens."
        );
    }
    Ok(())
}

fn cmd_user_subscription(cfg: &DeploymentConfig, id: &str) -> Result<()> {
    let users = store::load_users(&cfg.users_file())?;
    let user = users
        .iter()
        .find(|u| u.id == id)
        .ok_or_else(|| anyhow::anyhow!("no such user: {id}"))?;
    println!("User ID:  {}", user.id);
    println!("Name:     {}", user.name);
    println!("Enabled:  {}", user.enabled);
    println!(
        "Expiry:   {}",
        user.expires_at
            .map(|e| e.to_string())
            .unwrap_or_else(|| "never".to_string())
    );
    println!(
        "Public subscription host: {}:{}",
        cfg.subscription_host, cfg.subscription.public_port
    );
    println!();
    println!("Subscription token cannot be recovered.");
    println!("Run:");
    println!("  vpn-admin user rotate-token {id}");
    println!("to create a new URL.");
    Ok(())
}

fn cmd_version(cfg: &DeploymentConfig) -> Result<()> {
    println!("vpn1 {}", env!("CARGO_PKG_VERSION"));
    match std::process::Command::new(&cfg.singbox_binary)
        .arg("version")
        .output()
    {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            if let Some(first_line) = text.lines().next() {
                println!("{first_line}");
            }
        }
        _ => println!(
            "sing-box: not found at {:?} (or failed to run `version`)",
            cfg.singbox_binary
        ),
    }
    Ok(())
}

fn cmd_status(cfg: &DeploymentConfig) -> Result<()> {
    let users = store::load_users(&cfg.users_file())?;
    let now = UnixSeconds::now().0 as i64;
    let active = users.iter().filter(|u| u.is_active(now)).count();
    let disabled = users.iter().filter(|u| !u.enabled).count();

    println!("vpn1 status");
    println!();
    let singbox = CompatibilityServiceManager::new("sing-box");
    println!("sing-box              {}", service_state_label(&singbox));
    let subscription = CompatibilityServiceManager::new("vpn-subscription");
    println!(
        "subscription-service  {}",
        service_state_label(&subscription)
    );
    println!();
    println!(
        "sing-box config:       {}",
        if cfg.singbox_config_file().exists() {
            "present"
        } else {
            "missing (run `vpn-admin render-config`)"
        }
    );
    println!();
    println!("Users:");
    println!("  total:    {}", users.len());
    println!("  active:   {active}");
    println!("  disabled: {disabled}");
    println!();
    println!(
        "Public endpoints: {}:{} (VLESS+REALITY tcp/443, Hysteria2 udp/443 per deployment.toml)",
        cfg.public_host, cfg.reality.listen_port
    );
    println!(
        "Subscription HTTPS: https://{}:{}/sub/<token>",
        cfg.subscription_host, cfg.subscription.public_port
    );

    if let Some(days) = cert_expiry_days(&cfg.hysteria_dir().join("cert.pem")) {
        match days {
            Ok(d) if d < 0 => println!("Certificate:           EXPIRED {} day(s) ago", -d),
            Ok(d) => println!("Certificate:            valid, expires in {d} day(s)"),
            Err(e) => println!("Certificate:            could not check ({e})"),
        }
    }
    Ok(())
}

fn service_state_label(mgr: &CompatibilityServiceManager) -> &'static str {
    if !mgr.is_available() {
        "unknown (systemctl not available)"
    } else if !mgr.is_unit_installed() {
        "not installed"
    } else if mgr.is_active() {
        "active"
    } else {
        "inactive"
    }
}

/// Days until the certificate at `path` expires (negative if already
/// expired), computed via the real `openssl` binary. `None` if the file
/// doesn't exist; `Some(Err(..))` if it exists but `openssl` isn't
/// available or the output couldn't be parsed — callers must surface
/// this as an explicit "could not check", never a silent pass.
fn cert_expiry_days(path: &std::path::Path) -> Option<Result<i64, String>> {
    if !path.exists() {
        return None;
    }
    let output = std::process::Command::new("openssl")
        .args(["x509", "-enddate", "-noout", "-in"])
        .arg(path)
        .output();
    let output = match output {
        Ok(o) if o.status.success() => o,
        Ok(o) => return Some(Err(String::from_utf8_lossy(&o.stderr).trim().to_string())),
        Err(_) => return Some(Err("openssl not available".to_string())),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let date_str = match text.trim().strip_prefix("notAfter=") {
        Some(s) => s,
        None => return Some(Err(format!("unexpected openssl output: {text}"))),
    };
    // openssl's default date format, e.g. "Jan  2 03:04:05 2026 GMT" — parse
    // via `date -d` (coreutils) rather than hand-rolling a parser for a
    // locale-independent, well-known format string.
    let epoch = std::process::Command::new("date")
        .args(["-u", "-d", date_str, "+%s"])
        .output();
    match epoch {
        Ok(o) if o.status.success() => {
            let secs: i64 = String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse()
                .map_err(|e| format!("parsing date output: {e}"))
                .ok()?;
            let now = UnixSeconds::now().0 as i64;
            Some(Ok((secs - now) / 86400))
        }
        _ => Some(Err(format!("could not parse expiry date {date_str:?}"))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Ok,
    Info,
    Warn,
    Fail,
}

/// Explicit, exhaustive outcome of the L5-6 real-protocol self-test —
/// deliberately NOT a `bool`, and deliberately never inferred from the
/// L1-L4 failure counter. A prior version of this coverage logic used
/// `failures == 0` to mean "passed," which silently conflated
/// `Inconclusive` (a real dial happened, but the result cannot be
/// interpreted as pass or fail) with `Passed`, and separately used a
/// single shared counter that could make L1-L4's status look tainted by
/// an L5-6 failure or vice versa. This type exists so the coverage line
/// can only ever report exactly one of these four states — there is no
/// fifth, implicit "kind of passed" state to fall into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProtocolCheckResult {
    /// `--protocol` was not passed, OR it was passed but a pre-flight
    /// check bailed before a single packet was sent (missing binary,
    /// missing keys, no active user, harness setup failure). No real
    /// dial was attempted either way.
    NotRun,
    /// A real handshake was dialed and completed successfully end-to-end.
    Passed,
    /// A real handshake was dialed and definitively failed (REALITY
    /// rejected it).
    Failed,
    /// A real handshake was dialed but the result cannot be read as
    /// pass or fail (e.g. no HTTP success response through the tunnel).
    /// This is NOT the same as `Passed` and NOT the same as `Failed`.
    Inconclusive,
}

impl ProtocolCheckResult {
    fn label(self) -> &'static str {
        match self {
            ProtocolCheckResult::NotRun => "NOT RUN",
            ProtocolCheckResult::Passed => "PASSED",
            ProtocolCheckResult::Failed => "FAILED",
            ProtocolCheckResult::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// `layer` is one of `"L1"` (process), `"L2"` (config/key/cert),
/// `"L3"` (listeners/network), `"L4"` (subscription-coherence), or
/// `"L5-6"` (real protocol handshake) — see the module-level note above
/// `cmd_doctor` for why this labeling exists: L1-L3 all passing does
/// NOT mean a real client can connect (that's what the incident this
/// tagging responds to actually looked like).
fn report_check(status: CheckStatus, layer: &str, message: impl AsRef<str>) {
    let label = match status {
        CheckStatus::Ok => "[OK]  ",
        CheckStatus::Info => "[INFO]",
        CheckStatus::Warn => "[WARN]",
        CheckStatus::Fail => "[FAIL]",
    };
    println!("{label} [{layer:<4}] {}", message.as_ref());
}

#[cfg(unix)]
fn installed_file_policy(
    path: &std::path::Path,
    expected_group: &str,
) -> Option<Result<(), String>> {
    use std::ffi::CString;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return Some(Err(error.to_string())),
    };
    let group_name = match CString::new(expected_group) {
        Ok(name) => name,
        Err(error) => return Some(Err(error.to_string())),
    };
    let group = unsafe { libc::getgrnam(group_name.as_ptr()) };
    if group.is_null() {
        return Some(Err(format!(
            "required group {expected_group:?} does not exist"
        )));
    }
    let expected_gid = unsafe { (*group).gr_gid };
    let mode = metadata.permissions().mode() & 0o7777;
    if metadata.uid() != 0 || metadata.gid() != expected_gid || mode != 0o640 {
        return Some(Err(format!(
            "expected root:{expected_group} mode 0640, found uid={} gid={} mode={mode:04o}",
            metadata.uid(),
            metadata.gid()
        )));
    }
    Some(Ok(()))
}

#[cfg(not(unix))]
fn installed_file_policy(
    _path: &std::path::Path,
    _expected_group: &str,
) -> Option<Result<(), String>> {
    None
}

fn report_installed_file_policy(
    path: &std::path::Path,
    expected_group: &str,
    label: &str,
    failures: &mut u32,
) {
    match installed_file_policy(path, expected_group) {
        Some(Ok(())) => report_check(
            CheckStatus::Ok,
            "L2",
            format!("{label} ownership/mode is root:{expected_group} 0640"),
        ),
        Some(Err(error)) => {
            report_check(
                CheckStatus::Fail,
                "L2",
                format!("{label} policy invalid: {error}"),
            );
            *failures += 1;
        }
        None => report_check(
            CheckStatus::Warn,
            "L2",
            format!("{label} ownership/mode check unavailable on this platform"),
        ),
    }
}

/// Diagnostic checks, `[OK]`/`[WARN]`/`[FAIL]` per line (spec §17), each
/// tagged with the layer it actually covers. This tagging exists
/// because a real production incident passed every check that existed
/// here before (process active, config valid, port open, cert valid —
/// L1-L3) while a real Hiddify client's VLESS+REALITY handshake still
/// failed: sing-box logged "REALITY: processed invalid connection"
/// because the subscription service was advertising REALITY key
/// material that no longer matched what sing-box was enforcing. L1-L3
/// cannot see that class of bug by construction — they check that
/// *a* config is valid and *a* process is running, never that the
/// config a real client receives agrees with the config the server
/// enforces, and never that a handshake actually completes. L4 (always
/// run, file/struct comparisons only) and L5-6 (opt-in via
/// `--protocol`, a real throwaway client handshake) close that gap.
///
/// Returns an error (non-zero exit) iff any check is `[FAIL]`. A check
/// that needs a tool unavailable in the current environment is `[WARN]`,
/// never silently skipped and never counted as `[OK]`. The L5-6
/// self-test is always `[WARN]` on an inconclusive/skipped outcome,
/// never `[FAIL]` — see `check_l5_l6_protocol_selftest`'s doc comment
/// for why it cannot always distinguish "broken" from "untestable from
/// here".
#[allow(clippy::too_many_arguments)]
fn cmd_doctor(
    cfg: &DeploymentConfig,
    protocol: bool,
    require_protocol: bool,
    telegram: bool,
    report: bool,
    report_output: Option<&std::path::Path>,
    client: bool,
    performance: bool,
) -> Result<()> {
    if report {
        return cmd_doctor_report(cfg, report_output);
    }
    if performance {
        return cmd_doctor_performance();
    }

    let mut failures = 0u32;

    if cfg.singbox_binary.exists() {
        report_check(
            CheckStatus::Ok,
            "L2",
            format!("sing-box binary present at {:?}", cfg.singbox_binary),
        );
        let target = cfg.singbox_config_file();
        if target.exists() {
            report_installed_file_policy(&target, "sing-box", "sing-box config", &mut failures);
            let backend = SingBoxBackend {
                binary_path: cfg.singbox_binary.clone(),
            };
            match backend.validate(&target) {
                Ok(()) => report_check(CheckStatus::Ok, "L2", "sing-box config valid"),
                Err(e) => {
                    report_check(
                        CheckStatus::Fail,
                        "L2",
                        format!("sing-box config invalid: {e}"),
                    );
                    failures += 1;
                }
            }
        } else {
            report_check(
                CheckStatus::Warn,
                "L2",
                "sing-box config not yet rendered (run `vpn-admin render-config`)",
            );
        }
    } else {
        report_check(
            CheckStatus::Fail,
            "L2",
            format!("sing-box binary missing at {:?}", cfg.singbox_binary),
        );
        failures += 1;
    }

    if !cfg.reality_private_key_file().exists() {
        report_check(
            CheckStatus::Fail,
            "L2",
            format!(
                "REALITY private key missing at {:?}",
                cfg.reality_private_key_file()
            ),
        );
        failures += 1;
    } else {
        report_installed_file_policy(
            &cfg.reality_private_key_file(),
            "sing-box",
            "REALITY private key",
            &mut failures,
        );
    }
    if cfg.reality_public_key_file().exists() {
        report_installed_file_policy(
            &cfg.reality_public_key_file(),
            "vpn-subscription",
            "REALITY public key",
            &mut failures,
        );
        let short_id_path = cfg.reality_dir().join("short_id.txt");
        if short_id_path.exists() {
            report_installed_file_policy(
                &short_id_path,
                "vpn-subscription",
                "REALITY short_id",
                &mut failures,
            );
        }
        match (
            std::fs::read_to_string(cfg.reality_private_key_file()),
            std::fs::read_to_string(cfg.reality_public_key_file()),
        ) {
            (Ok(private), Ok(public)) => {
                match credentials::validate_reality_keypair(private.trim(), public.trim()) {
                    Ok(()) => report_check(
                        CheckStatus::Ok,
                        "L2",
                        "REALITY public.key cryptographically corresponds to private.key (X25519 derivation)",
                    ),
                    Err(e) => {
                        report_check(CheckStatus::Fail, "L2", format!("REALITY keypair incoherent: {e}"));
                        failures += 1;
                    }
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                report_check(
                    CheckStatus::Fail,
                    "L2",
                    format!("cannot read REALITY keypair: {e}"),
                );
                failures += 1;
            }
        }
    } else {
        report_check(
            CheckStatus::Fail,
            "L2",
            format!(
                "REALITY public key missing at {:?}",
                cfg.reality_public_key_file()
            ),
        );
        failures += 1;
    }

    if cfg.users_file().exists() {
        report_installed_file_policy(
            &cfg.users_file(),
            "vpn-subscription",
            "user store",
            &mut failures,
        );
    }
    match store::load_users(&cfg.users_file()) {
        Ok(users) => report_check(
            CheckStatus::Ok,
            "L2",
            format!("user store parses ({} user(s))", users.len()),
        ),
        Err(e) => {
            report_check(CheckStatus::Fail, "L2", format!("user store invalid: {e}"));
            failures += 1;
        }
    }

    let hysteria_cert = cfg.hysteria_dir().join("cert.pem");
    let hysteria_key = cfg.hysteria_dir().join("key.pem");
    if hysteria_cert.exists() {
        report_installed_file_policy(
            &hysteria_cert,
            "sing-box",
            "Hysteria2 certificate",
            &mut failures,
        );
    }
    if hysteria_key.exists() {
        report_installed_file_policy(
            &hysteria_key,
            "sing-box",
            "Hysteria2 private key",
            &mut failures,
        );
    }
    match cert_expiry_days(&hysteria_cert) {
        None => report_check(
            CheckStatus::Warn,
            "L2",
            "Hysteria2 TLS certificate not present (see docs/ALMALINUX_DEPLOYMENT.md)",
        ),
        Some(Ok(days)) if days < 0 => {
            report_check(
                CheckStatus::Fail,
                "L2",
                format!("Hysteria2 TLS certificate EXPIRED {} day(s) ago", -days),
            );
            failures += 1;
        }
        Some(Ok(days)) if days < 30 => report_check(
            CheckStatus::Warn,
            "L2",
            format!("Hysteria2 TLS certificate expires in {days} day(s)"),
        ),
        Some(Ok(days)) => report_check(
            CheckStatus::Ok,
            "L2",
            format!("Hysteria2 TLS certificate valid, expires in {days} day(s)"),
        ),
        Some(Err(e)) => report_check(
            CheckStatus::Warn,
            "L2",
            format!("could not check Hysteria2 TLS certificate expiry: {e}"),
        ),
    }

    if cfg.hysteria_obfs_password_file().exists() {
        report_installed_file_policy(
            &cfg.hysteria_obfs_password_file(),
            "vpn-subscription",
            "Hysteria2 obfuscation password",
            &mut failures,
        );
        report_check(
            CheckStatus::Ok,
            "L2",
            "Hysteria2 salamander obfuscation enabled",
        );
    } else {
        report_check(
            CheckStatus::Warn,
            "L2",
            "Hysteria2 salamander obfuscation is NOT enabled — the bare Hysteria2/QUIC handshake \
             is more exposed to DPI/traffic-classifier fingerprinting than an obfuscated one. Run \
             `vpn-admin hysteria-obfs-rotate` to enable it (every existing client must re-import \
             its Hysteria2 profile afterward).",
        );
    }

    for name in ["sing-box", "vpn-subscription"] {
        let mgr = CompatibilityServiceManager::new(name);
        if !mgr.is_available() {
            report_check(
                CheckStatus::Warn,
                "L1",
                format!("systemctl not available — cannot check {name}.service"),
            );
        } else if !mgr.is_unit_installed() {
            report_check(
                CheckStatus::Warn,
                "L1",
                format!("{name}.service not installed on this host"),
            );
        } else if mgr.is_active() {
            report_check(CheckStatus::Ok, "L1", format!("{name}.service active"));
        } else {
            report_check(
                CheckStatus::Fail,
                "L1",
                format!("{name}.service not active"),
            );
            failures += 1;
        }
    }

    // The once-a-minute reconciler is the only thing that applies user
    // expiry/disablement to the LIVE server between explicit `vpn-admin`
    // mutations — since it now runs with `--require-applied`, a failure
    // to reconcile makes this oneshot unit `failed`, and that state
    // persists (visible here) until the next successful run. This is
    // deliberately NOT the same question as "is it active" (see
    // `is_failed`'s doc comment) and deliberately does not fail overall
    // `doctor` just because the unit isn't installed (dev/CI hosts).
    {
        let reconcile_mgr = CompatibilityServiceManager::new("vpn-expiry-reconcile");
        if reconcile_mgr.is_available() && reconcile_mgr.is_unit_installed() {
            if reconcile_mgr.is_failed() {
                report_check(
                    CheckStatus::Fail,
                    "L1",
                    "vpn-expiry-reconcile.service is in a FAILED state — expired/disabled \
                     users' authorization may not be in sync with the live server; run `sudo \
                     journalctl -u vpn-expiry-reconcile` for the cause, then `sudo vpn-admin \
                     render-config --require-applied` to retry by hand",
                );
                failures += 1;
            } else {
                report_check(
                    CheckStatus::Ok,
                    "L1",
                    "vpn-expiry-reconcile.service has no recorded failure",
                );
            }
        } else {
            report_check(
                CheckStatus::Warn,
                "L1",
                "vpn-expiry-reconcile.service not installed on this host — expiry is not being \
                 reconciled automatically",
            );
        }
    }

    match std::process::Command::new("firewall-cmd")
        .arg("--state")
        .output()
    {
        Ok(o) if o.status.success() => report_check(CheckStatus::Ok, "L3", "firewalld running"),
        Ok(_) => {
            report_check(CheckStatus::Fail, "L3", "firewalld not running");
            failures += 1;
        }
        Err(_) => report_check(
            CheckStatus::Warn,
            "L3",
            "firewall-cmd not available — firewall check skipped",
        ),
    }

    for (proto_label, port, udp) in [
        ("VLESS+REALITY", cfg.reality.listen_port, false),
        ("Hysteria2", cfg.hysteria2.listen_port, true),
    ] {
        match listener_reported_by_ss(port, udp) {
            Some(true) => report_check(
                CheckStatus::Ok,
                "L3",
                format!(
                    "{proto_label} {} listener present on port {port}",
                    if udp { "UDP" } else { "TCP" }
                ),
            ),
            Some(false) => {
                report_check(
                    CheckStatus::Fail,
                    "L3",
                    format!(
                        "{proto_label} {} listener missing on port {port}",
                        if udp { "UDP" } else { "TCP" }
                    ),
                );
                failures += 1;
            }
            None => report_check(
                CheckStatus::Warn,
                "L3",
                format!("cannot inspect {proto_label} listener: `ss` is unavailable or failed"),
            ),
        }
    }

    // Additional UDP egress check: if Hysteria2 is listening, ensure the
    // host can send and receive basic UDP packets to public resolvers.
    // Try multiple resolvers and a small retry window to reduce false
    // negatives on transient failures.
    if let Some(true) = listener_reported_by_ss(cfg.hysteria2.listen_port, true) {
        let probe_cfg = cfg.udp_probe_config();
        let ipv4_candidates_vec = probe_cfg.ipv4_resolvers;
        let timeout = std::time::Duration::from_millis(probe_cfg.timeout_ms);
        let retries = probe_cfg.retries;
        let delay = std::time::Duration::from_millis(probe_cfg.delay_ms);

        let ipv4_refs: Vec<&str> = ipv4_candidates_vec.iter().map(|s| s.as_str()).collect();
        match run_udp_probe_candidates(&ipv4_refs, timeout, retries, delay) {
            Some(true) => report_check(
                CheckStatus::Ok,
                "L3",
                "UDP egress (IPv4) appears functional (DNS via UDP to public resolvers succeeded)",
            ),
            Some(false) => {
                report_check(
                    CheckStatus::Fail,
                    "L3",
                    "UDP egress (IPv4) appears blocked — Hysteria2 (QUIC/UDP) may not work from this VPS (tried multiple resolvers)",
                );
                failures += 1;
            }
            None => report_check(
                CheckStatus::Warn,
                "L3",
                "UDP egress check (IPv4) unavailable on this host (socket bind/permission failed)",
            ),
        }

        // NOTE: there is deliberately no blanket IPv6 UDP egress check
        // here. IPv6 egress is only actually *required* when the public
        // hostname has an AAAA record — on an IPv4-only host (no AAAA,
        // the common case on a plain EC2 box with no IPv6 configured at
        // all) failing this would blame an unrelated, expected-absent
        // capability for what is otherwise a fully working deployment
        // (docs/FINAL_PRODUCTION_AUDIT.md: "never infer one component's
        // status from another"). This exact bug used to abort
        // `--require-protocol` acceptance on IPv4-only hosts even though
        // the real VLESS+REALITY L5/L6 handshake passed. The
        // AAAA-aware, single source of truth for IPv6 posture is
        // `check_public_hostname_and_ipv6_policy` below — it is the only
        // place that runs the IPv6 UDP probe and decides fatality, so
        // there is exactly one IPv6 verdict line instead of two
        // potentially-contradictory ones. Do not add a second IPv6 probe
        // here; extend `classify_ipv6_posture`/`ipv6_posture_report`
        // instead. Only the IPv4 probe belongs here because IPv4 egress
        // is unconditionally required regardless of DNS records.
    }

    check_l4_subscription_coherence(cfg, &mut failures);
    check_l4_live_subscription_process_state(cfg, &mut failures);
    check_public_hostname_and_ipv6_policy(cfg, &mut failures);
    check_singbox_binary_version_consistency(cfg);
    report_check(
        CheckStatus::Info,
        "L4",
        "Automatic transport selection (`auto` / urltest) tests generic HTTPS connectivity to \
         Google, not Telegram-specific behavior. The subscription's default (`select`) is the \
         REALITY endpoint, chosen deterministically, not by that race — see \
         docs/TELEGRAM_RESILIENCE_PLAN.md and docs/TELEGRAM_TROUBLESHOOTING.md.",
    );

    // L1-L4's outcome is captured as a snapshot BEFORE the L5-6 check
    // runs, so the coverage line below can report each layer's status
    // independently — L1-4 must never look tainted by an L5-6 failure,
    // and L5-6 must never be inferred from the L1-4 count (or from
    // whether `--protocol` was merely passed on the command line: it
    // can bail out before dialing a single packet on missing binary/
    // keys/active user, in which case no real handshake was attempted
    // even though the flag was set). `check_l5_l6_protocol_selftest`'s
    // `ProtocolCheckResult` return value is the one source of truth for
    // what actually happened at L5-6.
    let l1_l4_failures = failures;
    let protocol_result = if protocol {
        check_l5_l6_protocol_selftest(cfg, &mut failures, require_protocol)
    } else {
        report_check(
            CheckStatus::Warn,
            "L5-6",
            "protocol handshake self-test not run (pass `--protocol` to actually dial this \
             server's own REALITY listener with a throwaway sing-box client) — passing every \
             check above does NOT prove a real client can authenticate",
        );
        ProtocolCheckResult::NotRun
    };

    // Independent Hysteria2/QUIC counterpart to the REALITY self-test
    // above — see `check_l5_l6_hysteria2_protocol_selftest`'s doc
    // comment for why it reports its own "L5-6-H2" line rather than
    // folding into `protocol_result`/`ProtocolCheckResult`.
    if protocol {
        check_l5_l6_hysteria2_protocol_selftest(cfg, &mut failures, require_protocol);
    } else {
        report_check(
            CheckStatus::Warn,
            "L5-6-H2",
            "Hysteria2 protocol handshake self-test not run (pass `--protocol` to actually dial \
             this server's own Hysteria2 listener with a throwaway sing-box client) — passing \
             every check above does NOT prove a real client can authenticate over Hysteria2",
        );
    }

    if telegram {
        print_telegram_diagnostics_summary(cfg, l1_l4_failures, protocol_result);
    }

    if client {
        print_client_acceptance_checklist(cfg, l1_l4_failures, protocol_result);
    }

    println!();
    if failures > 0 {
        bail!("{failures} check(s) failed");
    }
    println!("All checks passed (see [WARN] lines above for anything unverifiable on this host).");
    Ok(())
}

/// `vpn doctor --telegram`: after the standard checks above, print a
/// Telegram-oriented summary of exactly what those checks did and did
/// not verify, ending in an explicit, mandatory disclaimer. This
/// function performs NO additional network probing of its own — the
/// standard L1-L4 (and, if `--protocol` was passed, L5-6) checks above
/// already cover every server-side signal available from this host;
/// this only reframes that same evidence for the specific "Telegram is
/// unreliable" investigation and is explicit about what it cannot see.
/// Per the investigation's own finding, "Telegram works" is not one
/// test — see docs/TELEGRAM_TROUBLESHOOTING.md and
/// docs/DEVICE_ACCEPTANCE_TESTS.md for the real, per-function test
/// matrix that only a real device on a real network can actually run.
fn print_telegram_diagnostics_summary(
    cfg: &DeploymentConfig,
    l1_l4_failures: u32,
    protocol_result: ProtocolCheckResult,
) {
    println!();
    println!("--- Telegram-oriented summary (server-side only) ---");
    print_doctor_coverage_line(l1_l4_failures, protocol_result);
    println!();
    println!(
        "Public endpoints: {}:{} (VLESS+REALITY tcp), {}:{} (Hysteria2 udp)",
        cfg.public_host, cfg.reality.listen_port, cfg.public_host, cfg.hysteria2.listen_port
    );
    println!(
        "Hysteria2 Salamander obfuscation: {}",
        if cfg.hysteria_obfs_password_file().exists() {
            "enabled"
        } else {
            "DISABLED — Hysteria2's bare handshake is more exposed to DPI/traffic-classifier \
             fingerprinting; consider `vpn-admin hysteria-obfs-rotate`"
        }
    );
    println!(
        "Subscription default transport: REALITY (deterministic `select` outbound) — Hysteria2 \
         and `auto` remain manually selectable in the client."
    );
    println!();
    println!("Server-side diagnostics above passed/failed as shown. This does NOT verify:");
    println!("  - Russian DPI compatibility");
    println!("  - Hiddify TUN routing on the client device");
    println!("  - Telegram's own in-app proxy settings (Settings -> Data and Storage -> Proxy)");
    println!("  - Russian mobile ISP behavior");
    println!("  - IPv6 leakage on the client's own network path");
    println!("  - Which Telegram function (text / media / calls / notifications) actually fails");
    println!();
    println!("Run the client acceptance checklist next: docs/TELEGRAM_TROUBLESHOOTING.md and");
    println!("docs/DEVICE_ACCEPTANCE_TESTS.md.");
}

/// `vpn doctor --client`: after the standard server-side checks, print an
/// interactive, fill-in-by-hand checklist for onboarding a client device
/// (Hiddify on iOS in particular).
///
/// This performs NO device-side probing — it CANNOT reach into a phone —
/// and it must never be read as claiming otherwise. Its entire value is
/// separating what this host can already prove (everything above this
/// point in `doctor`'s output) from what only the human operator, sitting
/// with the device, can check next, in an order that finds the actual
/// fault fastest.
///
/// Exists because of a real, recurring confusion: Hiddify's own UI
/// showing a transport as "connected" is a claim about Hiddify's
/// internal proxy engine, not about the operating system's VPN/TUN
/// state. On iOS those are two different subsystems (Hiddify's local
/// proxy vs. NetworkExtension's `NEPacketTunnelProvider`), and Hiddify
/// has shipped builds/modes where the former activates without the
/// latter ever doing so — see docs/clients/HIDDIFY_IOS.md for the full
/// explanation and prioritized troubleshooting order. Nothing in the
/// subscription this server generates (outbounds + a manual selector)
/// can select Hiddify's "VPN/TUN" mode over its "Proxy Only" mode, or
/// grant the iOS "Allow VPN Configurations" permission — those are
/// entirely client-side settings/permissions this repository does not
/// control.
fn print_client_acceptance_checklist(
    cfg: &DeploymentConfig,
    l1_l4_failures: u32,
    protocol_result: ProtocolCheckResult,
) {
    println!();
    println!("--- Client acceptance checklist (fill in by hand on the device) ---");
    println!();
    if l1_l4_failures > 0 {
        println!(
            "WARNING: {l1_l4_failures} check(s) earlier in this report FAILED. Server-side \
             health is NOT proven — fix those failures before trusting this checklist to \
             isolate a client-side cause."
        );
        println!();
    }
    println!("IMPORTANT: \"Connected\" in Hiddify's own UI does NOT by itself prove system");
    println!("traffic is routed through the VPN. Hiddify's in-app connected state and iOS's");
    println!("system VPN/TUN state are two different things — verify BOTH, in this order.");
    println!();
    println!(
        "Public endpoints under test: {}:{} (REALITY tcp), {}:{} (Hysteria2 udp)",
        cfg.public_host, cfg.reality.listen_port, cfg.public_host, cfg.hysteria2.listen_port
    );
    println!();
    println!("1. [ ] Hiddify's Service Mode is set to VPN / TUN mode, NOT \"Proxy Only\"");
    println!("       (Hiddify Settings — the two modes look similar but only VPN/TUN mode");
    println!("       captures system-wide traffic; \"Proxy Only\" never shows an iOS VPN icon");
    println!("       and never changes your public IP by design).");
    println!("   [ ] For FULL-TUNNEL verification choose Region=Other / disable RU bypass");
    println!("       and custom split routes, then reconnect. The subscription cannot override");
    println!("       Hiddify's global routing policy.");
    println!("2. [ ] iOS granted the \"Allow VPN Configurations\" permission when first asked");
    println!("       (a dismissed/denied prompt fails silently — no error shown in Hiddify).");
    println!("3. [ ] Settings -> General -> VPN & Device Management shows a Hiddify VPN");
    println!("       profile actually installed (not just the app installed).");
    println!("4. [ ] No stale/duplicate VPN profiles from a previous install are present —");
    println!("       remove any and reconnect if so.");
    println!("5. [ ] iOS status bar / Control Center shows the VPN indicator once connected.");
    println!("6. [ ] Public IPv4 BEFORE connecting: ______________");
    println!("7. [ ] Select REALITY explicitly in Hiddify's server list (don't rely on auto).");
    println!("8. [ ] Public IPv4 AFTER connecting to REALITY: ______________  (must differ");
    println!("       from step 6 and match this server's public IP)");
    println!("   [ ] Check both a neutral IP endpoint and a .ru endpoint. If only .ru keeps");
    println!("       the ISP IP, classify CLIENT REGION BYPASS, not server failure.");
    println!("9. [ ] Disconnect, select Hysteria2 explicitly, reconnect, and repeat the public");
    println!("       IP check for Hysteria2 alone.");
    println!("10.[ ] Tested on Wi-Fi.");
    println!("11.[ ] Tested on mobile/cellular data.");
    println!(
        "12.[ ] From the SAME network as the phone, `curl -v https://{}:{}` (or",
        cfg.public_host, cfg.reality.listen_port
    );
    println!("       Test-NetConnection) succeeds — tests whether that network path can even");
    println!("       reach this server at all, independent of Hiddify.");
    println!();
    println!(
        "If step 8 or 9 shows an unchanged IP: go back to steps 1-4 (client mode/permission)."
    );
    print_doctor_coverage_line(l1_l4_failures, protocol_result);
    println!(
        "A PASS above only proves this server's own listener/key/auth path works FROM THIS \
         SERVER'S OWN vantage point — it never proves reachability from the phone's specific \
         network, iOS's NetworkExtension state, or Hiddify's TUN/routing behavior. Do not treat \
         a passing doctor run as \"confirmed client-side\"; step 12 above is what actually tests \
         the network path."
    );
    println!();
    println!(
        "If 1-12 are all satisfied and it STILL doesn't work: check your Hiddify build/version"
    );
    println!(
        "before assuming a behavioral bug. As of 2026-08, hiddify/hiddify-app#2317 (OPEN) \
         documents problems in Hiddify's own iOS release pipeline (App Store build reporting"
    );
    println!(
        "\"4.0.0 dev\", CI/signing/config inconsistencies, later tagged releases not producing \
         normal iOS artifacts). This does NOT establish that #2317 CAUSES the \"connected but no"
    );
    println!(
        "VPN tunnel\" symptom this checklist exists for — it only means the exact installed iOS \
         client build is an important variable to record when reporting a problem: note the"
    );
    println!(
        "exact version/build shown in Hiddify's About screen. Older reports of this exact \
         symptom on iOS (hiddify/hiddify-app#1812, #1485, #290) are CLOSED (stale-bot, no linked"
    );
    println!(
        "fix) as of 2026-08-11 — historical evidence this class of bug has happened before, not \
         a currently tracked, causally-established bug. Nothing in this server's subscription"
    );
    println!(
        "can detect or fix any of this. Try: update Hiddify, delete+reinstall it, remove ALL its \
         VPN profiles from Settings before reconnecting, reboot, retry — then report fresh to"
    );
    println!("Hiddify's tracker (with your exact app version/build) if still broken.");
    println!();
    println!("Full walkthrough and troubleshooting priority order: docs/clients/HIDDIFY_IOS.md");
}

/// Explicit diagnostic-coverage line, shared by the Telegram and client
/// summaries. L1-4's status and L5-6's status are tracked completely
/// independently — `l1_l4_failures == 0` says nothing about L5-6, and
/// `protocol_result` says nothing about L1-4. Each of the following
/// combinations must print distinctly, with no state inferred from the
/// other layer or collapsed into a fifth implicit "kind of passed"
/// state:
///
///   Coverage: L1-4: PASSED       L5-6: NOT RUN
///   Coverage: L1-4: PASSED       L5-6: PASSED
///   Coverage: L1-4: PASSED       L5-6: INCONCLUSIVE
///   Coverage: L1-4: PASSED       L5-6: FAILED
///   Coverage: L1-4: FAILED (n)   L5-6: PASSED
///   Coverage: L1-4: FAILED (n)   L5-6: NOT RUN
///   Coverage: L1-4: FAILED (n)   L5-6: INCONCLUSIVE
///   Coverage: L1-4: FAILED (n)   L5-6: FAILED
///
/// All 8 (2×4) combinations get their own match arm in
/// `build_doctor_coverage_report` with no wildcard — see that
/// function's own comment for why the wildcard-free match itself, not
/// a test, is what actually guards against a future 5th
/// `ProtocolCheckResult` variant being silently swallowed.
///
/// "Server proven healthy end-to-end" requires BOTH `l1_l4_failures ==
/// 0` AND `protocol_result == Passed` — every other combination gets an
/// explicit, distinct caveat, including `Inconclusive` (a real dial
/// happened, but the result cannot be read as pass or fail — this is
/// NOT "passed" and NOT "not run").
fn print_doctor_coverage_line(l1_l4_failures: u32, protocol_result: ProtocolCheckResult) {
    println!();
    println!(
        "{}",
        build_doctor_coverage_report(l1_l4_failures, protocol_result)
    );
}

/// Pure string-building half of [`print_doctor_coverage_line`], split
/// out so the exhaustive combination matrix in its doc comment is
/// directly unit-testable without capturing stdout. Never call this
/// from anywhere that isn't `print_doctor_coverage_line` or a test —
/// the leading-blank-line/println wrapping is that function's job.
fn build_doctor_coverage_report(
    l1_l4_failures: u32,
    protocol_result: ProtocolCheckResult,
) -> String {
    let l1_l4_label = if l1_l4_failures == 0 {
        "PASSED".to_string()
    } else {
        format!("FAILED ({l1_l4_failures})")
    };
    let header = format!(
        "Coverage: L1-4 (process/config/listeners/subscription): {l1_l4_label}   L5-6 (real \
         protocol handshake): {}",
        protocol_result.label()
    );
    // Deliberately no `_`/wildcard arm on `protocol_result`: if a fifth
    // `ProtocolCheckResult` variant is ever added, this match fails to
    // COMPILE rather than silently falling into a collapsed message —
    // that's the actual guard against a future regression here (a
    // wildcard arm would defeat it even with 100% test coverage of
    // today's four variants).
    let detail = match (l1_l4_failures == 0, protocol_result) {
        (true, ProtocolCheckResult::Passed) => {
            "All checks that ran, including the real protocol handshake, passed. This proves \
             the server's own listener/key/auth path — nothing about external reachability, \
             the client device, or the network in between (see below)."
        }
        (true, ProtocolCheckResult::NotRun) => {
            "No failures among checks that ran, but the real-handshake check (L5-6) did not \
             run — this is NOT the same as \"server proven healthy end-to-end.\" Re-run with \
             `--protocol --require-protocol` before treating the server as cleared."
        }
        (true, ProtocolCheckResult::Inconclusive) => {
            "L1-4 passed, but the real-handshake check (L5-6) DIALED and got an INCONCLUSIVE \
             result — not a pass, not a definitive failure. Do not treat this as \"server \
             healthy\"; inspect both sing-box processes' logs before concluding anything."
        }
        (true, ProtocolCheckResult::Failed) => {
            "L1-4 passed, but the real-handshake check (L5-6) FAILED — a real client using this \
             server's own current key material could not complete a handshake. This is a \
             server-side finding, not proof the problem is client-side."
        }
        (false, ProtocolCheckResult::Passed) => {
            "L1-4 check(s) FAILED even though L5-6's real handshake passed — these are \
             independent signals; a passing handshake does NOT clear the L1-4 failures above. \
             Fix those before treating the server as healthy."
        }
        (false, ProtocolCheckResult::NotRun) => {
            "L1-4 check(s) FAILED, and the real-handshake check (L5-6) did not run either — \
             server-side health is NOT established on either axis. Fix the L1-4 failures first."
        }
        (false, ProtocolCheckResult::Inconclusive) => {
            "L1-4 check(s) FAILED, and the real-handshake check (L5-6) DIALED but got an \
             INCONCLUSIVE result — server-side health is NOT established on either axis. Fix \
             the L1-4 failures first, then re-run the protocol self-test."
        }
        (false, ProtocolCheckResult::Failed) => {
            "L1-4 check(s) FAILED, and the real-handshake check (L5-6) also FAILED — server-side \
             health is NOT established on either axis. Fix the L1-4 failures first."
        }
    };
    format!("{header}\n{detail}")
}

/// Reads a `/proc`/`/sys` file and returns its trimmed contents, or
/// `None` if unreadable — the uniform "can't read it, say so, don't
/// guess" path every metric below goes through.
fn perf_read(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn perf_line(label: &str, value: Option<String>) {
    match value {
        Some(v) if !v.is_empty() => println!("  {label}: {v}"),
        _ => println!("  {label}: unavailable"),
    }
}

fn perf_cpu_model() -> Option<String> {
    let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    text.lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
}

fn perf_vcpu_count() -> Option<String> {
    std::thread::available_parallelism()
        .ok()
        .map(|n| n.get().to_string())
}

/// `/proc/stat`'s first line (aggregate across all CPUs): user nice
/// system idle iowait irq softirq steal ... Two samples ~200ms apart
/// give an instantaneous, not since-boot-average, reading — since-boot
/// figures are close to meaningless on a host that's been up for weeks.
fn perf_cpu_and_steal_pct() -> Option<(f64, f64)> {
    let parse = |line: &str| -> Option<[u64; 8]> {
        let mut fields = [0u64; 8];
        let nums: Vec<u64> = line
            .split_whitespace()
            .skip(1)
            .filter_map(|s| s.parse().ok())
            .collect();
        if nums.len() < 8 {
            return None;
        }
        fields.copy_from_slice(&nums[..8]);
        Some(fields)
    };
    let read_cpu_line = || -> Option<[u64; 8]> {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let line = stat.lines().find(|l| l.starts_with("cpu "))?;
        parse(line)
    };
    let a = read_cpu_line()?;
    std::thread::sleep(std::time::Duration::from_millis(200));
    let b = read_cpu_line()?;
    let deltas: Vec<u64> = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| y.saturating_sub(*x))
        .collect();
    let total: u64 = deltas.iter().sum();
    if total == 0 {
        return None;
    }
    let idle = deltas[3] + deltas[4]; // idle + iowait
    let steal = deltas[7];
    let busy_pct = 100.0 * (total.saturating_sub(idle)) as f64 / total as f64;
    let steal_pct = 100.0 * steal as f64 / total as f64;
    Some((busy_pct, steal_pct))
}

fn perf_load_average() -> Option<String> {
    perf_read("/proc/loadavg").map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
}

fn perf_meminfo_field(field: &str) -> Option<String> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    text.lines()
        .find(|l| l.starts_with(field))
        .map(|l| l.trim().to_string())
}

/// The primary non-loopback interface, best-effort: the first `UP`
/// interface `/proc/net/route` names as the default-route device. `None`
/// if the host has no default route (nothing meaningful to probe) or
/// `ip` isn't present.
fn perf_primary_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    text.lines().skip(1).find_map(|l| {
        let mut fields = l.split_whitespace();
        let iface = fields.next()?;
        let dest = fields.next()?;
        (dest == "00000000").then(|| iface.to_string())
    })
}

fn perf_run(cmd: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Finds a running `sing-box` process's PID via `/proc/*/comm` — no
/// `pidof`/`pgrep` dependency, and this never touches process
/// arguments/environment (which could contain secrets on other
/// processes; sing-box's own argv here is just `run -c <path>` but the
/// principle is to never read argv/environ of an arbitrary process).
fn perf_singbox_pid() -> Option<u32> {
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        let comm = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
        if comm.trim() == "sing-box" {
            return Some(pid);
        }
    }
    None
}

/// `vpn doctor --performance`: host/kernel/network MEASUREMENTS only —
/// see the `--performance` flag's doc comment on why this deliberately
/// never emits a verdict or a recommendation. Every number here is
/// either read straight from `/proc`/`/sys` or from a well-known
/// read-only tool (`ip`, `tc`, `ss`); nothing is derived by inference.
/// Always exits 0 — there is no pass/fail concept for a measurement.
fn cmd_doctor_performance() -> Result<()> {
    println!("vpn1 performance diagnostics (MEASUREMENTS, not recommendations)");
    println!(
        "See docs/PERFORMANCE_OPTIMIZATION_PLAN.md for how to interpret these numbers, and \
         `vpn benchmark` for actual throughput tests these alone cannot provide."
    );

    println!("\nCPU");
    perf_line("model", perf_cpu_model());
    perf_line("vCPUs", perf_vcpu_count());
    perf_line("load average (1m 5m 15m)", perf_load_average());
    match perf_cpu_and_steal_pct() {
        Some((busy, steal)) => {
            println!("  utilisation (instantaneous, ~200ms sample): {busy:.1}%");
            println!("  steal (instantaneous, ~200ms sample): {steal:.1}%");
        }
        None => {
            println!("  utilisation: unavailable");
            println!("  steal: unavailable");
        }
    }

    println!("\nMemory");
    perf_line("RAM total", perf_meminfo_field("MemTotal"));
    perf_line("RAM available", perf_meminfo_field("MemAvailable"));
    perf_line("swap total", perf_meminfo_field("SwapTotal"));
    perf_line("swap free", perf_meminfo_field("SwapFree"));

    println!("\nNetwork interface");
    let iface = perf_primary_interface();
    perf_line("primary interface", iface.clone());
    if let Some(ref iface) = iface {
        perf_line(
            "MTU",
            perf_run("ip", &["-o", "link", "show", "dev", iface]).and_then(|s| {
                s.split_whitespace()
                    .position(|w| w == "mtu")
                    .and_then(|i| s.split_whitespace().nth(i + 1).map(str::to_string))
            }),
        );
        perf_line("qdisc", perf_run("tc", &["qdisc", "show", "dev", iface]));
    } else {
        perf_line("MTU", None);
        perf_line("qdisc", None);
    }

    println!("\nTCP congestion control");
    perf_line(
        "current",
        perf_read("/proc/sys/net/ipv4/tcp_congestion_control"),
    );
    perf_line(
        "available",
        perf_read("/proc/sys/net/ipv4/tcp_available_congestion_control"),
    );

    println!("\nUDP/TCP buffers (sysctl ceilings, not in-use size)");
    perf_line(
        "net.core.rmem_max",
        perf_read("/proc/sys/net/core/rmem_max"),
    );
    perf_line(
        "net.core.wmem_max",
        perf_read("/proc/sys/net/core/wmem_max"),
    );

    println!("\nProtocol error counters (cumulative since boot — compare two runs, not the absolute value)");
    if let Ok(snmp) = std::fs::read_to_string("/proc/net/snmp") {
        let field = |proto_prefix: &str, field_name: &str| -> Option<String> {
            let mut lines = snmp.lines();
            while let Some(header) = lines.next() {
                if !header.starts_with(proto_prefix) {
                    continue;
                }
                let values = lines.next()?;
                let names: Vec<&str> = header.split_whitespace().skip(1).collect();
                let vals: Vec<&str> = values.split_whitespace().skip(1).collect();
                return names
                    .iter()
                    .position(|n| *n == field_name)
                    .and_then(|i| vals.get(i))
                    .map(|s| s.to_string());
            }
            None
        };
        perf_line("TCP retransmitted segments", field("Tcp:", "RetransSegs"));
        perf_line("UDP receive errors", field("Udp:", "InErrors"));
        perf_line("UDP receive buffer errors", field("Udp:", "RcvbufErrors"));
        perf_line("UDP send buffer errors", field("Udp:", "SndbufErrors"));
    } else {
        perf_line("TCP retransmitted segments", None);
        perf_line("UDP receive errors", None);
        perf_line("UDP receive buffer errors", None);
        perf_line("UDP send buffer errors", None);
    }

    println!("\nsing-box process");
    match perf_singbox_pid() {
        Some(pid) => {
            println!("  pid: {pid}");
            perf_line(
                "nice",
                perf_run("ps", &["-o", "ni=", "-p", &pid.to_string()])
                    .map(|s| s.trim().to_string()),
            );
            perf_line(
                "open file descriptor limit (soft/hard)",
                std::fs::read_to_string(format!("/proc/{pid}/limits"))
                    .ok()
                    .and_then(|s| {
                        s.lines()
                            .find(|l| l.starts_with("Max open files"))
                            .map(|l| {
                                l.split_whitespace()
                                    .skip(3)
                                    .take(2)
                                    .collect::<Vec<_>>()
                                    .join(" / ")
                            })
                    }),
            );
            perf_line(
                "CPU time consumed (utime+stime, clock ticks since process start)",
                std::fs::read_to_string(format!("/proc/{pid}/stat"))
                    .ok()
                    .and_then(|s| {
                        let fields: Vec<&str> = s.rsplit(')').next()?.split_whitespace().collect();
                        // Fields after the ')' are 1-indexed from field 3 in `man
                        // proc`; utime is index 11, stime is index 12 in that
                        // scheme, i.e. offsets 11-3=8 and 12-3=9 here (0-indexed
                        // after skipping state at offset 0).
                        let utime: u64 = fields.get(11).and_then(|s| s.parse().ok())?;
                        let stime: u64 = fields.get(12).and_then(|s| s.parse().ok())?;
                        Some((utime + stime).to_string())
                    }),
            );
        }
        None => println!("  not found (is sing-box running?)"),
    }

    println!(
        "\nDone. These are point-in-time measurements; CPU/steal figures in particular are \
         noisy over a 200ms sample — re-run under real load for a meaningful reading, and see \
         `vpn benchmark` for throughput/latency numbers this command does not attempt to \
         collect."
    );
    Ok(())
}

/// `vpn doctor --report`: a sanitized diagnostic bundle suitable for
/// sharing when asking for help (e.g. pasting into a chat with another
/// operator). Every value included here is either non-secret by
/// construction (versions, service state, listener presence, hostname
/// resolution counts, certificate expiry, config flags) or has been run
/// through `redact_secrets` (the log tail, which could otherwise
/// contain leaked key material from sing-box's own debug output).
/// Deliberately does NOT reuse `cmd_doctor`'s check functions directly —
/// those print human-readable `[OK]`/`[WARN]`/`[FAIL]` prose for an
/// interactive operator; this produces a compact, stable-shaped bundle
/// meant to be pasted elsewhere.
fn cmd_doctor_report(cfg: &DeploymentConfig, output: Option<&std::path::Path>) -> Result<()> {
    let mut out = String::new();
    use std::fmt::Write as _;

    let _ = writeln!(out, "vpn1 diagnostic report (sanitized)");
    let _ = writeln!(out, "generated: {}", UnixSeconds::now().0);
    let _ = writeln!(out, "vpn1 version: {}", env!("CARGO_PKG_VERSION"));

    let _ = writeln!(out, "\n[system]");
    match std::process::Command::new("uname").arg("-a").output() {
        Ok(o) if o.status.success() => {
            let _ = writeln!(out, "uname: {}", String::from_utf8_lossy(&o.stdout).trim());
        }
        _ => {
            let _ = writeln!(out, "uname: unavailable");
        }
    }

    let _ = writeln!(out, "\n[sing-box]");
    match std::process::Command::new(&cfg.singbox_binary)
        .arg("version")
        .output()
    {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let first_line = text.lines().next().unwrap_or("").trim();
            let _ = writeln!(out, "version: {first_line}");
        }
        _ => {
            let _ = writeln!(out, "version: unavailable at {:?}", cfg.singbox_binary);
        }
    }

    let _ = writeln!(out, "\n[services]");
    for name in ["sing-box", "vpn-subscription"] {
        let mgr = CompatibilityServiceManager::new(name);
        let _ = writeln!(out, "{name}: {}", service_state_label(&mgr));
    }

    let _ = writeln!(out, "\n[listeners]");
    for (label, port, udp) in [
        ("VLESS+REALITY", cfg.reality.listen_port, false),
        ("Hysteria2", cfg.hysteria2.listen_port, true),
    ] {
        let state = match listener_reported_by_ss(port, udp) {
            Some(true) => "present",
            Some(false) => "MISSING",
            None => "unknown (`ss` unavailable)",
        };
        let _ = writeln!(
            out,
            "{label} {}/{port}: {state}",
            if udp { "udp" } else { "tcp" }
        );
    }

    let _ = writeln!(out, "\n[hostname resolution]");
    match (cfg.public_host.as_str(), 0u16).to_socket_addrs() {
        Ok(iter) => {
            let addrs: Vec<_> = iter.collect();
            let v4 = addrs.iter().filter(|a| a.is_ipv4()).count();
            let v6 = addrs.iter().filter(|a| a.is_ipv6()).count();
            let _ = writeln!(out, "public_host resolves: {v4} A, {v6} AAAA");
        }
        Err(e) => {
            let _ = writeln!(out, "public_host does not resolve: {e}");
        }
    }

    let _ = writeln!(out, "\n[transport configuration]");
    let _ = writeln!(
        out,
        "hysteria2 salamander obfuscation: {}",
        if cfg.hysteria_obfs_password_file().exists() {
            "enabled"
        } else {
            "disabled"
        }
    );
    let _ = writeln!(
        out,
        "subscription default transport: reality (deterministic selector)"
    );
    match cert_expiry_days(&cfg.hysteria_dir().join("cert.pem")) {
        Some(Ok(days)) => {
            let _ = writeln!(out, "hysteria2 tls cert: expires in {days} day(s)");
        }
        Some(Err(e)) => {
            let _ = writeln!(out, "hysteria2 tls cert: could not check ({e})");
        }
        None => {
            let _ = writeln!(out, "hysteria2 tls cert: not present");
        }
    }

    let _ = writeln!(out, "\n[firewall]");
    match std::process::Command::new("firewall-cmd")
        .arg("--state")
        .output()
    {
        Ok(o) if o.status.success() => {
            let _ = writeln!(out, "firewalld: running");
        }
        Ok(_) => {
            let _ = writeln!(out, "firewalld: NOT running");
        }
        Err(_) => {
            let _ = writeln!(out, "firewalld: firewall-cmd unavailable");
        }
    }

    let _ = writeln!(out, "\n[selected configuration]");
    let _ = writeln!(
        out,
        "reality.handshake_server: {}",
        cfg.reality.handshake_server
    );
    let _ = writeln!(out, "reality.listen_port: {}", cfg.reality.listen_port);
    let _ = writeln!(out, "hysteria2.listen_port: {}", cfg.hysteria2.listen_port);
    let _ = writeln!(out, "state_dir: {}", cfg.state_dir.display());
    let _ = writeln!(out, "singbox_binary: {}", cfg.singbox_binary.display());

    let _ = writeln!(out, "\n[recent log tail (redacted)]");
    match std::process::Command::new("journalctl")
        .args([
            "-u",
            "sing-box",
            "-u",
            "vpn-subscription",
            "-n",
            "80",
            "--no-pager",
            "--no-hostname",
        ])
        .output()
    {
        Ok(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout);
            let _ = writeln!(out, "{}", redact_secrets(&raw));
        }
        _ => {
            let _ = writeln!(out, "journalctl unavailable or not permitted");
        }
    }

    match output {
        Some(path) => {
            std::fs::write(path, &out).with_context(|| format!("writing report to {path:?}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("setting mode 0600 on {path:?}"))?;
            }
            println!("Wrote sanitized diagnostic report to {path:?}");
        }
        None => print!("{out}"),
    }
    Ok(())
}

/// Redacts substrings that look like secrets (VLESS UUIDs, hex-encoded
/// keys/hashes, base64url-ish tokens/passwords, `Bearer `-prefixed
/// tokens) from free-form text such as a log tail, without a regex
/// dependency. Deliberately over-inclusive: a false-positive redaction
/// (hiding something that wasn't actually secret) is the safe failure
/// mode for a report meant to be pasted somewhere else; a missed
/// redaction is not. Splits on any byte that cannot appear inside a
/// UUID/hex/base64url token, so surrounding punctuation/whitespace is
/// preserved verbatim.
fn redact_secrets(text: &str) -> String {
    fn is_token_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
    }
    fn looks_like_uuid(tok: &str) -> bool {
        let parts: Vec<&str> = tok.split('-').collect();
        parts.len() == 5
            && [8, 4, 4, 4, 12]
                .iter()
                .zip(parts.iter())
                .all(|(len, p)| p.len() == *len && p.bytes().all(|b| b.is_ascii_hexdigit()))
    }
    fn looks_like_secret_token(tok: &str) -> bool {
        if tok.len() < 24 {
            return false;
        }
        if tok.bytes().all(|b| b.is_ascii_hexdigit()) {
            return true; // hex key/hash/password material
        }
        // base64url-ish random token (REALITY keys, subscription
        // tokens, Hysteria2/obfuscation passwords are generated in
        // this shape elsewhere in this crate — see credentials.rs).
        tok.bytes().all(is_token_byte)
            && tok.bytes().any(|b| b.is_ascii_alphabetic())
            && tok
                .bytes()
                .any(|b| b.is_ascii_digit() || b == b'-' || b == b'_')
    }

    // Token runs are ASCII-only by construction (`is_token_byte`), so
    // scanning by byte offset for token boundaries is safe as long as
    // every non-token span is re-emitted through the original `&str`
    // slice rather than reconstructed byte-by-byte — that keeps
    // multi-byte UTF-8 text (non-English log content) intact instead of
    // corrupting it one raw byte at a time.
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut plain_start = 0;
    while i < bytes.len() {
        if is_token_byte(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_token_byte(bytes[i]) {
                i += 1;
            }
            let tok = &text[start..i];
            if looks_like_uuid(tok) || looks_like_secret_token(tok) {
                out.push_str(&text[plain_start..start]);
                out.push_str("<redacted>");
                plain_start = i;
            }
        } else {
            i += 1;
        }
    }
    out.push_str(&text[plain_start..]);
    out
}

/// L4, always run, no network/subprocess involved: render the sing-box
/// server config AND the client subscription the live `vpn-subscription`
/// service would hand a real user right now, from the SAME in-memory
/// load of the current REALITY key files + `users.json`, and assert the
/// client's `public_key`/`short_id` are exactly what the server config
/// accepts. This alone is a regression guard (it re-exercises the real
/// render functions on every `doctor` run, not just in unit tests) — it
/// cannot, by itself, catch a *running* subscription process serving a
/// stale in-memory key from before its last restart, because both
/// renders here read the same on-disk files in the same process.
///
/// The second half closes exactly that gap without touching the
/// network: compare the sing-box `config.json` ALREADY on disk (the
/// config the last `systemctl reload-or-restart sing-box` actually
/// picked up) against what would be rendered right now from the current
/// files. If they differ, `vpn-admin render-config` was never re-run
/// after the REALITY key files or `users.json` changed — sing-box may
/// be enforcing different key material than the subscription service is
/// currently advertising to brand-new clients. This is the exact
/// "server and subscription-service disagree about REALITY key
/// material" incident class, caught from file contents alone. Private
/// key material is compared only via a SHA-256 fingerprint, never the
/// raw value.
/// IPv6 policy check (spec: "either IPv6 works through the VPN
/// correctly, or the system clearly prevents IPv6 leakage — never leave
/// a partially working IPv6 path"). Resolves `public_host` and reports
/// which address families it has DNS records for, then — only if an
/// AAAA record exists — probes whether this host actually has working
/// IPv6 egress. A mismatch (AAAA advertised, IPv6 egress unverifiable)
/// is exactly the ambiguous state the spec asks to surface explicitly,
/// so it is `[WARN]`, not `[FAIL]` (this check cannot see the client's
/// own network, only the server's) and not silently `[OK]`.
/// The DNS-and-egress state that decides how IPv6 is reported by
/// `check_public_hostname_and_ipv6_policy`. Factored out as a plain enum
/// (no I/O) so the fatality decision below is unit-testable without a
/// real resolver or a real UDP socket — see `ipv6_posture_tests`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ipv6Posture {
    /// No AAAA record at all. IPv6 was never advertised as working, so
    /// this VPS's own IPv6 egress (or lack of it) is irrelevant — an
    /// IPv4-only host (the common case, e.g. a plain EC2 box) must never
    /// be reported as failing over this.
    NoAaaa,
    /// AAAA exists and the IPv6 UDP egress probe positively succeeded.
    AaaaEgressOk,
    /// AAAA exists and the IPv6 UDP egress probe positively observed
    /// broken egress — IPv6-preferring clients would be stranded. This
    /// is the one case that stays fatal.
    AaaaEgressBroken,
    /// AAAA exists but the probe itself could not run (no socket
    /// permission, etc.) — inconclusive, never escalated to a failure.
    AaaaEgressUnknown,
}

fn classify_ipv6_posture(has_aaaa: bool, probe: Option<bool>) -> Ipv6Posture {
    if !has_aaaa {
        return Ipv6Posture::NoAaaa;
    }
    match probe {
        Some(true) => Ipv6Posture::AaaaEgressOk,
        Some(false) => Ipv6Posture::AaaaEgressBroken,
        None => Ipv6Posture::AaaaEgressUnknown,
    }
}

/// `(status, increment_failures, message)` for a given posture. This is
/// the ONLY place in the codebase that decides whether an IPv6 egress
/// finding is fatal — kept as a single pure mapping so
/// `check_public_hostname_and_ipv6_policy` (the only caller) and its
/// tests cannot drift apart.
fn ipv6_posture_report(posture: Ipv6Posture) -> (CheckStatus, bool, &'static str) {
    match posture {
        Ipv6Posture::NoAaaa => (
            CheckStatus::Info,
            false,
            "public hostname has no AAAA/IPv6 record — IPv6-capable clients will connect over \
             IPv4 only, which avoids IPv6-leak risk but means an IPv6-only client network cannot \
             reach this deployment at all",
        ),
        Ipv6Posture::AaaaEgressOk => (
            CheckStatus::Ok,
            false,
            "public hostname has an AAAA record and this VPS has working IPv6 UDP egress",
        ),
        Ipv6Posture::AaaaEgressBroken => (
            CheckStatus::Fail,
            true,
            "public hostname has an AAAA record but this VPS's IPv6 egress appears blocked — \
             IPv6-preferring clients may fail to connect at all while IPv4 clients work fine. \
             Either fix VPS IPv6 routing or remove the AAAA record so clients fall back to IPv4.",
        ),
        Ipv6Posture::AaaaEgressUnknown => (
            CheckStatus::Warn,
            false,
            "public hostname has an AAAA record but server IPv6 connectivity could not be \
             verified from this host (probe unavailable) — this does NOT confirm IPv6 works, \
             only that it could not be checked here",
        ),
    }
}

fn check_public_hostname_and_ipv6_policy(cfg: &DeploymentConfig, failures: &mut u32) {
    use std::net::IpAddr;

    let resolved = match (cfg.public_host.as_str(), 0u16).to_socket_addrs() {
        Ok(iter) => iter.map(|a| a.ip()).collect::<Vec<IpAddr>>(),
        Err(e) => {
            report_check(
                CheckStatus::Fail,
                "L2",
                format!(
                    "public hostname {:?} does not resolve: {e}",
                    cfg.public_host
                ),
            );
            *failures += 1;
            return;
        }
    };
    if resolved.is_empty() {
        report_check(
            CheckStatus::Fail,
            "L2",
            format!(
                "public hostname {:?} resolved zero addresses",
                cfg.public_host
            ),
        );
        *failures += 1;
        return;
    }
    let has_v4 = resolved.iter().any(|a| a.is_ipv4());
    let has_v6 = resolved.iter().any(|a| a.is_ipv6());
    report_check(
        CheckStatus::Ok,
        "L2",
        format!(
            "public hostname {:?} resolves ({} A/IPv4, {} AAAA/IPv6 address(es))",
            cfg.public_host,
            resolved.iter().filter(|a| a.is_ipv4()).count(),
            resolved.iter().filter(|a| a.is_ipv6()).count(),
        ),
    );
    if !has_v4 {
        report_check(
            CheckStatus::Warn,
            "L2",
            "public hostname has no A/IPv4 record — clients on IPv4-only networks cannot connect",
        );
    }
    if !has_v6 {
        let (status, increment, msg) = ipv6_posture_report(classify_ipv6_posture(false, None));
        report_check(status, "L2", msg);
        if increment {
            *failures += 1;
        }
        return;
    }

    // AAAA exists: verify this VPS itself actually has usable IPv6
    // egress before claiming IPv6 "works". sing-box's listeners bind
    // `::` (dual-stack) regardless (see crates/compat-config/src/
    // server.rs), so an AAAA record with no real server-side IPv6
    // connectivity would silently strand IPv6-preferring clients. This
    // is the ONLY IPv6 UDP egress probe run anywhere in `doctor` — see
    // the comment in the blanket Hysteria2 UDP egress block above for
    // why the old, unconditional (AAAA-blind) IPv6 probe was removed:
    // it used to fail hard on IPv4-only hosts with no AAAA record at
    // all, blaming an unrelated diagnostic for what was otherwise a
    // fully passing VLESS+REALITY acceptance run.
    let probe_cfg = cfg.udp_probe_config();
    let ipv6_refs: Vec<&str> = probe_cfg
        .ipv6_resolvers
        .iter()
        .map(|s| s.as_str())
        .collect();
    let timeout = std::time::Duration::from_millis(probe_cfg.timeout_ms);
    let probe_result = run_udp_probe_candidates(
        &ipv6_refs,
        timeout,
        probe_cfg.retries,
        std::time::Duration::from_millis(probe_cfg.delay_ms),
    );
    let (status, increment, msg) = ipv6_posture_report(classify_ipv6_posture(true, probe_result));
    report_check(status, "L2", msg);
    if increment {
        *failures += 1;
    }
}

/// Version-consistency check (spec item I). A real incident class: an
/// operator upgrades via one install path (e.g. a package manager
/// putting a binary at `/usr/bin/sing-box`) while systemd/vpn-admin
/// keep running an older binary at a different, still-present path
/// (e.g. `/usr/local/bin/sing-box`) — every other check in `doctor`
/// only ever inspects the ONE binary at `cfg.singbox_binary`, so it
/// cannot see this class of drift by construction. This check is
/// read-only: it never changes which binary is active.
fn check_singbox_binary_version_consistency(cfg: &DeploymentConfig) {
    let candidates: Vec<std::path::PathBuf> = vec![
        cfg.singbox_binary.clone(),
        std::path::PathBuf::from("/usr/local/bin/sing-box"),
        std::path::PathBuf::from("/usr/bin/sing-box"),
    ];
    let found = probe_singbox_binary_versions(&candidates, |path| {
        std::process::Command::new(path).arg("version").output()
    });
    if let Some((status, message)) = singbox_version_consistency_report(&found, &cfg.singbox_binary)
    {
        report_check(status, "L2", message);
    }
}

/// Runs `<path> version` for every existing, deduplicated candidate
/// path and captures its first output line. `run` is injected so the
/// pure decision logic below (`singbox_version_consistency_report`) can
/// be unit-tested without spawning real processes or touching the real
/// filesystem at fixed system paths like `/usr/bin/sing-box`.
fn probe_singbox_binary_versions(
    candidates: &[std::path::PathBuf],
    run: impl Fn(&std::path::Path) -> std::io::Result<std::process::Output>,
) -> Vec<(std::path::PathBuf, String)> {
    let mut deduped = candidates.to_vec();
    deduped.sort();
    deduped.dedup();

    let mut found = Vec::new();
    for path in deduped {
        if !path.exists() {
            continue;
        }
        match run(&path) {
            Ok(o) if o.status.success() => {
                let text = String::from_utf8_lossy(&o.stdout);
                let first_line = text.lines().next().unwrap_or("").trim().to_string();
                found.push((path, first_line));
            }
            _ => found.push((path, "(version unavailable)".to_string())),
        }
    }
    found
}

/// Pure decision logic: given the set of sing-box binaries actually
/// found on this host and what each reported for `version`, decide
/// whether to say anything at all (a single binary is the common case
/// and produces no extra noise), and if so whether it's a clean `[OK]`
/// (multiple binaries, same version — e.g. a symlink situation) or a
/// `[WARN]` (multiple binaries, differing versions — the drift class
/// this check exists to catch).
fn singbox_version_consistency_report(
    found: &[(std::path::PathBuf, String)],
    configured_binary: &std::path::Path,
) -> Option<(CheckStatus, String)> {
    if found.len() <= 1 {
        return None;
    }
    let versions: std::collections::HashSet<&str> = found.iter().map(|(_, v)| v.as_str()).collect();
    if versions.len() == 1 {
        return Some((
            CheckStatus::Ok,
            format!(
                "{} sing-box binaries found on this host, all report the same version",
                found.len()
            ),
        ));
    }
    let mut lines =
        vec!["multiple sing-box installations detected with DIFFERING versions:".to_string()];
    for (path, version) in found {
        lines.push(format!("  {} -> {version}", path.display()));
    }
    lines.push(format!(
        "  systemd/vpn-admin currently uses: {}",
        configured_binary.display()
    ));
    Some((CheckStatus::Warn, lines.join("\n")))
}

fn check_l4_subscription_coherence(cfg: &DeploymentConfig, failures: &mut u32) {
    let reality = match load_reality_params(cfg) {
        Ok(r) => r,
        Err(e) => {
            report_check(
                CheckStatus::Warn,
                "L4",
                format!("skipping subscription-coherence check: {e}"),
            );
            return;
        }
    };
    let users = match store::load_users(&cfg.users_file()) {
        Ok(u) => u,
        Err(e) => {
            report_check(
                CheckStatus::Warn,
                "L4",
                format!("skipping subscription-coherence check: user store unreadable ({e})"),
            );
            return;
        }
    };
    let hysteria = load_hysteria_params(cfg);
    let ports = ServerPorts {
        vless_reality_port: cfg.reality.listen_port,
        hysteria2_port: cfg.hysteria2.listen_port,
    };
    let now = UnixSeconds::now().0 as i64;
    let fresh_server_doc = render_singbox_server_config(&users, &reality, &hysteria, ports, now);

    // The EXACT same function `services/subscription`'s live process
    // calls to build its own `AppState.endpoints` — not a hand-rolled
    // equivalent construction on this side, which would only prove two
    // independent implementations agree by coincidence rather than that
    // they're actually computing the same thing. Paired with a
    // throwaway synthetic user that exists ONLY to exercise the render
    // function — never a real user's UUID/password, and never printed.
    let synthetic_user = CompatUser {
        id: "doctor-l4-synthetic".into(),
        name: "doctor-l4-synthetic".into(),
        enabled: true,
        vless_uuid: "00000000-0000-4000-8000-000000000000".into(),
        hysteria2_password: SecretString::new("unused"),
        subscription_token_hash_hex: String::new(),
        created_at: 0,
        expires_at: None,
    };
    let short_id = reality.short_ids.first().cloned().unwrap_or_default();
    let endpoints = compat_config::render::standard_endpoints(
        &cfg.public_host,
        cfg.reality.listen_port,
        cfg.hysteria2.listen_port,
        &reality.public_key_hex,
        &short_id,
        &reality.handshake_server,
        hysteria.obfs_password.as_ref().map(|s| s.expose()),
    );
    let client_doc = match render_singbox_client_subscription(&synthetic_user, &endpoints) {
        Ok(d) => d,
        Err(e) => {
            report_check(
                CheckStatus::Fail,
                "L4",
                format!("failed to render client subscription for coherence check: {e}"),
            );
            *failures += 1;
            return;
        }
    };

    let server_short_ids: Vec<String> = fresh_server_doc["inbounds"][0]["tls"]["reality"]
        ["short_id"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let client_short_id = client_doc["outbounds"][0]["tls"]["reality"]["short_id"]
        .as_str()
        .unwrap_or("");
    let client_pubkey = client_doc["outbounds"][0]["tls"]["reality"]["public_key"]
        .as_str()
        .unwrap_or("");

    if server_short_ids.iter().any(|s| s == client_short_id)
        && client_pubkey == reality.public_key_hex
    {
        report_check(
            CheckStatus::Ok,
            "L4",
            "subscription render coherence: the client subscription's public_key/short_id match \
             what the current server config accepts",
        );
    } else {
        report_check(
            CheckStatus::Fail,
            "L4",
            format!(
                "subscription render coherence FAILED: the client subscription would advertise \
                 short_id={client_short_id:?}, but the server config accepts short_id(s)={server_short_ids:?} \
                 — a real client using this subscription would fail REALITY's handshake (\"processed \
                 invalid connection\"). This indicates a bug in the render code paths, not a config \
                 file problem — do not attempt to fix by rotating keys."
            ),
        );
        *failures += 1;
    }

    let target = cfg.singbox_config_file();
    if !target.exists() {
        report_check(
            CheckStatus::Warn,
            "L4",
            "sing-box config.json not yet rendered — on-disk drift check skipped",
        );
        return;
    }
    let on_disk_bytes = match std::fs::read(&target) {
        Ok(b) => b,
        Err(e) => {
            report_check(
                CheckStatus::Warn,
                "L4",
                format!("could not read on-disk sing-box config.json to check for drift: {e}"),
            );
            return;
        }
    };
    let on_disk: serde_json::Value = match serde_json::from_slice(&on_disk_bytes) {
        Ok(v) => v,
        Err(e) => {
            report_check(
                CheckStatus::Warn,
                "L4",
                format!("could not parse on-disk sing-box config.json to check for drift: {e}"),
            );
            return;
        }
    };
    if on_disk == fresh_server_doc {
        report_check(
            CheckStatus::Ok,
            "L4",
            "on-disk sing-box config.json exactly matches the complete authorization/key/cert \
             document current state would render (not stale)",
        );
    } else {
        report_check(
            CheckStatus::Fail,
            "L4",
            "on-disk sing-box config.json does NOT exactly match current users/expiry/REALITY/\
             Hysteria state — sing-box (as of its last reload) may be enforcing stale \
             authorization or key material. Run \
             `vpn-admin render-config` to resync, then confirm with `systemctl status sing-box`.",
        );
        *failures += 1;
    }
}

/// The check above (`check_l4_subscription_coherence`) can only prove
/// what a FRESH read of the current files would produce — it cannot see
/// what the ALREADY-RUNNING `vpn-subscription` PROCESS actually has
/// cached in memory, because `vpn-subscription` reads its REALITY public
/// key/short_id from disk exactly once, at its own startup, and has no
/// config-reload path (`services/subscription/src/main.rs`). A process
/// that started before the on-disk keys last changed — a restart that
/// silently failed, a `reload-or-restart` that degraded to `reload`
/// against a unit that doesn't actually support it, a code path this
/// audit didn't cover — would pass every check above and still be
/// serving stale key material to every real client that fetches a
/// subscription from it right now. This is the exact incident class
/// that motivated this whole diagnostic layer; a check that can't
/// observe the live process isn't actually verifying it.
///
/// This check closes that gap by asking the running process itself: it
/// fetches `GET /internal/state-fingerprint` from `vpn-subscription`'s
/// own loopback listener (`services/subscription/src/lib.rs`,
/// `state_fingerprint`) — a SHA-256 fingerprint of its actual in-memory
/// `AppState.endpoints`, never the raw key/short_id — and compares it
/// against a fingerprint of what a fresh read of the current files would
/// produce (via the SAME `standard_endpoints`/`endpoints_fingerprint`
/// functions `vpn-subscription` itself uses). Agreement is a hard
/// `[FAIL]`-eligible property, not advisory: a mismatch means a real
/// client fetching a subscription right now gets different REALITY key
/// material than `sing-box` is enforcing, which is precisely how the
/// original incident manifested. Unreachable (service not running, not
/// on loopback here, firewalled) is `[WARN]`, not `[FAIL]` — that is a
/// "cannot verify" outcome, not a proven mismatch, and this function
/// must not conflate the two.
fn check_l4_live_subscription_process_state(cfg: &DeploymentConfig, failures: &mut u32) {
    let reality = match load_reality_params(cfg) {
        Ok(r) => r,
        Err(e) => {
            report_check(
                CheckStatus::Warn,
                "L4",
                format!("skipping live subscription-process check: {e}"),
            );
            return;
        }
    };
    let short_id = reality.short_ids.first().cloned().unwrap_or_default();
    let hysteria = load_hysteria_params(cfg);
    let expected_endpoints = compat_config::render::standard_endpoints(
        &cfg.public_host,
        cfg.reality.listen_port,
        cfg.hysteria2.listen_port,
        &reality.public_key_hex,
        &short_id,
        &reality.handshake_server,
        hysteria.obfs_password.as_ref().map(|s| s.expose()),
    );
    let expected_fingerprint = compat_config::render::endpoints_fingerprint(&expected_endpoints);

    let response = http_get_local_json(
        cfg.subscription.listen_port,
        "/internal/state-fingerprint",
        std::time::Duration::from_millis(800),
    );
    let live_fingerprint = match response {
        Ok(json) => match json["endpoints_fingerprint_sha256"].as_str() {
            Some(fp) => fp.to_string(),
            None => {
                report_check(
                    CheckStatus::Warn,
                    "L4",
                    "vpn-subscription's /internal/state-fingerprint responded with an unexpected \
                     shape — cannot verify the running process's live state (this may indicate a \
                     version skew between vpn-admin and vpn-subscription-svc).",
                );
                return;
            }
        },
        Err(e) => {
            report_check(
                CheckStatus::Warn,
                "L4",
                format!(
                    "cannot reach the running vpn-subscription process on \
                     127.0.0.1:{} to verify its LIVE state (not the same as proving it's stale — \
                     only that this check could not observe it): {e}",
                    cfg.subscription.listen_port
                ),
            );
            return;
        }
    };

    if live_fingerprint == expected_fingerprint {
        report_check(
            CheckStatus::Ok,
            "L4",
            "the ALREADY-RUNNING vpn-subscription process's live in-memory state matches current \
             REALITY key files/deployment config (verified via its own /internal/state-fingerprint \
             endpoint, not just a fresh disk read that a stale process would also pass)",
        );
    } else {
        report_check(
            CheckStatus::Fail,
            "L4",
            "the RUNNING vpn-subscription process is serving STALE state that does not match the \
             current REALITY key files/deployment config — every real client fetching a \
             subscription right now receives different key material than sing-box is enforcing. \
             This is the exact production incident class. Fix: `systemctl restart vpn-subscription` \
             (a plain reload is not sufficient — this process has no config-reload path), then \
             re-run `vpn-admin doctor` to confirm the fingerprints now agree.",
        );
        *failures += 1;
    }
}

fn tcp_port_reachable(host: &str, port: u16, timeout: std::time::Duration) -> bool {
    use std::net::ToSocketAddrs;
    let addr = match format!("{host}:{port}").to_socket_addrs() {
        Ok(mut it) => match it.next() {
            Some(a) => a,
            None => return false,
        },
        Err(_) => return false,
    };
    std::net::TcpStream::connect_timeout(&addr, timeout).is_ok()
}

/// Minimal UDP DNS probe for basic outbound-UDP capability checks.
///
/// Returns Some(true) if a UDP DNS response was successfully received,
/// Some(false) if the probe completed with no response (indicating a
/// likely block), and None if the environment prevented running the
/// probe (socket bind failure, unsupported platform, etc.). Uses a
/// plain DNS A query for `example.com` sent to the provided IP
/// (e.g. "1.1.1.1" or "8.8.8.8").
fn build_dns_query(name: &str) -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: standard query, recursion desired
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT, ARCOUNT = 0
    ];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00); // end of QNAME
                  // QTYPE and QCLASS IN
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    q
}

fn udp_dns_probe(resolver_ip: &str, timeout: std::time::Duration) -> Option<bool> {
    use std::net::{SocketAddr, UdpSocket};

    let query = build_dns_query("example.com");

    // Bind to an ephemeral UDP socket on all interfaces (IPv4).
    let bind_addr = match "0.0.0.0:0".parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => return None,
    };
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let _ = socket.set_read_timeout(Some(timeout));
    let _ = socket.set_write_timeout(Some(timeout));

    let target = format!("{resolver_ip}:53");
    let target_addr = match target.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => return None,
    };

    if socket.send_to(&query, target_addr).is_err() {
        return Some(false);
    }
    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((n, _)) => Some(n > 0),
        Err(_) => Some(false),
    }
}

/// IPv6 variant of the UDP DNS probe. Binds to the IPv6 unspecified
/// address and dials a bracketed IPv6 resolver address like
/// `[2606:4700:4700::1111]:53`.
fn udp_dns_probe_v6(resolver_ip: &str, timeout: std::time::Duration) -> Option<bool> {
    use std::net::{SocketAddr, UdpSocket};

    let query = build_dns_query("example.com");

    // Bind to an ephemeral UDP socket on all interfaces (IPv6).
    let bind_addr = match "[::]:0".parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => return None,
    };
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(_) => return None,
    };
    let _ = socket.set_read_timeout(Some(timeout));
    let _ = socket.set_write_timeout(Some(timeout));

    let target = format!("[{resolver_ip}]:53");
    let target_addr = match target.parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => return None,
    };

    if socket.send_to(&query, target_addr).is_err() {
        return Some(false);
    }
    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((n, _)) => Some(n > 0),
        Err(_) => Some(false),
    }
}

/// Try multiple resolver candidates with retries and inter-attempt delay.
///
/// Returns Some(true) if any candidate returned a positive response,
/// Some(false) if probes ran but none responded, and None if every
/// attempt failed to run (e.g., socket bind errors across attempts).
fn run_udp_probe_candidates_with_probe<F>(
    candidates: &[&str],
    timeout: std::time::Duration,
    retries: usize,
    delay: std::time::Duration,
    mut probe: F,
) -> Option<bool>
where
    F: FnMut(&str, std::time::Duration) -> Option<bool>,
{
    let mut any_ran = false;
    for &cand in candidates {
        for attempt in 0..retries {
            let outcome = probe(cand, timeout);
            match outcome {
                Some(true) => return Some(true),
                Some(false) => {
                    any_ran = true;
                    // try again or next resolver
                }
                None => {
                    // probe could not be executed for this candidate/attempt
                }
            }
            if attempt + 1 < retries {
                std::thread::sleep(delay);
            }
        }
    }
    if !any_ran {
        None
    } else {
        Some(false)
    }
}

fn run_udp_probe_candidates(
    candidates: &[&str],
    timeout: std::time::Duration,
    retries: usize,
    delay: std::time::Duration,
) -> Option<bool> {
    run_udp_probe_candidates_with_probe(candidates, timeout, retries, delay, |cand, to| {
        if cand.contains(":") {
            udp_dns_probe_v6(cand, to)
        } else {
            udp_dns_probe(cand, to)
        }
    })
}

/// Minimal, dependency-free HTTP/1.0 GET over loopback: connect, send a
/// bare request with `Connection: close`, read the whole response (the
/// server closes after writing it, since we asked for that), split the
/// status line, headers, and body, and parse the body as JSON. Good
/// enough for talking to `vpn-subscription`'s own loopback-only
/// `/internal/state-fingerprint` — not a general-purpose HTTP client,
/// and deliberately not pulling in `reqwest` just for one same-host GET.
fn http_get_local_json(
    port: u16,
    path: &str,
    timeout: std::time::Duration,
) -> Result<serde_json::Value> {
    use std::io::{Read, Write};
    let mut stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}")
            .parse()
            .context("building loopback address")?,
        timeout,
    )
    .with_context(|| format!("connecting to 127.0.0.1:{port}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .context("writing HTTP request")?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .context("reading HTTP response")?;
    let text = String::from_utf8_lossy(&response);
    let mut parts = text.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("");
    let status_line = head.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") {
        bail!("unexpected HTTP status from {path}: {status_line:?}");
    }
    serde_json::from_str(body).with_context(|| format!("parsing JSON body from {path}: {body:?}"))
}

/// Best-effort L5/L6, only run with `doctor --protocol`: spin up the
/// REAL `sing-box` binary as a throwaway client process pointed at this
/// server's OWN VLESS+REALITY listener on `127.0.0.1`, using the live
/// REALITY public_key/short_id read from the CURRENT on-disk key files
/// — the same source `vpn-subscription` reads at its own startup, but
/// note this self-test builds its client config directly from those
/// files itself, so a clean PASS here proves the on-disk key material
/// is internally coherent with what `sing-box` enforces, but does NOT
/// by itself prove the ALREADY-RUNNING `vpn-subscription` process is
/// advertising the same thing — that is what
/// `check_l4_live_subscription_process_state` (run unconditionally,
/// every `doctor` invocation) exists to verify separately, by asking
/// that process directly rather than re-deriving from disk. Uses an
/// enabled, unexpired user's VLESS UUID and requires application bytes
/// from the local subscription health endpoint. A successful SOCKS
/// CONNECT reply alone is not evidence that VLESS authentication was
/// accepted by the server.
///
/// Gated on `sing-box` being present AND the port actually being
/// reachable on loopback; anything else is `[WARN] cannot self-test:
/// <reason>` — a self-test that can't run here says so, it does not
/// fake a pass.
///
/// A client-side REALITY verification rejection is a hard failure. A
/// timeout or missing prerequisite is a warning by default because it
/// can be environmental; `--require-protocol` promotes that uncertainty
/// to a failure for installation acceptance checks.
fn report_protocol_unavailable(
    require_protocol: bool,
    failures: &mut u32,
    message: impl AsRef<str>,
) {
    if require_protocol {
        report_check(CheckStatus::Fail, "L5-6", message.as_ref());
        *failures += 1;
    } else {
        report_check(CheckStatus::Warn, "L5-6", message.as_ref());
    }
}

/// Outcome of `verify_reality_handshake_or_warn`. Deliberately distinct
/// from a bare `Option<RealitySelfTestOutcome>`: that shape let a caller
/// print a single unconditional "handshake self-test passed" message
/// regardless of whether a handshake was ever actually attempted (a
/// fresh deployment with no active user, or a rotation with no sing-box
/// binary, both produced `None`, and the caller's success text did not
/// distinguish that from `Some(Pass)`). `NotRun` carries the reason so a
/// caller can — and must — say plainly that verification did not happen
/// and why, instead of staying silent about the gap.
enum HandshakeVerification {
    Ran(RealitySelfTestOutcome),
    NotRun(String),
}

/// Runs the real REALITY handshake self-test against candidate/live key
/// material as a live-health gate for the apply/rotate transactions (not
/// just `doctor --protocol`, which is diagnostic-only and never blocks
/// anything). `NotRun` means the check could not run at all — no
/// sing-box binary, no enabled/unexpired user to test with (e.g. a
/// brand-new deployment with zero users yet), or a harness setup
/// failure — and callers must treat that as "not verified," never as a
/// pass. Only `Ran(HandshakeRejected)` is meant to block a transaction;
/// `Ran(Pass)`/`Ran(Inconclusive)` are informational.
fn verify_reality_handshake_or_warn(
    cfg: &DeploymentConfig,
    users: &[CompatUser],
    reality: &RealityServerParams,
    reality_port: u16,
) -> HandshakeVerification {
    if !cfg.singbox_binary.exists() {
        return HandshakeVerification::NotRun(format!(
            "no sing-box binary at {:?}",
            cfg.singbox_binary
        ));
    }
    let now = UnixSeconds::now().0 as i64;
    let Some(test_user) = users.iter().find(|u| u.is_active(now)) else {
        return HandshakeVerification::NotRun(
            "no enabled, unexpired VLESS user to test with".to_string(),
        );
    };
    match run_reality_client_selftest(cfg, reality, test_user, reality_port) {
        Ok(outcome) => HandshakeVerification::Ran(outcome),
        Err(e) => HandshakeVerification::NotRun(format!("self-test harness failed: {e:#}")),
    }
}

fn listener_reported_by_ss(port: u16, udp: bool) -> Option<bool> {
    let args = if udp { ["-H", "-lun"] } else { ["-H", "-ltn"] };
    let output = std::process::Command::new("ss").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let suffix = format!(":{port}");
    let text = String::from_utf8_lossy(&output.stdout);
    Some(text.lines().any(|line| {
        line.split_whitespace().any(|field| {
            field == suffix || field.ends_with(&suffix) || field.contains(&format!("]{suffix}"))
        })
    }))
}

/// Returns the exact outcome of the L5-6 real-protocol self-test as a
/// `ProtocolCheckResult` — never a `bool`, and never something the
/// caller has to re-derive from `failures`. `NotRun` means every
/// pre-flight check bailed before a single packet was sent (missing
/// binary, missing keys, no active user, or a harness setup failure) —
/// the caller must not treat that the same as a completed,
/// interpretable self-test. This is what `cmd_doctor` uses to decide
/// exactly what the coverage line can honestly say about L5-6,
/// regardless of whether `--protocol` was merely passed on the command
/// line and regardless of the unrelated L1-4 failure count.
fn check_l5_l6_protocol_selftest(
    cfg: &DeploymentConfig,
    failures: &mut u32,
    require_protocol: bool,
) -> ProtocolCheckResult {
    if !cfg.singbox_binary.exists() {
        report_protocol_unavailable(
            require_protocol,
            failures,
            format!(
                "cannot self-test: sing-box binary not found at {:?}",
                cfg.singbox_binary
            ),
        );
        return ProtocolCheckResult::NotRun;
    }
    let reality = match load_reality_params(cfg) {
        Ok(r) => r,
        Err(e) => {
            report_protocol_unavailable(
                require_protocol,
                failures,
                format!("cannot self-test: {e}"),
            );
            return ProtocolCheckResult::NotRun;
        }
    };
    let users = match store::load_users(&cfg.users_file()) {
        Ok(users) => users,
        Err(e) => {
            report_protocol_unavailable(
                require_protocol,
                failures,
                format!("cannot self-test: failed to load users: {e}"),
            );
            return ProtocolCheckResult::NotRun;
        }
    };
    let now = UnixSeconds::now().0 as i64;
    let Some(test_user) = users.iter().find(|user| user.is_active(now)) else {
        report_protocol_unavailable(
            require_protocol,
            failures,
            "cannot self-test: there is no enabled, unexpired VLESS user",
        );
        return ProtocolCheckResult::NotRun;
    };
    let port = cfg.reality.listen_port;

    match run_reality_client_selftest(cfg, &reality, test_user, port) {
        Ok(RealitySelfTestOutcome::Pass) => {
            report_check(
                CheckStatus::Ok,
                "L5-6",
                format!(
                    "protocol self-test: a throwaway sing-box client using the CURRENT REALITY \
                     public_key/short_id and an active VLESS user completed a full handshake \
                     through 127.0.0.1:{port} and returned application bytes end-to-end"
                ),
            );
            ProtocolCheckResult::Passed
        }
        Ok(RealitySelfTestOutcome::HandshakeRejected) => {
            report_check(
                CheckStatus::Fail,
                "L5-6",
                format!(
                    "protocol self-test FAILED: a throwaway sing-box client using the CURRENT \
                     REALITY public_key/short_id could not complete a handshake through \
                     127.0.0.1:{port}. A real Hiddify client using this same key material would \
                     fail identically.\n\
                     \n\
                     TWO DIFFERENT CAUSES produce this, and sing-box logs the SAME message \
                     (\"REALITY: processed invalid connection\") for both — do not assume the \
                     first one:\n\
                     \n\
                     (a) The REALITY key material really is mismatched. The L4 checks above test \
                     exactly that; if they passed, this is NOT your cause.\n\
                     \n\
                     (b) The configured handshake_server (\"{decoy}\") returns a TLS 1.3 flight \
                     that sing-box's REALITY implementation refuses. It rejects ANY record larger \
                     than its hard-coded 8192-byte budget (metacubex/utls reality.go: \
                     `if handshakeLen > int(realitySize) {{ break f }}`), which an oversized \
                     certificate chain easily exceeds. Authentication SUCCEEDS and the connection \
                     is still dropped. This is edge- and CDN-dependent, so it can appear without \
                     any change on your side. Try a different handshake_server and re-run this \
                     check.",
                    decoy = reality.handshake_server
                ),
            );
            *failures += 1;
            ProtocolCheckResult::Failed
        }
        Ok(RealitySelfTestOutcome::Inconclusive) => {
            report_protocol_unavailable(
                require_protocol,
                failures,
                "protocol self-test INCONCLUSIVE: the client did not return an HTTP success \
                 response through the live VLESS+REALITY listener. This can be an \
                 authentication, routing, decoy, listener, or transient failure; inspect both \
                 sing-box processes' logs.",
            );
            ProtocolCheckResult::Inconclusive
        }
        Err(e) => {
            report_protocol_unavailable(
                require_protocol,
                failures,
                format!("cannot self-test: {e}"),
            );
            ProtocolCheckResult::NotRun
        }
    }
}

/// Runs the actual throwaway client + SOCKS probe for
/// `check_l5_l6_protocol_selftest`. `Ok(RealitySelfTestOutcome)` is a
/// verdict about the relay/server; `Err` means the self-test harness
/// itself failed to set up (never a verdict about the server).
fn run_reality_client_selftest(
    cfg: &DeploymentConfig,
    reality: &RealityServerParams,
    test_user: &CompatUser,
    reality_port: u16,
) -> Result<RealitySelfTestOutcome> {
    // Fence the journal before creating our loopback client. Public scanners
    // routinely produce the same rejection string and must never be
    // attributed to this self-test.
    let journal_cursor = singbox_journal_cursor();
    let short_id = reality.short_ids.first().cloned().unwrap_or_default();

    // Reserve a free loopback port for the throwaway client's local
    // SOCKS inbound, then release it immediately before sing-box binds
    // it — a small, unavoidable race in a best-effort self-test, not a
    // correctness requirement.
    let local_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .context("reserving a local port for the throwaway client")?;
        listener.local_addr()?.port()
    };

    let client_config = json!({
        "log": { "level": "error" },
        "inbounds": [
            { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": local_port }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "reality-selftest",
                "server": "127.0.0.1",
                "server_port": reality_port,
                "uuid": test_user.vless_uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": true,
                    "server_name": reality.handshake_server,
                    "utls": { "enabled": true, "fingerprint": "chrome" },
                    "reality": {
                        "enabled": true,
                        "public_key": reality.public_key_hex,
                        "short_id": short_id,
                    }
                }
            },
            { "type": "direct", "tag": "direct" }
        ],
        "route": { "final": "reality-selftest" }
    });

    let tmp = tempfile::NamedTempFile::new().context("creating throwaway client config file")?;
    std::fs::write(tmp.path(), serde_json::to_vec_pretty(&client_config)?)
        .context("writing throwaway client config")?;

    let mut child = std::process::Command::new(&cfg.singbox_binary)
        .arg("run")
        .arg("-c")
        .arg(tmp.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning throwaway sing-box client")?;

    // Drain stderr on a background thread as it's produced (not after
    // the fact) — the pipe has a small OS buffer, and this process can
    // log continuously, so reading only after killing the child risks
    // blocking on a full pipe the child is also blocked writing to.
    // sing-box's own `errors.New("REALITY: processed invalid
    // connection")` (github.com/metacubex/utls, reality.go) and its
    // client-side counterpart `"reality verification failed"` are plain
    // static strings with no secret interpolated — safe to capture and
    // pattern-match on, unlike anything at `debug`/`trace` log level
    // (never enabled here; `client_config` above sets `"level": "error"`).
    let stderr_pipe = child.stderr.take().expect("stderr was piped");
    let stderr_capture = std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = String::new();
        let mut pipe = stderr_pipe;
        let _ = pipe.read_to_string(&mut buf);
        buf
    });

    // Always kill the throwaway client before returning on every path
    // below — never leave an orphaned sing-box process behind from a
    // diagnostic command.
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // Poll for the client's local SOCKS inbound to come up.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut client_bound = true;
    while !tcp_port_reachable(
        "127.0.0.1",
        local_port,
        std::time::Duration::from_millis(100),
    ) {
        if std::time::Instant::now() >= deadline {
            client_bound = false;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    let relay_ok = client_bound
        && socks5_http_get_succeeds(
            local_port,
            "127.0.0.1",
            cfg.subscription.listen_port,
            "/healthz",
            std::time::Duration::from_secs(4),
        );

    // Kill+reap now (releases the stderr pipe's write end so the reader
    // thread's `read_to_string` returns), THEN read what it captured —
    // ordering matters, joining first would deadlock against a child
    // that's still alive and still writing. Wrapping in the drop guard
    // even though we kill explicitly: if anything above this point had
    // returned early via `?`, the guard is what would have caught it —
    // kept for that safety net even though this exact path always kills
    // explicitly too (a second kill/wait on an already-reaped child in
    // `Drop` is a harmless no-op, ignored the same way as everywhere
    // else in this function).
    let mut guard = KillOnDrop(child);
    let _ = guard.0.kill();
    let _ = guard.0.wait();
    let captured_stderr = stderr_capture.join().unwrap_or_default();

    if relay_ok {
        return Ok(RealitySelfTestOutcome::Pass);
    }
    if reality_selftest_stderr_or_journal_indicates_rejection(
        &captured_stderr,
        server_journal_shows_local_processed_invalid_connection_after(journal_cursor.as_deref()),
    ) {
        return Ok(RealitySelfTestOutcome::HandshakeRejected);
    }
    Ok(RealitySelfTestOutcome::Inconclusive)
}

/// Hysteria2 counterpart to `RealitySelfTestOutcome`. Deliberately
/// coarser than REALITY's outcome: unlike REALITY (whose rejection
/// message is a well-known, string-matched constant — see
/// `reality_selftest_stderr_or_journal_indicates_rejection`), this
/// project has not catalogued sing-box's exact client-side error text
/// for a Hysteria2/QUIC authentication rejection, and guessing at an
/// unverified string match would risk a false hard `FAIL` — worse than
/// an honest "could not confirm." A failed dial is always
/// `Inconclusive`, never a confident rejection verdict.
enum Hysteria2SelfTestOutcome {
    Pass,
    Inconclusive,
}

/// Hysteria2 counterpart to `run_reality_client_selftest`: dials this
/// server's OWN Hysteria2/QUIC listener on `127.0.0.1` with a throwaway
/// `sing-box` client, using an active user's real password (and this
/// deployment's real Salamander obfuscation password, if configured),
/// and requires an actual HTTP success response back through the
/// tunnel — a bound local SOCKS/mixed inbound alone is not evidence of
/// authentication, same reasoning as the REALITY self-test.
///
/// Before this existed, `vpn doctor --protocol` verified ONLY REALITY's
/// TCP/443 handshake; there was no live check of Hysteria2's UDP/QUIC
/// path at all, so a Hysteria2-only regression (wrong password on disk,
/// a listener that opens the port but doesn't actually complete QUIC
/// handshakes, a sing-box UDP/QUIC defect) could pass every existing
/// health check while being completely broken for a real client. That
/// gap meant this project could never rule out "the Hysteria2 listener
/// itself is broken" as a cause of a real-world playback failure —
/// nothing here ever actually dialed it.
///
/// `tls.insecure: true` is deliberate and narrower than it looks: this
/// dials `127.0.0.1` while asserting `server_name` = the deployment's
/// real public hostname (mirroring the REALITY self-test's use of the
/// decoy hostname over a loopback connection), so the presented
/// certificate's CN/SAN can never line up with the address actually
/// dialed regardless of whether the certificate itself is valid. This
/// is NOT a certificate-validity check — that already exists separately
/// (`health-check.sh`'s "Hysteria TLS cert not expired", and whatever a
/// real client validates against the real public IP) — it exists purely
/// to exercise the QUIC handshake, password authentication, and UDP
/// relay path end to end.
fn run_hysteria2_client_selftest(
    cfg: &DeploymentConfig,
    hysteria: &Hysteria2ServerParams,
    test_user: &CompatUser,
    hysteria_port: u16,
) -> Result<Hysteria2SelfTestOutcome> {
    let local_port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .context("reserving a local port for the throwaway Hysteria2 client")?;
        listener.local_addr()?.port()
    };

    let mut outbound = json!({
        "type": "hysteria2",
        "tag": "hysteria2-selftest",
        "server": "127.0.0.1",
        "server_port": hysteria_port,
        "password": test_user.hysteria2_password.expose(),
        "tls": {
            "enabled": true,
            "server_name": cfg.public_host,
            "insecure": true,
        }
    });
    if let Some(pw) = &hysteria.obfs_password {
        outbound["obfs"] = json!({ "type": "salamander", "password": pw.expose() });
    }

    let client_config = json!({
        "log": { "level": "error" },
        "inbounds": [
            { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": local_port }
        ],
        "outbounds": [ outbound, { "type": "direct", "tag": "direct" } ],
        "route": { "final": "hysteria2-selftest" }
    });

    let tmp = tempfile::NamedTempFile::new()
        .context("creating throwaway Hysteria2 client config file")?;
    std::fs::write(tmp.path(), serde_json::to_vec_pretty(&client_config)?)
        .context("writing throwaway Hysteria2 client config")?;

    let child = std::process::Command::new(&cfg.singbox_binary)
        .arg("run")
        .arg("-c")
        .arg(tmp.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("spawning throwaway sing-box Hysteria2 client")?;

    // Same never-leave-an-orphan guarantee as the REALITY self-test.
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut guard = KillOnDrop(child);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut client_bound = true;
    while !tcp_port_reachable(
        "127.0.0.1",
        local_port,
        std::time::Duration::from_millis(100),
    ) {
        if std::time::Instant::now() >= deadline {
            client_bound = false;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    let relay_ok = client_bound
        && socks5_http_get_succeeds(
            local_port,
            "127.0.0.1",
            cfg.subscription.listen_port,
            "/healthz",
            std::time::Duration::from_secs(4),
        );

    let _ = guard.0.kill();
    let _ = guard.0.wait();

    if relay_ok {
        Ok(Hysteria2SelfTestOutcome::Pass)
    } else {
        Ok(Hysteria2SelfTestOutcome::Inconclusive)
    }
}

/// Hysteria2 counterpart to `check_l5_l6_protocol_selftest`. Deliberately
/// separate from that function, from `ProtocolCheckResult`, and from the
/// Telegram/client-acceptance summary functions that consume it — those
/// are written specifically around REALITY's `Pass` /
/// `HandshakeRejected` / `Inconclusive` three-way distinction (see
/// `RealitySelfTestOutcome`'s doc comment), which this Hysteria2 check
/// cannot make (see `Hysteria2SelfTestOutcome`'s doc comment). Reusing
/// that type here would either force a fake `HandshakeRejected` verdict
/// or silently redefine what "L5-6" means to those existing summaries.
/// This reports its own "L5-6-H2" line instead, contributing to the
/// same `failures` counter every other `doctor` check already uses.
fn check_l5_l6_hysteria2_protocol_selftest(
    cfg: &DeploymentConfig,
    failures: &mut u32,
    require_protocol: bool,
) {
    if !cfg.singbox_binary.exists() {
        report_protocol_unavailable(
            require_protocol,
            failures,
            format!(
                "cannot self-test Hysteria2: sing-box binary not found at {:?}",
                cfg.singbox_binary
            ),
        );
        return;
    }
    let hysteria = load_hysteria_params(cfg);
    let users = match store::load_users(&cfg.users_file()) {
        Ok(users) => users,
        Err(e) => {
            report_protocol_unavailable(
                require_protocol,
                failures,
                format!("cannot self-test Hysteria2: failed to load users: {e}"),
            );
            return;
        }
    };
    let now = UnixSeconds::now().0 as i64;
    let Some(test_user) = users.iter().find(|user| user.is_active(now)) else {
        report_protocol_unavailable(
            require_protocol,
            failures,
            "cannot self-test Hysteria2: there is no enabled, unexpired user",
        );
        return;
    };
    let port = cfg.hysteria2.listen_port;

    match run_hysteria2_client_selftest(cfg, &hysteria, test_user, port) {
        Ok(Hysteria2SelfTestOutcome::Pass) => {
            report_check(
                CheckStatus::Ok,
                "L5-6-H2",
                format!(
                    "Hysteria2 protocol self-test: a throwaway sing-box client using an active \
                     user's real password (and this deployment's obfuscation password, if \
                     configured) completed a QUIC/UDP handshake through 127.0.0.1:{port} and \
                     returned application bytes end-to-end"
                ),
            );
        }
        Ok(Hysteria2SelfTestOutcome::Inconclusive) => {
            report_protocol_unavailable(
                require_protocol,
                failures,
                "Hysteria2 protocol self-test INCONCLUSIVE: the throwaway client did not return \
                 an HTTP success response through the live Hysteria2 listener. This can be a \
                 password/obfuscation mismatch, a listener/UDP problem, or a transient failure \
                 — inspect both sing-box processes' logs. Unlike the REALITY self-test, this \
                 project has not catalogued a reliable client-side error string for a Hysteria2 \
                 authentication rejection, so this can never report a definitive handshake-\
                 rejected verdict, only OK, or WARN (FAIL under --require-protocol).",
            );
        }
        Err(e) => {
            report_protocol_unavailable(
                require_protocol,
                failures,
                format!("cannot self-test Hysteria2: {e}"),
            );
        }
    }
}

/// A definitive signal that the handshake does not work — our own throwaway
/// client, built from the CURRENT REALITY public_key/short_id exactly as a
/// real subscription would hand a real client, could not complete it.
///
/// What it is NOT is evidence about the CAUSE. "processed invalid
/// connection" is sing-box's message for any connection that fails to
/// complete REALITY's hijack — including one whose key material is perfect
/// but whose handshake_server returned an over-budget TLS record (see
/// `crates/compat-config/tests/reality_decoy_budget.rs`). The caller reports
/// both possibilities; it must not claim a key mismatch. Distinct from a
/// bare timeout, which proves nothing either way (see the caller's WARN
/// path).
///
/// `captured_stderr` alone almost never catches a genuine REALITY auth
/// failure, and that is not a bug in the string list — it is REALITY
/// working as designed. On rejection the SERVER transparently proxies the
/// connection through to the real `handshake_server` decoy, so the CLIENT
/// typically completes what looks like an entirely normal TLS session (or,
/// if the decoy's cert isn't in its trust store, an ordinary x509
/// validation error unrelated to REALITY) and only then hangs trying to
/// speak VLESS to a plain HTTPS site — producing no "reality verification
/// failed"/"processed invalid connection" on the client side at all.
/// Reproduced directly against the pinned real sing-box binary with a
/// genuinely mismatched (but well-formed) REALITY keypair: the server
/// logged `hs.c.conn == conn: false` / `TLS handshake: REALITY: processed
/// invalid connection`, while the client — run with this self-test's exact
/// production log level — logged nothing matching either string.
///
/// The SERVER's own log is the reliable signal (confirmed: it logs
/// `processed invalid connection` at ERROR severity, so it survives the
/// production default `"log": {"level": "warn"}`, matching `journalctl -u
/// sing-box` output an operator would see directly), so `journal_hit`
/// (a cross-check of that log during this self-test's own connection
/// attempt) also counts. This is still only corroborating evidence, not
/// proof of cause: unrelated scanner traffic hitting the same port during
/// the self-test's brief window could in principle produce a false-positive
/// correlation, and — per the HandshakeRejected message in
/// `check_l5_l6_protocol_selftest` — the same server log line is also what
/// an oversized decoy TLS record produces even when REALITY authentication
/// itself succeeded. It is never used to fabricate a PASS, only to promote
/// an otherwise-silent failure out of Inconclusive.
fn reality_selftest_stderr_or_journal_indicates_rejection(
    captured_stderr: &str,
    journal_hit: bool,
) -> bool {
    captured_stderr.contains("reality verification failed")
        || captured_stderr.contains("processed invalid connection")
        || journal_hit
}

/// Best-effort cross-check of the LIVE `sing-box` server's own journal for a
/// `processed invalid connection` entry logged during this self-test's brief
/// connection attempt. `false` on any failure to query the journal (missing
/// `journalctl`, no permission, non-systemd host) — this never fabricates a
/// positive result, it only widens what counts as corroborating evidence for
/// a rejection the caller already suspects from `relay_ok == false`.
fn singbox_journal_cursor() -> Option<String> {
    let output = std::process::Command::new("journalctl")
        .args([
            "-u",
            "sing-box",
            "-n",
            "0",
            "--show-cursor",
            "--no-pager",
            "-q",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("-- cursor: ").map(str::to_owned))
}

fn journal_has_local_reality_rejection(text: &str) -> bool {
    text.lines().any(|line| {
        line.contains("processed invalid connection")
            && (line.contains("127.0.0.1") || line.contains("[::1]"))
    })
}

fn server_journal_shows_local_processed_invalid_connection_after(cursor: Option<&str>) -> bool {
    let Some(cursor) = cursor else { return false };
    std::process::Command::new("journalctl")
        .args([
            "-u",
            "sing-box",
            "--after-cursor",
            cursor,
            "--no-pager",
            "-q",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .is_some_and(|o| journal_has_local_reality_rejection(&String::from_utf8_lossy(&o.stdout)))
}

/// See `run_reality_client_selftest`'s doc comment for how these are
/// distinguished.
///
/// `HandshakeRejected` is a hard verdict that the handshake does not work,
/// but deliberately NOT a verdict about *why*: sing-box emits the same
/// "processed invalid connection" for a key/short_id mismatch and for a
/// handshake_server whose TLS records exceed REALITY's 8192-byte budget
/// (auth succeeds, connection still dropped). Conflating the two is what
/// sent three separate investigations after the wrong cause. `Inconclusive`
/// means exactly that
/// — a timeout with no corroborating client-side rejection proves
/// nothing about which layer, if any, is broken (could be no outbound
/// path to the REALITY decoy target, an unrelated transient failure,
/// etc.), so it must never be reported as if it were either verdict.
enum RealitySelfTestOutcome {
    Pass,
    HandshakeRejected,
    Inconclusive,
}

/// Minimal, dependency-free SOCKS5 HTTP probe. It does not treat SOCKS
/// `REP=0` as success: VLESS has no positive authentication ACK, so the
/// server can reject the UUID after the local proxy accepted CONNECT.
/// Only an HTTP 200 received through the tunnel proves authentication
/// and application-data relay by the live server.
fn socks5_http_get_succeeds(
    local_port: u16,
    target_host: &str,
    target_port: u16,
    target_path: &str,
    timeout: std::time::Duration,
) -> bool {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", local_port)) else {
        return false;
    };
    if stream.set_read_timeout(Some(timeout)).is_err()
        || stream.set_write_timeout(Some(timeout)).is_err()
    {
        return false;
    }
    // Greeting: version 5, 1 method, no-auth (0x00).
    if stream.write_all(&[0x05, 0x01, 0x00]).is_err() {
        return false;
    }
    let mut resp = [0u8; 2];
    if stream.read_exact(&mut resp).is_err() || resp != [0x05, 0x00] {
        return false;
    }
    // CONNECT request, domain-name address type.
    let host_bytes = target_host.as_bytes();
    if host_bytes.is_empty() || host_bytes.len() > 255 {
        return false;
    }
    let mut req = vec![0x05u8, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.push((target_port >> 8) as u8);
    req.push((target_port & 0xff) as u8);
    if stream.write_all(&req).is_err() {
        return false;
    }
    // Reply header: ver, rep, rsv, atyp. Consume the complete reply before
    // writing application data.
    let mut head = [0u8; 4];
    if stream.read_exact(&mut head).is_err() || head[0] != 0x05 || head[1] != 0x00 {
        return false;
    }
    let trailing_len = match head[3] {
        0x01 => 6,
        0x04 => 18,
        0x03 => {
            let mut len = [0u8; 1];
            if stream.read_exact(&mut len).is_err() {
                return false;
            }
            usize::from(len[0]) + 2
        }
        _ => return false,
    };
    let mut trailing = vec![0u8; trailing_len];
    if stream.read_exact(&mut trailing).is_err() {
        return false;
    }

    let request =
        format!("GET {target_path} HTTP/1.0\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = Vec::new();
    if stream.read_to_end(&mut response).is_err() {
        return false;
    }
    response.starts_with(b"HTTP/1.0 200") || response.starts_with(b"HTTP/1.1 200")
}

/// Canonical, single-source list of every file a backup archive may
/// contain besides `deployment.toml` (handled separately below — it
/// comes from the caller's `--config` argument, not a `DeploymentConfig`
/// accessor, and restore deliberately never overwrites it: a restore
/// onto a different host must keep that host's own domain/paths).
///
/// This one list drives backup creation (`stage_backup_contents`),
/// archive-extraction allow-listing (`extract_validated_backup`), and
/// restore installation (`cmd_restore`) — previously each of those three
/// had its own independently hand-maintained copy, and they drifted:
/// backup creation included `reality/hysteria_obfs_password.txt` while
/// the extraction allowlist did not, so `vpn-admin restore` unconditionally
/// rejected any backup of a deployment that had ever run
/// `hysteria-obfs-rotate`, before restore's own (correct) handling of
/// that file ever got a chance to run.
type BackupFileAccessor = fn(&DeploymentConfig) -> PathBuf;
const BACKUP_MANIFEST: &[(&str, BackupFileAccessor)] = &[
    ("users/users.json", |cfg| cfg.users_file()),
    ("reality/private.key", |cfg| cfg.reality_private_key_file()),
    ("reality/public.key", |cfg| cfg.reality_public_key_file()),
    ("reality/short_id.txt", |cfg| {
        cfg.reality_dir().join("short_id.txt")
    }),
    ("hysteria/cert.pem", |cfg| {
        cfg.hysteria_dir().join("cert.pem")
    }),
    ("hysteria/key.pem", |cfg| cfg.hysteria_dir().join("key.pem")),
    // Optional: absent on deployments that never enabled obfuscation.
    ("reality/hysteria_obfs_password.txt", |cfg| {
        cfg.hysteria_obfs_password_file()
    }),
];

/// True for `deployment.toml`, every path in `BACKUP_MANIFEST`, and the
/// directory entries a tar archive built from those paths necessarily
/// contains (e.g. `reality` as the parent of `reality/private.key`).
/// Shared by `extract_validated_backup`'s allowlist check so the archive
/// format's real shape can never drift from `BACKUP_MANIFEST` itself.
fn is_allowed_backup_path(path: &std::path::Path) -> bool {
    if path == std::path::Path::new("deployment.toml") {
        return true;
    }
    for (rel, _) in BACKUP_MANIFEST {
        let rel_path = std::path::Path::new(rel);
        if path == rel_path {
            return true;
        }
        if let Some(parent) = rel_path.parent() {
            if !parent.as_os_str().is_empty() && path == parent {
                return true;
            }
        }
    }
    false
}

/// Stage the minimum state needed to rebuild this deployment into `dir`:
/// users store, deployment config, REALITY key material, Hysteria2 TLS
/// material. Missing optional pieces (e.g. no Hysteria2 cert yet) are
/// skipped, not treated as an error — a backup taken mid-setup is still
/// useful.
fn stage_backup_contents(
    cfg: &DeploymentConfig,
    config_path: &std::path::Path,
    dir: &std::path::Path,
) -> Result<()> {
    let copy_if_exists = |src: &std::path::Path, dst: &std::path::Path| -> Result<()> {
        if !src.exists() {
            return Ok(());
        }
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(src, dst)?;
        Ok(())
    };

    copy_if_exists(config_path, &dir.join("deployment.toml"))?;
    for (rel, accessor) in BACKUP_MANIFEST {
        copy_if_exists(&accessor(cfg), &dir.join(rel))?;
    }
    Ok(())
}

fn cmd_backup(
    cfg: &DeploymentConfig,
    config_path: &std::path::Path,
    output: Option<PathBuf>,
) -> Result<()> {
    let dest = output
        .unwrap_or_else(|| PathBuf::from(format!("vpn1-backup-{}.tar", UnixSeconds::now().0)));
    let staging = tempdir_here()?;
    stage_backup_contents(cfg, config_path, staging.path())?;

    // Own the destination from its first byte. `create_new` refuses both
    // pre-existing files and symlinks, avoiding predictable-name clobbering
    // and attacker-owned output. The Rust tar writer writes only through
    // this already-open descriptor.
    let mut created = false;
    let mut create_archive = || -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&dest).with_context(|| {
            format!("securely creating backup {dest:?} (destination must not already exist)")
        })?;
        created = true;
        let mut archive = tar::Builder::new(file);
        archive.follow_symlinks(false);
        archive
            .append_dir_all(".", staging.path())
            .context("writing backup archive contents")?;
        let file = archive.into_inner().context("finishing backup archive")?;
        file.sync_all().context("syncing backup archive")?;
        Ok(())
    };
    if let Err(error) = create_archive() {
        if created {
            let _ = std::fs::remove_file(&dest);
        }
        return Err(error);
    }

    println!("Backup written to {dest:?}.");
    println!(
        "This archive contains secrets (REALITY private key, Hysteria2 TLS key, user \
         credential hashes) — store it as securely as the live server."
    );
    Ok(())
}

fn tempdir_here() -> Result<tempfile::TempDir> {
    tempfile::tempdir().context("creating temporary staging directory")
}

/// Refuse to restore from an archive containing anything that is not a
/// plain file or directory.
///
/// Restore reads a handful of known relative paths out of the extracted
/// tree. A hostile or corrupted archive can plant other entry types there,
/// and each one is a distinct failure:
///   * **symlink** — reading it yields whatever the target happens to be
///     instead of the archive's own content.
///   * **FIFO** — `std::fs::read` on it blocks forever with no writer, and
///     restore holds the global `/run/lock/vpn1.lock` while it does, so
///     every subsequent `vpn user …`, rotation and restore deadlocks too.
///     (Reproduced: the process simply never returns.)
///   * **character/block device** — `read` on e.g. `/dev/zero` consumes
///     memory without bound until the OOM killer intervenes, which on a VPS
///     means it takes sing-box or nginx with it.
///
/// `tar` runs as root during restore, so all of these are really created.
/// Rejecting by entry type up front is cheaper and more complete than
/// hardening each read site.
fn normalized_archive_path(path: &std::path::Path) -> Result<PathBuf> {
    use std::path::Component;
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("backup archive contains unsafe path {path:?}")
            }
        }
    }
    Ok(normalized)
}

/// Validate each archive header before extracting that entry into the
/// private staging directory. This rejects traversal, duplicate names,
/// links/devices/FIFOs, unexpected files, and archive bombs before any
/// live deployment path is touched.
fn extract_validated_backup(archive_path: &std::path::Path, dir: &std::path::Path) -> Result<()> {
    use std::collections::HashSet;

    const MAX_ENTRIES: usize = 32;
    const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

    let file = std::fs::File::open(archive_path)
        .with_context(|| format!("opening backup archive {archive_path:?}"))?;
    let mut archive = tar::Archive::new(file);
    let mut seen = HashSet::new();
    let mut total_bytes = 0u64;
    let mut count = 0usize;
    for entry in archive
        .entries()
        .context("reading backup archive headers")?
    {
        let mut entry = entry.context("reading backup archive entry")?;
        count += 1;
        if count > MAX_ENTRIES {
            bail!("backup archive contains more than {MAX_ENTRIES} entries");
        }
        let raw_path = entry.path().context("reading backup entry path")?;
        let path = normalized_archive_path(&raw_path)?;
        if path.as_os_str().is_empty() {
            if !entry.header().entry_type().is_dir() {
                bail!("backup archive root entry is not a directory");
            }
            continue;
        }
        if !seen.insert(path.clone()) {
            bail!("backup archive contains duplicate entry {path:?}");
        }
        if !is_allowed_backup_path(&path) {
            bail!("backup archive contains unexpected entry {path:?}");
        }
        let entry_type = entry.header().entry_type();
        if !(entry_type.is_file() || entry_type.is_dir()) {
            bail!(
                "backup archive entry {path:?} is not a regular file or directory; links and \
                 special files (symlink, hard link, FIFO, device) are forbidden"
            );
        }
        let size = entry.size();
        if size > MAX_ENTRY_BYTES {
            bail!("backup archive entry {path:?} is too large ({size} bytes)");
        }
        total_bytes = total_bytes
            .checked_add(size)
            .context("backup archive size overflow")?;
        if total_bytes > MAX_TOTAL_BYTES {
            bail!("backup archive expands beyond {MAX_TOTAL_BYTES} bytes");
        }
        if !entry
            .unpack_in(dir)
            .with_context(|| format!("extracting backup entry {path:?}"))?
        {
            bail!("backup entry {path:?} would escape the staging directory");
        }
    }
    Ok(())
}

fn cmd_restore(
    cfg: &DeploymentConfig,
    config_path: &std::path::Path,
    archive: &std::path::Path,
) -> Result<()> {
    let staging = tempdir_here()?;
    extract_validated_backup(archive, staging.path())
        .context("validating and extracting backup archive")?;

    // Validate before touching any live state (spec §20: "Validate
    // restored data before replacing active state").
    let users_path = staging.path().join("users/users.json");
    let restored_users: Vec<CompatUser> = if users_path.exists() {
        let bytes = std::fs::read(&users_path).context("reading restored users.json")?;
        // Understands both the current versioned envelope and the legacy
        // pre-versioning bare-array shape — a backup taken before `vpn-admin
        // config migrate`/an upgrade is exactly as restorable as one taken
        // after (see store::parse_users_bytes's doc comment).
        store::parse_users_bytes(&bytes)
            .context("restored users.json is not valid — refusing to restore")?
    } else {
        bail!("archive does not contain users/users.json — refusing to restore");
    };
    let reality_key_path = staging.path().join("reality/private.key");
    if !reality_key_path.exists() {
        bail!("archive does not contain reality/private.key — refusing to restore");
    }
    // The REALITY triple must be restored as a SET. Restoring a new
    // private.key next to the live host's OLD public.key/short_id produces
    // a guaranteed split-brain: sing-box enforces the restored private key
    // while vpn-subscription keeps advertising the old public half, and
    // every client fails REALITY's handshake. Previously the last four
    // targets were restored only `if src.exists()`, so an archive with a
    // private key and nothing else reported success.
    for required in ["reality/public.key", "reality/short_id.txt"] {
        if !staging.path().join(required).exists() {
            bail!(
                "archive contains reality/private.key but not {required} — refusing to restore \
                 a partial REALITY keyset, which would leave the server enforcing one key while \
                 the subscription service advertises another"
            );
        }
    }
    let restored_private = std::fs::read_to_string(&reality_key_path)
        .context("reading restored REALITY private key")?;
    let restored_public = std::fs::read_to_string(staging.path().join("reality/public.key"))
        .context("reading restored REALITY public key")?;
    credentials::validate_reality_keypair(restored_private.trim(), restored_public.trim())
        .map_err(|error| anyhow::anyhow!(error))
        .context(
            "restored REALITY private/public keys do not form one X25519 keypair — refusing to \
             install a split keyset",
        )?;
    let hy_cert = staging.path().join("hysteria/cert.pem");
    let hy_key = staging.path().join("hysteria/key.pem");
    if hy_cert.exists() != hy_key.exists() {
        bail!(
            "archive contains only one half of the Hysteria2 TLS pair — refusing to restore a \
             mismatched certificate/key"
        );
    }

    let singbox_mgr = CompatibilityServiceManager::default();
    let sub_mgr = CompatibilityServiceManager::new("vpn-subscription");
    if !offline_mutation_allowed()
        && (!singbox_mgr.is_available()
            || !singbox_mgr.is_unit_installed()
            || !sub_mgr.is_available()
            || !sub_mgr.is_unit_installed())
    {
        bail!(
            "refusing restore: both sing-box.service and vpn-subscription.service must be \
             installed and controllable so restored authorization/key state can be committed \
             atomically. VPN1_ALLOW_OFFLINE_MUTATION=1 is only for explicit offline recovery."
        );
    }

    // Only after validation: copy into place.
    std::fs::create_dir_all(cfg.reality_dir())?;
    std::fs::create_dir_all(cfg.hysteria_dir())?;
    std::fs::create_dir_all(cfg.users_file().parent().unwrap())?;

    // Derived from the same BACKUP_MANIFEST that drives backup creation
    // and archive-extraction allow-listing (see its doc comment) — minus
    // `users/users.json`, which restore handles separately above via
    // `restored_users`/`save_users_atomic` rather than a raw file copy.
    // Optional entries (e.g. hysteria_obfs_password.txt) are absent from
    // archives taken before obfuscation was enabled; the `install_all`
    // loop below already skips any entry missing from the archive, so
    // this is safe on old backups.
    let restore_targets: Vec<(&str, PathBuf)> = BACKUP_MANIFEST
        .iter()
        .filter(|(rel, _)| *rel != "users/users.json")
        .map(|(rel, accessor)| (*rel, accessor(cfg)))
        .collect();

    // Back EVERYTHING up before touching any of it, so a failure part-way
    // through can put the deployment back exactly as it was. `restore` was
    // the only mutating command with no rollback at all, while the rotation
    // path right next to it builds precisely this scaffolding.
    let users_path = cfg.users_file();
    let users_backup = backup_for_rotate(&users_path)?;
    let users_had_backup = users_backup.is_some();
    let mut prepared_backups: Vec<PathBuf> = users_backup.into_iter().collect();
    let mut backed_up: Vec<(PathBuf, bool)> = Vec::new();
    for (_, dest) in &restore_targets {
        match backup_for_rotate(dest) {
            Ok(backup) => {
                let existed = backup.is_some();
                prepared_backups.extend(backup);
                backed_up.push((dest.clone(), existed));
            }
            Err(error) => {
                for backup in prepared_backups {
                    let _ = std::fs::remove_file(backup);
                }
                return Err(error).context(
                    "failed to prepare the complete restore transaction; live state was not changed",
                );
            }
        }
    }
    let rollback = |backed_up: &[(PathBuf, bool)]| -> Result<()> {
        let mut errors = Vec::new();
        for (dest, existed) in backed_up {
            let result = if *existed {
                restore_from_rotate_backup(dest)
            } else {
                std::fs::remove_file(dest)
                    .or_else(|error| {
                        if error.kind() == std::io::ErrorKind::NotFound {
                            Ok(())
                        } else {
                            Err(error)
                        }
                    })
                    .map_err(anyhow::Error::from)
            };
            if let Err(error) = result {
                errors.push(format!("restore {dest:?}: {error}"));
            }
        }
        let users_result = if users_had_backup {
            restore_from_rotate_backup(&users_path)
        } else {
            std::fs::remove_file(&users_path)
                .or_else(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(error)
                    }
                })
                .map_err(anyhow::Error::from)
        };
        if let Err(error) = users_result {
            errors.push(format!("restore {users_path:?}: {error}"));
        }
        if let Err(error) = regenerate_singbox_config(cfg, true) {
            errors.push(format!("reload previous sing-box authorization: {error:#}"));
        }
        if sub_mgr.is_available() && sub_mgr.is_unit_installed() {
            if let Err(error) = sub_mgr.reload_and_verify() {
                errors.push(format!("restart previous subscription state: {error:#}"));
            }
        } else if !offline_mutation_allowed() {
            errors.push("vpn-subscription.service unavailable during rollback".into());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!(errors.join("; "))
        }
    };

    let install_all = || -> Result<()> {
        store::save_users_atomic(&users_path, &restored_users)?;
        apply_restored_file_policy(&users_path, "vpn-subscription")?;
        for (rel, dest) in &restore_targets {
            let src = staging.path().join(rel);
            if !src.exists() {
                continue;
            }
            // Read-and-write rather than `fs::copy`. `fs::copy` propagates
            // the SOURCE file's permission bits to the destination, and the
            // source here is attacker-influenced archive metadata — a mode
            // of 04777 in a tar header became the live mode of
            // reality/private.key. It also creates the destination
            // root-owned when it doesn't already exist, which leaves
            // sing-box (running as Group=sing-box) unable to read its own
            // private key on a rebuilt host.
            let contents = std::fs::read(&src)
                .with_context(|| format!("reading {rel} from the backup archive"))?;
            let text = String::from_utf8(contents)
                .with_context(|| format!("{rel} in the backup archive is not valid UTF-8"))?;
            install_rotated_key_file(dest, &text)
                .with_context(|| format!("installing restored {rel}"))?;
            let group = if matches!(
                *rel,
                "reality/public.key"
                    | "reality/short_id.txt"
                    | "reality/hysteria_obfs_password.txt"
            ) {
                "vpn-subscription"
            } else {
                "sing-box"
            };
            apply_restored_file_policy(dest, group)?;
        }
        fsync_dir(&cfg.reality_dir());
        fsync_dir(&cfg.hysteria_dir());
        Ok(())
    };

    if let Err(e) = install_all() {
        let recovery = rollback(&backed_up);
        bail!(
            "restore FAILED while installing staged state ({e:#}). {}",
            match recovery {
                Ok(()) => "Rollback restored and reloaded the complete previous state.".into(),
                Err(error) => format!(
                    "ROLLBACK ALSO FAILED ({error:#}); deployment may be inconsistent and needs \
                     manual recovery from .rotate-bak files."
                ),
            }
        );
    }

    let restored_deployment_toml = staging.path().join("deployment.toml");
    if restored_deployment_toml.exists() {
        println!(
            "Note: the backup's deployment.toml was NOT applied automatically (host/port \
             settings are not safe to overwrite blindly). It was extracted for reference at \
             {restored_deployment_toml:?} before this temporary directory is removed; the live \
             config remains {config_path:?}."
        );
    }

    // Deliberately NOT announcing success yet: the previous ordering printed
    // "Restored N user(s)…" and only then applied the config, so a rejected
    // config produced a success line immediately followed by an error, with
    // the deployment left half-restored.
    if let Err(e) = regenerate_singbox_config(cfg, true) {
        let recovery = rollback(&backed_up);
        bail!(
            "restore FAILED while applying restored authorization ({e:#}). {}",
            match recovery {
                Ok(()) => "Rollback restored and reloaded the complete previous state.".into(),
                Err(error) => format!(
                    "ROLLBACK ALSO FAILED ({error:#}); deployment may be inconsistent and needs \
                     manual recovery from .rotate-bak files."
                ),
            }
        );
    }

    // The archive always contains REALITY private/public key + short_id
    // (checked above) and may differ from whatever key material was live
    // before this restore ran (e.g. restoring an older backup after a
    // rotation, or onto a fresh host). `regenerate_singbox_config` only
    // reloads sing-box — but vpn-subscription caches the REALITY public
    // key/short_id in memory at startup and has no config-reload path
    // (see `cmd_reality_rotate`'s doc comment for the same fact), so a
    // restore that skips this step can leave the subscription service
    // silently advertising a STALE public key while sing-box already
    // speaks the restored one — the exact split-brain P0-5 exists to
    // prevent, just reached via `restore` instead of `init --rotate`.
    if sub_mgr.is_available() && sub_mgr.is_unit_installed() {
        if let Err(e) = sub_mgr.reload_and_verify() {
            let recovery = rollback(&backed_up);
            bail!(
                "restore FAILED while restarting vpn-subscription ({e:#}). {}",
                match recovery {
                    Ok(()) => "Rollback restored and reloaded the complete previous state.".into(),
                    Err(error) => format!(
                        "ROLLBACK ALSO FAILED ({error:#}); deployment may be inconsistent and \
                         needs manual recovery from .rotate-bak files."
                    ),
                }
            );
        }
    } else {
        println!(
            "warning: systemctl/vpn-subscription.service not available — restored REALITY \
             key material was NOT picked up by the subscription service (it caches this at \
             startup, so a manual `systemctl restart vpn-subscription` is required on a real \
             deployment)."
        );
    }

    for (dest, existed) in &backed_up {
        if *existed {
            remove_rotate_backup(dest);
        }
    }
    if users_had_backup {
        remove_rotate_backup(&users_path);
    }

    println!(
        "Restored {} user(s) and REALITY/Hysteria2 material from {archive:?}.",
        restored_users.len()
    );
    println!("Restore applied and validated against the running server.");
    Ok(())
}

#[cfg(test)]
mod reality_selftest_classification_tests {
    use super::*;

    #[test]
    fn client_side_rejection_strings_are_still_detected() {
        assert!(reality_selftest_stderr_or_journal_indicates_rejection(
            "some prefix reality verification failed some suffix",
            false,
        ));
        assert!(reality_selftest_stderr_or_journal_indicates_rejection(
            "TLS handshake: REALITY: processed invalid connection",
            false,
        ));
    }

    /// The exact production incident this fix addresses. Reproduced against
    /// the real pinned sing-box 1.13.14 binary with a genuinely mismatched
    /// (well-formed) REALITY keypair and a local TLS 1.3 decoy: the
    /// throwaway client, run with this self-test's real production log
    /// level ("error"), logged an x509 chain-validation error from falling
    /// through to the decoy — NOT either of the two REALITY-specific
    /// strings — because REALITY's entire design goal is to make a
    /// rejected connection indistinguishable from a normal TLS session with
    /// the decoy. Before this fix, this exact client stderr made
    /// `check_l5_l6_protocol_selftest` report `Inconclusive` for a
    /// definitive, reproducible handshake failure — matching the live
    /// incident's `doctor --protocol` output verbatim ("protocol self-test
    /// INCONCLUSIVE"). The journal cross-check is what recovers a correct
    /// verdict here.
    #[test]
    fn a_real_key_mismatch_does_not_reliably_produce_either_client_side_string() {
        let real_client_stderr_from_repro = "ERROR[0002] [2197300140 43ms] connection: open \
             connection to 127.0.0.1:19999 using outbound/vless[reality-selftest]: x509: \
             certificate signed by unknown authority (possibly because of \"x509: invalid \
             signature: parent certificate cannot sign this kind of certificate\" while trying \
             to verify candidate authority certificate \"localhost\")";
        assert!(!reality_selftest_stderr_or_journal_indicates_rejection(
            real_client_stderr_from_repro,
            false,
        ));
        // The same failure IS caught once the server's own journal
        // corroborates it — this is the fix.
        assert!(reality_selftest_stderr_or_journal_indicates_rejection(
            real_client_stderr_from_repro,
            true,
        ));
    }

    #[test]
    fn empty_client_stderr_and_no_journal_hit_stays_inconclusive() {
        assert!(!reality_selftest_stderr_or_journal_indicates_rejection(
            "", false,
        ));
    }

    #[test]
    fn unrelated_public_scanner_rejection_is_not_attributed_to_selftest() {
        let journal = "sing-box inbound/reality[0]: [203.0.113.9:50123] REALITY: processed invalid connection";
        assert!(!journal_has_local_reality_rejection(journal));
    }

    #[test]
    fn fenced_loopback_rejection_is_still_detected() {
        let journal =
            "sing-box inbound/reality[0]: [127.0.0.1:50123] REALITY: processed invalid connection";
        assert!(journal_has_local_reality_rejection(journal));
    }
}

/// Regression coverage for the IPv4-only-host doctor bug: a blanket,
/// AAAA-blind IPv6 UDP egress check used to unconditionally fail
/// `--require-protocol` acceptance even when the real VLESS+REALITY L5/L6
/// handshake passed and the host simply had no IPv6 configured at all
/// (the common case on a plain EC2 box). `classify_ipv6_posture` /
/// `ipv6_posture_report` are the single source of truth for IPv6
/// fatality now; these tests pin every state so that bug cannot come
/// back silently.
#[cfg(test)]
mod ipv6_posture_tests {
    use super::*;

    #[test]
    fn ipv4_only_host_no_aaaa_is_never_fatal_regardless_of_probe_outcome() {
        // No AAAA record at all — this VPS's own IPv6 egress state is
        // irrelevant to fatality; even a broken/unavailable probe result
        // must not escalate. `has_aaaa=false` short-circuits before a
        // probe would ever run in the real caller, but the classifier
        // itself must be robust to any `probe` value passed here.
        for probe in [None, Some(true), Some(false)] {
            let posture = classify_ipv6_posture(false, probe);
            assert_eq!(posture, Ipv6Posture::NoAaaa);
            let (status, increment, _msg) = ipv6_posture_report(posture);
            assert_eq!(status, CheckStatus::Info);
            assert!(
                !increment,
                "an IPv4-only host (no AAAA) must never increment failures, probe={probe:?}"
            );
        }
    }

    #[test]
    fn reality_pass_is_not_undermined_by_ipv4_only_ipv6_diagnostic() {
        // Pins the actual regression: simulate an otherwise-fully-passing
        // doctor run (failures starts at 0, REALITY/Hysteria2 listeners
        // OK) on an IPv4-only host and confirm the IPv6 diagnostic alone
        // does not push `failures` above zero.
        let mut failures: u32 = 0;
        let (status, increment, _msg) = ipv6_posture_report(classify_ipv6_posture(false, None));
        if increment {
            failures += 1;
        }
        assert_eq!(status, CheckStatus::Info);
        assert_eq!(
            failures, 0,
            "an unrelated IPv4-only IPv6 diagnostic must not fail an otherwise-passing acceptance run"
        );
    }

    #[test]
    fn aaaa_present_and_egress_confirmed_working_is_ok_and_non_fatal() {
        let posture = classify_ipv6_posture(true, Some(true));
        assert_eq!(posture, Ipv6Posture::AaaaEgressOk);
        let (status, increment, _msg) = ipv6_posture_report(posture);
        assert_eq!(status, CheckStatus::Ok);
        assert!(!increment);
    }

    #[test]
    fn aaaa_present_and_egress_confirmed_broken_is_fatal() {
        // The one case that must stay fatal: IPv6 is actually advertised
        // (AAAA exists) and the probe positively observed it does not
        // work — IPv6-preferring clients would be silently stranded.
        let posture = classify_ipv6_posture(true, Some(false));
        assert_eq!(posture, Ipv6Posture::AaaaEgressBroken);
        let (status, increment, msg) = ipv6_posture_report(posture);
        assert_eq!(status, CheckStatus::Fail);
        assert!(
            increment,
            "AAAA present + confirmed-broken IPv6 egress must increment failures"
        );
        assert!(msg.contains("blocked"));
    }

    #[test]
    fn aaaa_present_but_probe_unavailable_is_inconclusive_not_fatal() {
        // The probe itself failing to run (no socket permission, etc.)
        // is not evidence IPv6 is broken — must warn, not fail.
        let posture = classify_ipv6_posture(true, None);
        assert_eq!(posture, Ipv6Posture::AaaaEgressUnknown);
        let (status, increment, _msg) = ipv6_posture_report(posture);
        assert_eq!(status, CheckStatus::Warn);
        assert!(!increment);
    }
}

#[cfg(test)]
mod udp_probe_tests {
    use super::*;

    #[test]
    fn build_dns_query_contains_labels() {
        let q = build_dns_query("example.com");
        // Should contain label lengths 7 and 3 followed by the ascii bytes
        assert!(q.windows(2).any(|w| w == [7, b'e']));
        assert!(q.windows(2).any(|w| w == [3, b'c']));
    }

    #[test]
    fn run_udp_probe_candidates_with_probe_logic() {
        // Simulate first resolver failing twice, second resolver succeeding on first attempt
        let candidates = ["1.2.3.4", "5.6.7.8"];
        let mut calls = 0;
        let probe = |cand: &str, _timeout: std::time::Duration| -> Option<bool> {
            calls += 1;
            if cand == "1.2.3.4" {
                Some(false)
            } else if cand == "5.6.7.8" {
                Some(true)
            } else {
                None
            }
        };
        let res = run_udp_probe_candidates_with_probe(
            &candidates,
            std::time::Duration::from_millis(10),
            2,
            std::time::Duration::from_millis(1),
            probe,
        );
        assert_eq!(res, Some(true));
        assert!(calls >= 3);
    }

    #[test]
    fn singbox_version_consistency_silent_on_single_binary() {
        let found = vec![(
            std::path::PathBuf::from("/a/sing-box"),
            "1.13.14".to_string(),
        )];
        assert!(
            singbox_version_consistency_report(&found, std::path::Path::new("/a/sing-box"))
                .is_none()
        );
    }

    #[test]
    fn singbox_version_consistency_ok_when_versions_match() {
        let found = vec![
            (
                std::path::PathBuf::from("/a/sing-box"),
                "sing-box 1.13.14".to_string(),
            ),
            (
                std::path::PathBuf::from("/b/sing-box"),
                "sing-box 1.13.14".to_string(),
            ),
        ];
        let (status, _msg) =
            singbox_version_consistency_report(&found, std::path::Path::new("/a/sing-box"))
                .expect("should report something for multiple binaries");
        assert!(matches!(status, CheckStatus::Ok));
    }

    #[test]
    fn singbox_version_consistency_warns_and_names_configured_binary_when_versions_differ() {
        let found = vec![
            (
                std::path::PathBuf::from("/usr/local/bin/sing-box"),
                "sing-box 1.13.14".to_string(),
            ),
            (
                std::path::PathBuf::from("/usr/bin/sing-box"),
                "sing-box 1.12.0".to_string(),
            ),
        ];
        let (status, msg) = singbox_version_consistency_report(
            &found,
            std::path::Path::new("/usr/local/bin/sing-box"),
        )
        .expect("differing versions must be reported");
        assert!(matches!(status, CheckStatus::Warn));
        assert!(msg.contains("1.13.14"));
        assert!(msg.contains("1.12.0"));
        assert!(msg.contains("/usr/local/bin/sing-box"));
        assert!(
            msg.contains("systemd/vpn-admin currently uses: /usr/local/bin/sing-box"),
            "must name which binary is actually active: {msg}"
        );
    }

    #[test]
    fn probe_singbox_binary_versions_skips_nonexistent_paths_and_dedupes() {
        let existing = std::env::current_exe().unwrap(); // guaranteed to exist
        let candidates = vec![
            existing.clone(),
            existing.clone(),
            std::path::PathBuf::from("/definitely/does/not/exist/sing-box"),
        ];
        let found = probe_singbox_binary_versions(&candidates, |_path| {
            Ok(std::process::Output {
                status: std::process::ExitStatus::default(),
                stdout: b"sing-box 1.13.14\n".to_vec(),
                stderr: Vec::new(),
            })
        });
        assert_eq!(
            found.len(),
            1,
            "duplicate + nonexistent paths must be filtered: {found:?}"
        );
        assert_eq!(found[0].0, existing);
        assert_eq!(found[0].1, "sing-box 1.13.14");
    }

    /// Task 8: deterministic doctor coverage for a missing/invalid/expired
    /// Hysteria2 TLS certificate — one of the concrete failure cases the
    /// task's requirement 8 lists. Shells out to the real `openssl`/`date`
    /// binaries `cert_expiry_days` itself uses, rather than mocking them,
    /// so this actually exercises the same code path doctor runs.
    #[test]
    fn cert_expiry_days_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(cert_expiry_days(&dir.path().join("does-not-exist.pem")).is_none());
    }

    #[test]
    fn cert_expiry_days_reports_negative_days_for_an_already_expired_cert() {
        let dir = tempfile::tempdir().unwrap();
        let csr_path = dir.path().join("expired.csr");
        let key_path = dir.path().join("expired.key");
        let cert_path = dir.path().join("expired.pem");
        // `req -x509 -days` rejects negative values outright — build a CSR
        // first, then self-sign it via `x509 -req -days -1`, which backdates
        // notAfter to yesterday and so reliably produces an already-expired
        // certificate regardless of what "today" is when this test runs.
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=expired.example.com",
                "-keyout",
            ])
            .arg(&key_path)
            .arg("-out")
            .arg(&csr_path)
            .status()
            .expect("openssl must be available to run this test");
        assert!(status.success(), "openssl failed to generate a test CSR");
        let status = std::process::Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(&csr_path)
            .args(["-signkey"])
            .arg(&key_path)
            .args(["-days", "-1", "-out"])
            .arg(&cert_path)
            .status()
            .expect("openssl must be available to run this test");
        assert!(status.success(), "openssl failed to self-sign a test cert");

        let result = cert_expiry_days(&cert_path).expect("file exists, must return Some");
        let days = result.expect("valid cert, openssl/date parsing must succeed");
        assert!(
            days < 0,
            "cert self-signed with -days -1 must report negative days remaining, got {days}"
        );
    }

    #[test]
    fn cert_expiry_days_reports_positive_days_for_a_freshly_issued_cert() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("fresh.pem");
        let key_path = dir.path().join("fresh.key");
        let status = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "90",
                "-subj",
                "/CN=fresh.example.com",
                "-keyout",
            ])
            .arg(&key_path)
            .arg("-out")
            .arg(&cert_path)
            .status()
            .expect("openssl must be available to run this test");
        assert!(status.success(), "openssl failed to generate a test cert");

        let result = cert_expiry_days(&cert_path).expect("file exists, must return Some");
        let days = result.expect("valid cert, openssl/date parsing must succeed");
        assert!(
            days > 0 && days <= 90,
            "cert issued with -days 90 must report a small positive days remaining, got {days}"
        );
    }

    #[test]
    fn redact_secrets_hides_a_vless_uuid() {
        let text = "user 11111111-2222-4333-8444-555555555555 connected";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("11111111-2222-4333-8444-555555555555"));
        assert!(redacted.contains("<redacted>"));
        assert!(redacted.starts_with("user "));
        assert!(redacted.ends_with(" connected"));
    }

    #[test]
    fn redact_secrets_hides_a_long_hex_key_or_hash() {
        let text = "reality private_key=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef end";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
        assert!(redacted.contains("<redacted>"));
    }

    #[test]
    fn redact_secrets_hides_a_base64url_style_token() {
        // Shaped like the subscription/Hysteria2/obfuscation tokens this
        // crate actually generates (see compat-config's credentials.rs):
        // mixed letters/digits, base64url alphabet, well past 24 chars.
        let text = "subscription token=aB3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cD end";
        let redacted = redact_secrets(text);
        assert!(!redacted.contains("aB3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cD"));
        assert!(redacted.contains("<redacted>"));
    }

    #[test]
    fn redact_secrets_leaves_ordinary_log_text_and_short_words_untouched() {
        let text = "2026-08-10T12:00:00Z sing-box[1234]: TLS handshake: REALITY: processed invalid connection";
        let redacted = redact_secrets(text);
        assert_eq!(
            redacted, text,
            "no false-positive redaction on ordinary log prose"
        );
    }

    #[test]
    fn redact_secrets_preserves_non_ascii_text_around_a_redacted_token() {
        // Regression guard: redaction must not corrupt multi-byte UTF-8
        // text elsewhere on the same line (e.g. non-English log content).
        let text = "пользователь 11111111-2222-4333-8444-555555555555 подключился успешно";
        let redacted = redact_secrets(text);
        assert!(redacted.starts_with("пользователь "));
        assert!(redacted.ends_with(" подключился успешно"));
        assert!(redacted.contains("<redacted>"));
    }
}

/// Regression tests for the doctor coverage-state bug found in review:
/// L1-4's outcome and L5-6's outcome must never be inferred from each
/// other, and L5-6 must be a real four-state result (NotRun / Passed /
/// Failed / Inconclusive), never a `bool` collapsed from "the flag was
/// passed." Every combination in `build_doctor_coverage_report`'s doc
/// comment is covered here directly (no stdout capture needed — see
/// that function's own doc comment for why it's split out this way).
#[cfg(test)]
mod doctor_coverage_tests {
    use super::*;

    #[test]
    fn l1_l4_passed_l5_l6_not_run() {
        let report = build_doctor_coverage_report(0, ProtocolCheckResult::NotRun);
        assert!(report.contains("L1-4"));
        assert!(report.contains("PASSED"));
        assert!(report.contains("L5-6"));
        assert!(report.contains("NOT RUN"));
        assert!(
            !report.contains("All checks that ran, including the real protocol handshake, passed"),
            "L1-4 passing alone must never be read as full server health:\n{report}"
        );
    }

    #[test]
    fn l1_l4_passed_l5_l6_passed_is_the_only_full_health_claim() {
        let report = build_doctor_coverage_report(0, ProtocolCheckResult::Passed);
        assert!(report.contains("PASSED"));
        assert!(
            report.contains("All checks that ran, including the real protocol handshake, passed"),
            "only this exact combination may claim full coverage passed:\n{report}"
        );
    }

    /// The specific scenario the review flagged: `--protocol` passed
    /// without `--require-protocol`, and the self-test result is
    /// `Inconclusive` (a real dial happened, HTTP success wasn't
    /// returned). This must NOT print "L5-6 ... PASSED" — it is a
    /// distinct third state, not folded into pass or not-run.
    #[test]
    fn l1_l4_passed_l5_l6_inconclusive_is_never_reported_as_passed_or_not_run() {
        let report = build_doctor_coverage_report(0, ProtocolCheckResult::Inconclusive);
        assert!(
            report.contains("INCONCLUSIVE"),
            "must explicitly say INCONCLUSIVE:\n{report}"
        );
        assert!(
            !report.contains("L5-6 (real protocol handshake): PASSED"),
            "an inconclusive self-test must never be reported as PASSED:\n{report}"
        );
        assert!(
            !report.contains("L5-6 (real protocol handshake): NOT RUN"),
            "an inconclusive self-test actually dialed — it must never be reported as NOT RUN:\n\
             {report}"
        );
        assert!(
            report.contains("not a definitive failure") || report.contains("DIALED"),
            "must make clear a real dial happened but the result is ambiguous:\n{report}"
        );
    }

    #[test]
    fn l1_l4_passed_l5_l6_failed() {
        let report = build_doctor_coverage_report(0, ProtocolCheckResult::Failed);
        assert!(report.contains("L5-6 (real protocol handshake): FAILED"));
        assert!(
            report.contains("not proof the problem is client-side"),
            "an L5-6 failure must not be framed as proving the client is at fault:\n{report}"
        );
    }

    /// The other half of the review finding: L1-4's failure count must
    /// not taint or be inferred from an L5-6 result that happens to
    /// pass. Both must be visible, independently, in the same report.
    #[test]
    fn l1_l4_failed_l5_l6_passed_does_not_imply_l1_l4_ok() {
        let report = build_doctor_coverage_report(3, ProtocolCheckResult::Passed);
        assert!(
            report.contains("FAILED (3)"),
            "L1-4's failure count must still be visible even when L5-6 passed:\n{report}"
        );
        assert!(
            report.contains("L5-6 (real protocol handshake): PASSED"),
            "L5-6's own passing result must still be visible independently:\n{report}"
        );
        assert!(
            report.contains("does NOT clear the L1-4 failures"),
            "a passing handshake must not be read as clearing unrelated L1-4 failures:\n{report}"
        );
    }

    #[test]
    fn l1_l4_failed_l5_l6_not_run() {
        let report = build_doctor_coverage_report(2, ProtocolCheckResult::NotRun);
        assert!(report.contains("FAILED (2)"));
        assert!(report.contains("L5-6 (real protocol handshake): NOT RUN"));
        assert!(report.contains("NOT established"));
        assert!(
            report.contains("did not run either"),
            "the L1-4-failed + L5-6-not-run combination has its own distinct message, not the \
             generic L1-4-only one:\n{report}"
        );
    }

    #[test]
    fn l1_l4_failed_l5_l6_inconclusive_still_reports_both_independently() {
        let report = build_doctor_coverage_report(1, ProtocolCheckResult::Inconclusive);
        assert!(report.contains("FAILED (1)"));
        assert!(report.contains("L5-6 (real protocol handshake): INCONCLUSIVE"));
        assert!(
            report.contains("INCONCLUSIVE result"),
            "the L1-4-failed + L5-6-inconclusive combination has its own distinct message:\n\
             {report}"
        );
    }

    #[test]
    fn l1_l4_failed_l5_l6_failed_both_shown() {
        let report = build_doctor_coverage_report(4, ProtocolCheckResult::Failed);
        assert!(report.contains("FAILED (4)"));
        assert!(report.contains("L5-6 (real protocol handshake): FAILED"));
        assert!(
            report.contains("also FAILED"),
            "the L1-4-failed + L5-6-failed combination has its own distinct message stating \
             BOTH failed, not just L1-4:\n{report}"
        );
    }

    /// `ProtocolCheckResult::label()` must stay a strict 4-state match —
    /// this test's own `match` has no `_` arm, so it fails to COMPILE if
    /// a variant is ever added without updating `label()`. Note this
    /// guards `label()` specifically, not `build_doctor_coverage_report`
    /// — that function has its own separate exhaustive (also
    /// wildcard-free) match and is protected by the compiler directly,
    /// not by this test.
    #[test]
    fn protocol_check_result_label_is_exhaustively_defined() {
        for result in [
            ProtocolCheckResult::NotRun,
            ProtocolCheckResult::Passed,
            ProtocolCheckResult::Failed,
            ProtocolCheckResult::Inconclusive,
        ] {
            let label = match result {
                ProtocolCheckResult::NotRun => "NOT RUN",
                ProtocolCheckResult::Passed => "PASSED",
                ProtocolCheckResult::Failed => "FAILED",
                ProtocolCheckResult::Inconclusive => "INCONCLUSIVE",
            };
            assert_eq!(result.label(), label);
        }
    }
}

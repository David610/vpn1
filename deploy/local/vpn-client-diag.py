#!/usr/bin/env python3
"""vpn1 client-side network diagnostics.

Standard library only (Python 3.7+), works unmodified on Windows, macOS,
and Linux — no admin/root privileges, no extra packages, nothing to
install. Designed to be run BY THE USER from wherever they actually are
(their real Russia-side laptop/phone, over their real ISP), because the
server (`deploy/lib/vpn-benchmark.sh`) cannot see that path at all: a
benchmark run on the VPS only measures the VPS's own uplink, never the
Russia -> VPS path a real client actually uses.

WHAT THIS COLLECTS: only non-secret network measurements — DNS timing,
TCP connect timing, ICMP ping/loss (via the OS's own `ping` binary, no
raw sockets, no admin needed), a best-effort PMTU probe, a baseline
download-speed sample, and your public exit IP (to confirm whether a VPN
was actually active during a given run). It NEVER reads, requests, or
transmits your subscription URL, UUID, REALITY key, Hysteria2 password,
or any vpn1 config file — those never touch this script at all.

RECOMMENDED METHODOLOGY (Phase 3/4 of the performance investigation):
run this script multiple times, in this order, changing nothing else
between runs:
  1. VPN disconnected                      --label baseline
  2. Connected via VLESS+REALITY profile   --label reality
  3. Connected via Hysteria2 profile       --label hysteria2
Compare the printed/JSON output across the three runs. The public exit
IP field alone tells you whether a given run was actually tunneled
(baseline should show your ISP's IP; reality/hysteria2 runs should show
the VPS's IP) — a very common self-inflicted "the VPN isn't even
active" mistake in earlier ad-hoc testing.

Usage:
  python3 vpn-client-diag.py --server your.vpn.host --label baseline
  python3 vpn-client-diag.py --server your.vpn.host --label reality --json out.json

Paste the printed report (or the JSON file) back into the issue/session
that asked for this data. Nothing in the output is secret.
"""

import argparse
import json
import platform
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

DEFAULT_DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
DEFAULT_IP_ECHO_URLS = [
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def safe_run(cmd, timeout=15):
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout + out.stderr
    except Exception as exc:  # noqa: BLE001 - best-effort diagnostic, never fatal
        return f"SKIPPED: {exc}"


def measure_dns(hostnames, samples=3):
    results = {}
    for host in hostnames:
        timings = []
        error = None
        for _ in range(samples):
            start = time.perf_counter()
            try:
                socket.getaddrinfo(host, None)
                timings.append((time.perf_counter() - start) * 1000.0)
            except Exception as exc:  # noqa: BLE001
                error = str(exc)
        results[host] = {
            "samples_ms": [round(t, 1) for t in timings],
            "median_ms": round(statistics.median(timings), 1) if timings else None,
            "error": error if not timings else None,
        }
    return results


def measure_tcp_connect(host, port, samples=3, timeout=5):
    timings = []
    errors = []
    for _ in range(samples):
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                timings.append((time.perf_counter() - start) * 1000.0)
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
    return {
        "samples_ms": [round(t, 1) for t in timings],
        "median_ms": round(statistics.median(timings), 1) if timings else None,
        "errors": errors,
    }


def measure_ping(host, count=10):
    """Shells out to the OS's own ping binary — works without admin/root
    on every platform, unlike raw ICMP sockets. Parses loss % and
    min/avg/max/jitter where the platform's own output makes that easy;
    falls back to raw output if parsing fails, so a format change in a
    given OS's ping never silently hides data."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), host]
    raw = safe_run(cmd, timeout=count * 2 + 10)

    loss_pct = None
    rtt_min = rtt_avg = rtt_max = None
    for line in raw.splitlines():
        low = line.lower()
        if "%" in low and ("loss" in low or "потер" in low):
            for token in line.replace(",", " ").split():
                if token.endswith("%"):
                    try:
                        loss_pct = float(token.rstrip("%"))
                    except ValueError:
                        pass
        if "min/avg/max" in low or "minimum" in low and "maximum" in low:
            # Linux/macOS: "rtt min/avg/max/mdev = 12.1/13.4/15.0/0.9 ms"
            # Windows: "Minimum = 12ms, Maximum = 15ms, Average = 13ms"
            nums = []
            for token in line.replace("=", " ").replace("/", " ").split():
                token = token.rstrip("ms,")
                try:
                    nums.append(float(token))
                except ValueError:
                    continue
            if system != "windows" and len(nums) >= 3:
                rtt_min, rtt_avg, rtt_max = nums[0], nums[1], nums[2]
    if system == "windows":
        mins, maxs, avgs = [], [], []
        for line in raw.splitlines():
            low = line.lower()
            if "minimum" in low:
                mins.append(low)
            if "average" in low:
                avgs.append(low)
        # best-effort only; Windows locales vary too much to parse robustly
    return {
        "raw": raw,
        "loss_pct": loss_pct,
        "rtt_min_ms": rtt_min,
        "rtt_avg_ms": rtt_avg,
        "rtt_max_ms": rtt_max,
    }


def measure_pmtu(host, start=1472, floor=1200, step=20):
    """Binary-search-ish best-effort PMTU probe using don't-fragment
    ping. 1472 = 1500 (typical Ethernet MTU) - 28 (ICMP+IP headers); if
    that size gets through unfragmented, the path MTU is >= 1500. Not a
    substitute for a real PMTUD/tracepath tool, but needs no extra
    software and no privileges on any of the three platforms."""
    system = platform.system().lower()
    size = start
    largest_ok = None
    while size >= floor:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-f", "-l", str(size), host]
        elif system == "darwin":
            cmd = ["ping", "-c", "1", "-D", "-s", str(size), host]
        else:
            cmd = ["ping", "-c", "1", "-M", "do", "-s", str(size), host]
        out = safe_run(cmd, timeout=5)
        low = out.lower()
        fragmented_or_failed = (
            "fragmentation needed" in low
            or "frag needed" in low
            or "message too long" in low
            or "packet needs to be fragmented" in low
        )
        got_reply = ("bytes from" in low) or ("reply from" in low and "ttl" in low)
        if got_reply and not fragmented_or_failed:
            largest_ok = size
            break
        size -= step
    if largest_ok is None:
        return {"path_mtu_estimate": None, "note": "probe failed or blocked by firewall"}
    return {"path_mtu_estimate": largest_ok + 28, "icmp_payload_ok_bytes": largest_ok}


def measure_download(url, timeout=30):
    start = time.perf_counter()
    total_bytes = 0
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total_bytes += len(chunk)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc), "bytes": total_bytes}
    elapsed = time.perf_counter() - start
    mbps = (total_bytes * 8 / 1_000_000) / elapsed if elapsed > 0 else None
    return {
        "bytes": total_bytes,
        "seconds": round(elapsed, 2),
        "mbps": round(mbps, 2) if mbps else None,
    }


def measure_public_ip():
    for url in DEFAULT_IP_ECHO_URLS:
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(url, timeout=8, context=ctx) as resp:
                ip = resp.read().decode().strip()
                if ip:
                    return {"ip": ip, "source": url}
        except Exception:  # noqa: BLE001
            continue
    return {"ip": None, "source": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--server", required=True, help="VPN server hostname or IP (no scheme, no port)")
    parser.add_argument("--port", type=int, default=443, help="server port to test TCP connect against (default 443)")
    parser.add_argument("--label", default="unlabeled", help="e.g. baseline, reality, hysteria2 — your own tag for this run")
    parser.add_argument("--download-url", default=DEFAULT_DOWNLOAD_URL, help="baseline speed-test URL (default: Cloudflare speed test, 10MB)")
    parser.add_argument("--ping-count", type=int, default=10)
    parser.add_argument("--skip-download", action="store_true", help="skip the throughput sample (DNS/ping/PMTU/IP only)")
    parser.add_argument("--json", metavar="PATH", help="also write the full result as JSON to this path")
    parser.add_argument("--network-label", default="", help="free-text note, e.g. 'home wifi', 'MTS mobile data' — for your own comparison, not detected automatically")
    args = parser.parse_args()

    print(f"vpn1 client diagnostics — label={args.label!r} target={args.server}:{args.port}")
    print("Collecting only network timing/throughput and your public exit IP.")
    print("No subscription URL, token, key, or password is read or sent by this script.\n")

    result = {
        "generated_at": now_iso(),
        "label": args.label,
        "network_label": args.network_label,
        "target_host": args.server,
        "target_port": args.port,
        "client_os": f"{platform.system()} {platform.release()}",
        "python_version": platform.python_version(),
    }

    print("[1/6] Public exit IP...")
    result["public_ip"] = measure_public_ip()
    print(f"      -> {result['public_ip']}")

    print("[2/6] DNS lookup latency...")
    result["dns"] = measure_dns([args.server, "www.google.com", "www.cloudflare.com"])
    for host, r in result["dns"].items():
        print(f"      {host}: median {r['median_ms']} ms")

    print(f"[3/6] TCP connect latency to {args.server}:{args.port}...")
    result["tcp_connect"] = measure_tcp_connect(args.server, args.port)
    print(f"      median {result['tcp_connect']['median_ms']} ms, errors: {len(result['tcp_connect']['errors'])}")

    print(f"[4/6] ICMP ping to {args.server} ({args.ping_count} packets)...")
    result["ping"] = measure_ping(args.server, count=args.ping_count)
    print(f"      loss {result['ping']['loss_pct']}%, rtt avg {result['ping']['rtt_avg_ms']} ms")

    print(f"[5/6] Best-effort PMTU probe to {args.server}...")
    result["pmtu"] = measure_pmtu(args.server)
    print(f"      -> {result['pmtu']}")

    if args.skip_download:
        result["download"] = {"skipped": True}
        print("[6/6] Download throughput sample: skipped (--skip-download)")
    else:
        print("[6/6] Download throughput sample (10MB from Cloudflare's speed-test endpoint)...")
        result["download"] = measure_download(args.download_url)
        print(f"      -> {result['download']}")

    print("\n--- Summary (paste this whole block back) ---")
    print(json.dumps(result, indent=2))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"\nAlso wrote JSON to {args.json}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

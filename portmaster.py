"""
Fast Async Port Scanner & Network Analyzer
Uses asyncio + semaphores for maximum speed with minimal resource usage.
"""

import asyncio
import socket
import ipaddress
import time
import argparse
import sys
from datetime import datetime

# ── Common service names ──────────────────────────────────────────────────────
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2181: "Zookeeper", 3000: "Dev Server", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5000: "Flask", 5432: "PostgreSQL",
    5672: "RabbitMQ", 5900: "VNC", 6379: "Redis", 6443: "Kubernetes",
    7000: "Cassandra", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "PHP-FPM", 9090: "Prometheus", 9200: "Elasticsearch",
    9300: "Elasticsearch", 15672: "RabbitMQ-Mgmt", 27017: "MongoDB",
    27018: "MongoDB", 50000: "SAP", 50070: "Hadoop",
}

TOP_1000_PORTS = list(range(1, 1024)) + [
    1433, 1521, 2049, 2181, 3000, 3306, 3389, 4444, 5000, 5432,
    5672, 5900, 6379, 6443, 7000, 8000, 8080, 8443, 8888, 9000,
    9090, 9200, 9300, 15672, 27017, 27018, 50070,
]


# ── Core scanner ──────────────────────────────────────────────────────────────

async def check_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore):
    """Return (port, True) if open, (port, False) otherwise."""
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True
        except Exception:
            return port, False


async def scan_host(
    host: str,
    ports: list[int],
    timeout: float = 0.5,
    concurrency: int = 1000,
) -> list[int]:
    """Scan all ports on a single host concurrently."""
    sem = asyncio.Semaphore(concurrency)
    tasks = [check_port(host, p, timeout, sem) for p in ports]
    results = await asyncio.gather(*tasks)
    return sorted(p for p, open_ in results if open_)


async def resolve_host(host: str) -> str | None:
    """Resolve hostname → IP, return None on failure."""
    loop = asyncio.get_event_loop()
    try:
        result = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        return result[0][4][0]
    except Exception:
        return None


# ── Reporting ─────────────────────────────────────────────────────────────────

def banner(text: str, width: int = 60):
    print("═" * width)
    print(f"  {text}")
    print("═" * width)


def print_results(host: str, ip: str, open_ports: list[int], elapsed: float):
    print(f"\n{'─'*60}")
    print(f"  Host   : {host}  ({ip})")
    print(f"  Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Time   : {elapsed:.2f}s")
    print(f"{'─'*60}")
    if not open_ports:
        print("  ⚠  No open ports found.\n")
        return
    print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE'}")
    print(f"  {'----':<8} {'-----':<10} {'-------'}")
    for port in open_ports:
        svc = COMMON_SERVICES.get(port, "unknown")
        print(f"  {port:<8} {'open':<10} {svc}")
    print(f"\n  ✔  {len(open_ports)} open port(s) found.\n")


# ── Network ping sweep (ICMP not available without root → TCP-based) ──────────

async def ping_sweep(network: str, concurrency: int = 500, timeout: float = 0.3):
    """Quick TCP-22/80/443 sweep to find live hosts on a subnet."""
    try:
        net = ipaddress.IPv4Network(network, strict=False)
    except ValueError as e:
        print(f"[!] Invalid network: {e}")
        return []

    probe_ports = [22, 80, 443, 8080]
    print(f"\n[*] Sweeping {net} ({net.num_addresses} addresses) …")

    sem = asyncio.Semaphore(concurrency)

    async def is_alive(ip: str) -> str | None:
        tasks = [check_port(ip, p, timeout, sem) for p in probe_ports]
        results = await asyncio.gather(*tasks)
        return ip if any(open_ for _, open_ in results) else None

    hosts = [str(h) for h in net.hosts()]
    alive = await asyncio.gather(*[is_alive(h) for h in hosts])
    return [h for h in alive if h]


# ── CLI ───────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser(
        description="⚡ Fast Async Port Scanner & Network Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fast_port_scanner.py scanme.nmap.org
  python fast_port_scanner.py 192.168.1.1 -p 1-65535
  python fast_port_scanner.py 192.168.1.1 -p 22,80,443,3306
  python fast_port_scanner.py --sweep 192.168.1.0/24
        """,
    )
    parser.add_argument("target", nargs="?", help="Target host/IP to scan")
    parser.add_argument(
        "-p", "--ports",
        default="top1000",
        help="Port range: 'top1000' | '1-65535' | '22,80,443' (default: top1000)",
    )
    parser.add_argument("-t", "--timeout", type=float, default=0.5, help="Per-port timeout in seconds (default: 0.5)")
    parser.add_argument("-c", "--concurrency", type=int, default=1000, help="Max concurrent connections (default: 1000)")
    parser.add_argument("--sweep", metavar="CIDR", help="Ping-sweep a subnet, e.g. 192.168.1.0/24")

    args = parser.parse_args()

    banner("⚡ Fast Async Port Scanner  |  github.com/you")

    # ── Network sweep mode ────────────────────────────────────────────────────
    if args.sweep:
        t0 = time.perf_counter()
        live = await ping_sweep(args.sweep, concurrency=args.concurrency, timeout=args.timeout)
        elapsed = time.perf_counter() - t0
        print(f"\n  Live hosts ({len(live)}) found in {elapsed:.2f}s:")
        for h in live:
            try:
                hostname = socket.gethostbyaddr(h)[0]
            except Exception:
                hostname = ""
            suffix = f"  ({hostname})" if hostname else ""
            print(f"    ✔  {h}{suffix}")
        print()
        return

    # ── Single host scan mode ─────────────────────────────────────────────────
    if not args.target:
        parser.print_help()
        sys.exit(1)

    # Resolve
    print(f"\n[*] Resolving {args.target} …")
    ip = await resolve_host(args.target)
    if not ip:
        print(f"[!] Could not resolve '{args.target}'. Exiting.")
        sys.exit(1)
    print(f"[*] {args.target}  →  {ip}")

    # Build port list
    if args.ports == "top1000":
        ports = TOP_1000_PORTS
        print(f"[*] Scanning top {len(ports)} ports …")
    elif "-" in args.ports:
        start, end = args.ports.split("-")
        ports = list(range(int(start), int(end) + 1))
        print(f"[*] Scanning ports {start}–{end} ({len(ports)} total) …")
    else:
        ports = [int(p) for p in args.ports.split(",")]
        print(f"[*] Scanning {len(ports)} specified ports …")

    print(f"[*] Concurrency={args.concurrency}, Timeout={args.timeout}s\n")

    t0 = time.perf_counter()
    open_ports = await scan_host(ip, ports, timeout=args.timeout, concurrency=args.concurrency)
    elapsed = time.perf_counter() - t0

    print_results(args.target, ip, open_ports, elapsed)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")

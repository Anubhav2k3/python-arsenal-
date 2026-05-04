#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║         AI Recon Agent — Powered by Gemini API           ║
║   Safe, passive recon with natural language interface    ║
╚══════════════════════════════════════════════════════════╝

Usage:
    python gemini_recon.py
    python gemini_recon.py --target example.com
    python gemini_recon.py --target 8.8.8.8 --mode full

Requirements:
    pip install google-generativeai requests dnspython
"""

import os
import sys
import json
import socket
import subprocess
import argparse
import textwrap
import ipaddress
from datetime import datetime

# ── Optional deps (graceful fallback) ─────────────────────
try:
    import google.generativeai as genai
    GEMINI_OK = True
except ImportError:
    GEMINI_OK = False
    print("[!] google-generativeai not installed. Run: pip install google-generativeai")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ══════════════════════════════════════════════════════════
# CONFIGURATION — edit only this block
# ══════════════════════════════════════════════════════════
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "YOUR_API_KEY_HERE")
GEMINI_MODEL   = "gemini-2.0-flash"   # or gemini-1.5-pro
MAX_OUTPUT_LEN = 2000                 # chars to feed back to Gemini per tool

# ══════════════════════════════════════════════════════════
# COLORS & DISPLAY
# ══════════════════════════════════════════════════════════
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    BLUE   = "\033[94m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.RESET}{C.GRAY}       AI Recon Agent  ·  Gemini Powered{C.RESET}
""")

def section(title: str):
    width = 56
    bar = "─" * width
    print(f"\n{C.BLUE}{bar}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  {title}{C.RESET}")
    print(f"{C.BLUE}{bar}{C.RESET}")

def result_row(label: str, value: str, color=C.GREEN):
    label_fmt = f"{C.CYAN}{label:<22}{C.RESET}"
    value_fmt = f"{color}{value}{C.RESET}"
    print(f"  {label_fmt} {value_fmt}")

def info(msg):  print(f"  {C.YELLOW}[*]{C.RESET} {msg}")
def ok(msg):    print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def err(msg):   print(f"  {C.RED}[-]{C.RESET} {msg}")
def ai_say(msg):
    print(f"\n  {C.CYAN}🤖 Gemini Analysis:{C.RESET}")
    for line in textwrap.wrap(msg, width=70):
        print(f"     {line}")
    print()

# ══════════════════════════════════════════════════════════
# SAFE RECON TOOLS
# ══════════════════════════════════════════════════════════

def run_cmd(cmd: list, timeout=15) -> str:
    """Run a system command safely and return output."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return (result.stdout + result.stderr).strip()
    except FileNotFoundError:
        return f"[not available: {cmd[0]}]"
    except subprocess.TimeoutExpired:
        return "[timeout]"
    except Exception as e:
        return f"[error: {e}]"

def tool_ping(target: str) -> dict:
    """Ping the target (4 packets)."""
    info(f"Pinging {target} ...")
    flag = "-n" if sys.platform == "win32" else "-c"
    out = run_cmd(["ping", flag, "4", target], timeout=10)
    alive = "ttl=" in out.lower() or "bytes from" in out.lower()
    return {"alive": alive, "raw": out}

def tool_dns_lookup(target: str) -> dict:
    """Resolve A, MX, NS, TXT records."""
    info("DNS lookup ...")
    records = {}
    rtypes = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    if DNS_OK:
        for rtype in rtypes:
            try:
                answers = dns.resolver.resolve(target, rtype, raise_on_no_answer=False)
                records[rtype] = [r.to_text() for r in answers]
            except Exception:
                pass
    else:
        try:
            records["A"] = [socket.gethostbyname(target)]
        except Exception as e:
            records["error"] = str(e)
    return records

def tool_whois(target: str) -> dict:
    """Basic WHOIS via system command."""
    info("WHOIS lookup ...")
    out = run_cmd(["whois", target], timeout=20)
    if "[not available" in out:
        out = "whois not found on this system"
    # Extract key lines to keep it concise
    important = []
    keywords = ["registrar", "creation", "expir", "updated", "name server",
                 "organization", "country", "status", "registrant"]
    for line in out.splitlines():
        if any(k in line.lower() for k in keywords):
            important.append(line.strip())
    return {"summary": important[:25], "full_length": len(out)}

def tool_traceroute(target: str) -> dict:
    """Traceroute / tracert (first 10 hops)."""
    info("Traceroute (10 hops) ...")
    if sys.platform == "win32":
        out = run_cmd(["tracert", "-h", "10", target], timeout=30)
    else:
        cmd = ["traceroute", "-m", "10", target]
        out = run_cmd(cmd, timeout=30)
        if "[not available" in out:
            out = run_cmd(["tracepath", "-m", "10", target], timeout=30)
    return {"raw": out[:MAX_OUTPUT_LEN]}

def tool_port_scan(target: str, ports=None) -> dict:
    """Quick TCP connect scan on common ports (no nmap needed)."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143,
                 443, 445, 3306, 3389, 5432, 8080, 8443]
    info(f"Port scan on {len(ports)} common ports ...")
    open_ports, closed = [], []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.8)
        try:
            res = sock.connect_ex((target, port))
            if res == 0:
                open_ports.append(port)
            else:
                closed.append(port)
        except Exception:
            closed.append(port)
        finally:
            sock.close()
    return {"open": open_ports, "closed_count": len(closed)}

def tool_http_headers(target: str) -> dict:
    """Fetch HTTP headers from a target."""
    if not REQUESTS_OK:
        return {"error": "requests not installed"}
    info("Fetching HTTP headers ...")
    results = {}
    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        try:
            r = requests.head(url, timeout=8, allow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0 (recon-tool)"})
            results[scheme] = {
                "status":  r.status_code,
                "server":  r.headers.get("Server", "—"),
                "powered": r.headers.get("X-Powered-By", "—"),
                "csp":     "✓" if "Content-Security-Policy" in r.headers else "✗",
                "hsts":    "✓" if "Strict-Transport-Security" in r.headers else "✗",
                "x-frame": r.headers.get("X-Frame-Options", "—"),
                "final_url": r.url,
            }
            break
        except Exception as e:
            results[scheme] = {"error": str(e)}
    return results

def tool_reverse_dns(ip: str) -> dict:
    """Reverse DNS lookup for an IP."""
    info("Reverse DNS ...")
    try:
        host = socket.gethostbyaddr(ip)[0]
        return {"hostname": host}
    except Exception as e:
        return {"error": str(e)}

def tool_ip_geolocation(target: str) -> dict:
    """Free IP geolocation via ip-api.com."""
    if not REQUESTS_OK:
        return {"error": "requests not installed"}
    info("IP geolocation ...")
    try:
        r = requests.get(f"http://ip-api.com/json/{target}", timeout=8)
        data = r.json()
        return {
            "country": data.get("country", "—"),
            "region":  data.get("regionName", "—"),
            "city":    data.get("city", "—"),
            "isp":     data.get("isp", "—"),
            "org":     data.get("org", "—"),
            "lat":     data.get("lat"),
            "lon":     data.get("lon"),
            "as":      data.get("as", "—"),
        }
    except Exception as e:
        return {"error": str(e)}

def tool_ssl_info(target: str) -> dict:
    """Check SSL certificate details."""
    import ssl, socket as s
    info("SSL certificate check ...")
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(s.create_connection((target, 443), timeout=8),
                               server_hostname=target)
        cert = conn.getpeercert()
        conn.close()
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        return {
            "common_name": subject.get("commonName", "—"),
            "org":         subject.get("organizationName", "—"),
            "issuer":      issuer.get("organizationName", "—"),
            "valid_from":  cert.get("notBefore", "—"),
            "valid_to":    cert.get("notAfter", "—"),
            "san":         [v for _, v in cert.get("subjectAltName", [])],
        }
    except Exception as e:
        return {"error": str(e)}

# ══════════════════════════════════════════════════════════
# GEMINI INTEGRATION
# ══════════════════════════════════════════════════════════

def init_gemini():
    if not GEMINI_OK:
        return None
    if GEMINI_API_KEY == "YOUR_API_KEY_HERE":
        err("Set your GEMINI_API_KEY in the script or as env variable.")
        return None
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        return model
    except Exception as e:
        err(f"Gemini init failed: {e}")
        return None

def gemini_analyze(model, target: str, recon_data: dict, question: str = None) -> str:
    """Send recon results to Gemini for AI analysis."""
    if model is None:
        return "Gemini not configured — skipping AI analysis."
    
    prompt = f"""You are a cybersecurity reconnaissance analyst.
Target: {target}
Timestamp: {datetime.utcnow().isoformat()}Z

Recon data collected (JSON):
{json.dumps(recon_data, indent=2, default=str)[:4000]}

{f'User question: {question}' if question else ''}

Provide a concise, professional analysis covering:
1. Key findings and what they reveal about the target
2. Security observations (open ports, missing headers, cert issues, etc.)
3. Risk highlights (low/medium/high)
4. 2–3 brief recommendations

Keep it under 300 words. Be direct and factual. No markdown."""
    
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"Gemini API error: {e}"

def gemini_chat(model, history: list, user_msg: str, context: str) -> str:
    """Interactive follow-up chat with Gemini."""
    if model is None:
        return "Gemini not available."
    system = f"You are a recon analyst. Context:\n{context[:3000]}"
    full_history = [{"role": "user", "parts": [system]},
                    {"role": "model", "parts": ["Understood. Ready to answer questions."]}]
    for turn in history:
        full_history.append(turn)
    full_history.append({"role": "user", "parts": [user_msg]})
    try:
        chat = model.start_chat(history=full_history[:-1])
        r = chat.send_message(user_msg)
        return r.text.strip()
    except Exception as e:
        return f"Error: {e}"

# ══════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ══════════════════════════════════════════════════════════

def display_ping(data: dict):
    section("🏓  PING")
    status = f"{C.GREEN}ALIVE{C.RESET}" if data["alive"] else f"{C.RED}UNREACHABLE{C.RESET}"
    result_row("Status", "ALIVE" if data["alive"] else "UNREACHABLE",
               C.GREEN if data["alive"] else C.RED)
    for line in data["raw"].splitlines()[-6:]:
        if line.strip():
            print(f"  {C.GRAY}{line}{C.RESET}")

def display_dns(data: dict):
    section("🔎  DNS RECORDS")
    if "error" in data:
        err(data["error"]); return
    for rtype, vals in data.items():
        for v in vals[:5]:
            result_row(rtype, v)

def display_whois(data: dict):
    section("📋  WHOIS")
    result_row("Lines matched", str(len(data["summary"])))
    for line in data["summary"]:
        print(f"  {C.GRAY}{line}{C.RESET}")

def display_traceroute(data: dict):
    section("🛤️   TRACEROUTE  (10 hops)")
    for line in data["raw"].splitlines():
        if line.strip():
            print(f"  {C.GRAY}{line}{C.RESET}")

def display_ports(data: dict):
    section("🔌  PORT SCAN")
    if data["open"]:
        for p in data["open"]:
            svc = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
                   80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",
                   445:"SMB",3306:"MySQL",3389:"RDP",5432:"Postgres",
                   8080:"HTTP-Alt",8443:"HTTPS-Alt"}.get(p, "?")
            result_row(f"Port {p}", f"OPEN  ({svc})", C.GREEN)
    else:
        info("No common ports open (or filtered)")
    result_row("Closed/filtered", str(data["closed_count"]), C.GRAY)

def display_http(data: dict):
    section("🌐  HTTP HEADERS")
    for scheme, h in data.items():
        if "error" in h:
            err(f"{scheme}: {h['error']}"); continue
        print(f"\n  {C.BOLD}{scheme.upper()}{C.RESET}")
        result_row("Status",   str(h.get("status",   "—")))
        result_row("Server",   str(h.get("server",   "—")))
        result_row("Powered-By",str(h.get("powered", "—")))
        result_row("CSP",      h.get("csp", "—"), C.GREEN if h.get("csp")=="✓" else C.RED)
        result_row("HSTS",     h.get("hsts","—"), C.GREEN if h.get("hsts")=="✓" else C.RED)
        result_row("X-Frame",  str(h.get("x-frame",  "—")))
        result_row("Final URL",str(h.get("final_url","—")))

def display_geo(data: dict):
    section("🌍  GEOLOCATION")
    if "error" in data:
        err(data["error"]); return
    for k, v in data.items():
        if v and v != "—":
            result_row(k.capitalize(), str(v))

def display_ssl(data: dict):
    section("🔒  SSL / TLS")
    if "error" in data:
        err(data["error"]); return
    for k, v in data.items():
        if k == "san":
            result_row("SANs", ", ".join(v[:6]))
        elif v and v != "—":
            result_row(k.replace("_", " ").title(), str(v))

def display_reverse(data: dict):
    section("🔄  REVERSE DNS")
    if "error" in data:
        err(data["error"])
    else:
        result_row("Hostname", data.get("hostname", "—"))

# ══════════════════════════════════════════════════════════
# MAIN RUNNER
# ══════════════════════════════════════════════════════════

def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def run_recon(target: str, mode: str = "full") -> dict:
    """Run all (or selected) recon tools and return collected data."""
    recon = {}

    # Always run
    recon["ping"]    = tool_ping(target)
    recon["dns"]     = tool_dns_lookup(target) if not is_ip(target) else {"skipped": "IP target"}
    recon["geo"]     = tool_ip_geolocation(target)
    recon["ports"]   = tool_port_scan(target)
    recon["http"]    = tool_http_headers(target)

    if mode == "full":
        recon["whois"]     = tool_whois(target)
        recon["ssl"]       = tool_ssl_info(target)
        recon["traceroute"]= tool_traceroute(target)
        if is_ip(target):
            recon["reverse_dns"] = tool_reverse_dns(target)

    return recon

def display_all(recon: dict):
    """Render all collected data."""
    if "ping"        in recon: display_ping(recon["ping"])
    if "dns"         in recon and "skipped" not in recon["dns"]:
        display_dns(recon["dns"])
    if "geo"         in recon: display_geo(recon["geo"])
    if "ports"       in recon: display_ports(recon["ports"])
    if "http"        in recon: display_http(recon["http"])
    if "whois"       in recon: display_whois(recon["whois"])
    if "ssl"         in recon: display_ssl(recon["ssl"])
    if "traceroute"  in recon: display_traceroute(recon["traceroute"])
    if "reverse_dns" in recon: display_reverse(recon["reverse_dns"])

# ══════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AI Recon Agent powered by Gemini",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
          Examples:
            python gemini_recon.py
            python gemini_recon.py --target example.com
            python gemini_recon.py --target 1.1.1.1 --mode quick
            python gemini_recon.py --target example.com --no-ai
        """)
    )
    parser.add_argument("--target",  help="Domain or IP to recon")
    parser.add_argument("--mode",    choices=["quick","full"], default="full",
                        help="quick = core checks only; full = everything (default)")
    parser.add_argument("--no-ai",   action="store_true", help="Skip Gemini AI analysis")
    parser.add_argument("--save",    help="Save results to JSON file")
    args = parser.parse_args()

    banner()

    # ── Get target ─────────────────────────────────────────
    target = args.target
    if not target:
        target = input(f"  {C.CYAN}Enter target (domain or IP):{C.RESET} ").strip()
    if not target:
        err("No target provided."); sys.exit(1)

    # Normalise — strip http(s)://
    target = target.removeprefix("https://").removeprefix("http://").split("/")[0]

    # ── Init Gemini ────────────────────────────────────────
    model = None if args.no_ai else init_gemini()

    print(f"\n  {C.BOLD}Target:{C.RESET} {C.WHITE}{target}{C.RESET}")
    print(f"  {C.BOLD}Mode  :{C.RESET} {args.mode}")
    print(f"  {C.BOLD}AI    :{C.RESET} {'disabled' if args.no_ai or model is None else 'Gemini ' + GEMINI_MODEL}")
    print(f"  {C.BOLD}Time  :{C.RESET} {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    # ── Run recon ──────────────────────────────────────────
    section("⚡  STARTING RECON")
    recon = run_recon(target, mode=args.mode)

    # ── Display results ────────────────────────────────────
    display_all(recon)

    # ── AI Analysis ────────────────────────────────────────
    section("🤖  AI ANALYSIS — GEMINI")
    analysis = gemini_analyze(model, target, recon)
    ai_say(analysis)

    # ── Save ───────────────────────────────────────────────
    if args.save:
        out = {"target": target, "timestamp": datetime.utcnow().isoformat(),
               "recon": recon, "ai_analysis": analysis}
        with open(args.save, "w") as f:
            json.dump(out, f, indent=2, default=str)
        ok(f"Results saved → {args.save}")

    # ── Interactive Q&A ────────────────────────────────────
    if model:
        section("💬  INTERACTIVE CHAT  (type 'exit' to quit)")
        context = json.dumps(recon, default=str)
        history = []
        while True:
            try:
                q = input(f"\n  {C.CYAN}Ask Gemini:{C.RESET} ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not q or q.lower() in {"exit", "quit", "q"}:
                break
            reply = gemini_chat(model, history, q, context)
            ai_say(reply)
            history.append({"role": "user",  "parts": [q]})
            history.append({"role": "model", "parts": [reply]})

    print(f"\n  {C.GRAY}{'─'*56}{C.RESET}")
    ok("Recon complete.")
    print()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
domain_analyzer.py — Full tech stack fingerprinting for any domain.
Usage: python domain_analyzer.py example.com
"""

import sys
import ssl
import socket
import json
import re
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
import urllib.request
import urllib.error

# ── Optional deps (gracefully degraded if missing) ──────────────────────────
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False

# ── Color helpers (fallback if Rich not installed) ───────────────────────────
def p(label, value, color="cyan"):
    if HAS_RICH:
        console.print(f"  [bold]{label}:[/bold] [{color}]{value}[/{color}]")
    else:
        print(f"  {label}: {value}")

def section(title):
    if HAS_RICH:
        console.rule(f"[bold yellow]{title}[/bold yellow]")
    else:
        print(f"\n{'='*60}\n  {title}\n{'='*60}")

# ════════════════════════════════════════════════════════════════════════════
# TECHNOLOGY SIGNATURES
# ════════════════════════════════════════════════════════════════════════════

TECH_SIGNATURES = {
    # ── Frontend Frameworks ───────────────────────────────────────────────
    "React":            [r'react(?:\.min)?\.js', r'__REACT', r'data-reactroot', r'_reactFiber', r'react-dom'],
    "Vue.js":           [r'vue(?:\.min)?\.js', r'__vue__', r'data-v-\w+', r'\bVue\.'],
    "Angular":          [r'angular(?:\.min)?\.js', r'ng-version', r'ng-app', r'\bangular\b'],
    "Next.js":          [r'__NEXT_DATA__', r'_next/static', r'next/dist'],
    "Nuxt.js":          [r'__nuxt', r'_nuxt/', r'window\.__NUXT__'],
    "Svelte":           [r'svelte', r'__svelte'],
    "Ember.js":         [r'ember(?:\.min)?\.js', r'Ember\.VERSION', r'data-ember-action'],
    "Backbone.js":      [r'backbone(?:\.min)?\.js', r'Backbone\.'],
    "jQuery":           [r'jquery(?:\.min)?\.js', r'\bjQuery\b', r'\$\(document\)'],
    "Alpine.js":        [r'alpine(?:\.min)?\.js', r'x-data='],
    "Gatsby":           [r'___gatsby', r'gatsby-'],
    "Remix":            [r'__remixContext', r'@remix-run'],
    "Astro":            [r'astro-', r'@astrojs'],
    "HTMX":             [r'htmx(?:\.min)?\.js', r'hx-get', r'hx-post'],

    # ── CSS Frameworks ────────────────────────────────────────────────────
    "Bootstrap":        [r'bootstrap(?:\.min)?\.css', r'bootstrap(?:\.min)?\.js', r'class="[^"]*\bcol-\w+-\d+\b'],
    "Tailwind CSS":     [r'tailwind(?:\.min)?\.css', r'class="[^"]*\b(?:flex|grid|p-\d|m-\d|text-\w+)\b'],
    "Bulma":            [r'bulma(?:\.min)?\.css', r'class="[^"]*\b(?:columns|column|hero)\b'],
    "Foundation":       [r'foundation(?:\.min)?\.css'],
    "Materialize":      [r'materialize(?:\.min)?\.css'],

    # ── CMS ───────────────────────────────────────────────────────────────
    "WordPress":        [r'wp-content', r'wp-includes', r'wp-json', r'WordPress'],
    "Drupal":           [r'Drupal\.settings', r'/sites/default/files', r'drupal\.js'],
    "Joomla":           [r'/components/com_', r'Joomla!', r'joomla'],
    "Shopify":          [r'Shopify\.theme', r'cdn\.shopify\.com', r'myshopify\.com'],
    "Wix":              [r'wix\.com', r'wixstatic\.com', r'X-Wix-'],
    "Squarespace":      [r'squarespace\.com', r'static\.squarespace\.com'],
    "Ghost":            [r'ghost\.io', r'content\.ghost\.io'],
    "Webflow":          [r'webflow\.com', r'Webflow\.'],
    "Contentful":       [r'contentful\.com'],

    # ── Backend / Server-side ─────────────────────────────────────────────
    "PHP":              [r'\.php', r'PHPSESSID', r'X-Powered-By: PHP'],
    "Laravel":          [r'laravel_session', r'XSRF-TOKEN', r'Laravel'],
    "Django":           [r'csrfmiddlewaretoken', r'django', r'__django'],
    "Ruby on Rails":    [r'_rails_', r'X-Runtime', r'Rails'],
    "ASP.NET":          [r'ASP\.NET', r'__VIEWSTATE', r'__EVENTVALIDATION', r'\.aspx'],
    "Express.js":       [r'X-Powered-By: Express'],
    "FastAPI":          [r'fastapi', r'openapi\.json'],
    "Spring":           [r'JSESSIONID', r'X-Application-Context'],
    "Flask":            [r'Werkzeug', r'flask'],
    "Node.js":          [r'X-Powered-By: Node'],

    # ── Web Servers ───────────────────────────────────────────────────────
    "Nginx":            [r'nginx', r'Server: nginx'],
    "Apache":           [r'Apache', r'Server: Apache'],
    "Caddy":            [r'Caddy', r'Server: Caddy'],
    "LiteSpeed":        [r'LiteSpeed', r'Server: LiteSpeed'],
    "IIS":              [r'Microsoft-IIS', r'Server: Microsoft-IIS'],

    # ── CDN / Cloud ───────────────────────────────────────────────────────
    "Cloudflare":       [r'cloudflare', r'CF-Ray', r'__cfduid', r'cf-cache-status'],
    "AWS CloudFront":   [r'CloudFront', r'X-Amz-Cf-Id', r'X-Cache: Hit from cloudfront'],
    "Fastly":           [r'Fastly', r'X-Served-By', r'X-Cache: HIT, HIT'],
    "Vercel":           [r'vercel', r'x-vercel-id', r'\.vercel\.app'],
    "Netlify":          [r'netlify', r'X-Netlify', r'\.netlify\.app'],
    "AWS S3":           [r'AmazonS3', r's3\.amazonaws\.com', r'x-amz-request-id'],
    "Google Cloud":     [r'X-GUploader', r'storage\.googleapis\.com'],
    "Azure":            [r'X-Azure-', r'\.azurewebsites\.net'],

    # ── Analytics / Marketing ─────────────────────────────────────────────
    "Google Analytics": [r'google-analytics\.com', r'gtag\(', r'ga\.js', r'analytics\.js'],
    "Google Tag Manager":[r'googletagmanager\.com', r'GTM-'],
    "Hotjar":           [r'hotjar\.com', r'_hjSettings'],
    "Mixpanel":         [r'mixpanel\.com', r'mixpanel\.init'],
    "HubSpot":          [r'hubspot\.com', r'hs-scripts\.com'],
    "Intercom":         [r'intercom\.io', r'intercomSettings'],
    "Segment":          [r'segment\.com', r'analytics\.load'],

    # ── Payment ───────────────────────────────────────────────────────────
    "Stripe":           [r'stripe\.com', r'Stripe\.js', r'js\.stripe\.com'],
    "PayPal":           [r'paypal\.com', r'paypalobjects\.com'],

    # ── Security ──────────────────────────────────────────────────────────
    "reCAPTCHA":        [r'recaptcha', r'google\.com/recaptcha'],
    "hCaptcha":         [r'hcaptcha\.com'],
    "Cloudflare Turnstile": [r'challenges\.cloudflare\.com'],
}

# Headers → technology map
HEADER_TECH = {
    "server":           "Web Server",
    "x-powered-by":     "Runtime",
    "x-generator":      "Generator",
    "x-cms":            "CMS",
    "x-frame-options":  "Security Header",
    "content-security-policy": "Security Header",
    "strict-transport-security": "Security Header",
    "x-content-type-options": "Security Header",
    "x-xss-protection": "Security Header",
    "referrer-policy":  "Security Header",
    "permissions-policy": "Security Header",
    "cf-ray":           "CDN (Cloudflare)",
    "x-amz-cf-id":      "CDN (AWS CloudFront)",
    "x-cache":          "Cache",
    "x-varnish":        "Cache (Varnish)",
    "via":              "Proxy/CDN",
    "x-vercel-id":      "Hosting (Vercel)",
    "x-netlify-id":     "Hosting (Netlify)",
    "x-runtime":        "Framework",
    "x-request-id":     "Request Tracing",
    "alt-svc":          "HTTP/3 / QUIC Support",
}

# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════

def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        domain = urlparse(domain).netloc
    return domain.split("/")[0]


def fetch_page(url: str, timeout=10):
    """Fetch URL, return (response_obj_or_None, html_text_or_None)."""
    if HAS_REQUESTS:
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             headers={"User-Agent": "Mozilla/5.0 (DomainAnalyzer/1.0)"})
            return r, r.text
        except Exception:
            return None, None
    else:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode("utf-8", errors="replace")
                return resp, html
        except Exception:
            return None, None


def match_signatures(text: str) -> list[str]:
    found = []
    for tech, patterns in TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                found.append(tech)
                break
    return found

# ════════════════════════════════════════════════════════════════════════════
# ANALYSIS MODULES
# ════════════════════════════════════════════════════════════════════════════

def analyze_dns(domain):
    section("DNS Records")
    results = {}

    if HAS_DNS:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records = [str(r) for r in answers]
                results[rtype] = records
                p(rtype, ", ".join(records), "green")
            except Exception:
                pass
    else:
        # Fallback: socket
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            results["A"] = ips
            p("A (socket)", ", ".join(ips), "green")
        except Exception as e:
            p("Error", str(e), "red")

    # IP geolocation hint
    if "A" in results and results["A"]:
        ip = results["A"][0]
        p("Primary IP", ip, "cyan")
        try:
            # Check if private
            if ipaddress.ip_address(ip).is_private:
                p("IP Type", "Private / Internal", "yellow")
        except Exception:
            pass

    return results


def analyze_ssl(domain):
    section("SSL / TLS Certificate")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=8),
                             server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer  = dict(x[0] for x in cert.get("issuer", []))

        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
        days_left  = (not_after - datetime.utcnow()).days

        p("Common Name",  subject.get("commonName", "N/A"))
        p("Issuer",       issuer.get("organizationName", "N/A"))
        p("Valid From",   not_before.strftime("%Y-%m-%d"))
        p("Valid Until",  not_after.strftime("%Y-%m-%d"),
          "green" if days_left > 30 else "red")
        p("Days Remaining", str(days_left),
          "green" if days_left > 30 else "red")
        p("TLS Version",  version, "cyan")
        p("Cipher Suite", cipher[0] if cipher else "N/A")

        # SANs
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        if sans:
            p("SANs", ", ".join(sans[:8]) + ("..." if len(sans) > 8 else ""), "blue")

        return {"issuer": issuer, "days_left": days_left, "version": version}
    except Exception as e:
        p("SSL Error", str(e), "red")
        return {}


def analyze_headers(resp, domain):
    section("HTTP Headers & Server Info")
    detected = []

    if HAS_REQUESTS:
        headers = dict(resp.headers)
    else:
        headers = dict(resp.getheaders())

    important = {}
    security_headers = {}
    SECURITY_KEYS = {"x-frame-options","content-security-policy",
                     "strict-transport-security","x-content-type-options",
                     "x-xss-protection","referrer-policy","permissions-policy"}

    for k, v in headers.items():
        kl = k.lower()
        if kl in SECURITY_KEYS:
            security_headers[k] = v
        elif kl in HEADER_TECH:
            important[k] = v

        # Technology detection from header values
        matched = match_signatures(f"{k}: {v}")
        detected.extend(matched)

    if important:
        p("Notable Headers", "", "white")
        for k, v in important.items():
            short_v = v[:80] + "…" if len(v) > 80 else v
            p(f"  {k}", short_v, "cyan")

    # Security score
    section("Security Headers")
    score = 0
    for h in ["Strict-Transport-Security","Content-Security-Policy",
              "X-Frame-Options","X-Content-Type-Options",
              "Referrer-Policy","Permissions-Policy"]:
        found = any(k.lower() == h.lower() for k in security_headers)
        status = "✓" if found else "✗"
        color  = "green" if found else "red"
        if found: score += 1
        p(h, status, color)

    p("Security Score", f"{score}/6",
      "green" if score >= 4 else "yellow" if score >= 2 else "red")

    return detected, security_headers


def analyze_html(html, url):
    section("Frontend Technology")
    detected = []

    # Detect from raw HTML
    detected.extend(match_signatures(html))

    meta_tags = {}
    links = []
    scripts = []
    generators = []

    if HAS_BS4:
        soup = BeautifulSoup(html, "html.parser")

        # Meta tags
        for tag in soup.find_all("meta"):
            name = tag.get("name","").lower()
            prop = tag.get("property","").lower()
            content = tag.get("content","")
            if name in ("generator","description","author","keywords"):
                meta_tags[name] = content
            if "generator" in name:
                generators.append(content)

        # Script sources
        for s in soup.find_all("script", src=True):
            src = s.get("src","")
            scripts.append(src)
            detected.extend(match_signatures(src))

        # Link/stylesheet sources
        for l in soup.find_all("link", rel=True):
            href = l.get("href","")
            links.append(href)
            detected.extend(match_signatures(href))

        # Inline scripts
        for s in soup.find_all("script"):
            if s.string:
                detected.extend(match_signatures(s.string[:2000]))

        p("Title", soup.title.string.strip() if soup.title and soup.title.string else "N/A")

        if meta_tags.get("generator"):
            p("Generator Meta", meta_tags["generator"], "yellow")
        if meta_tags.get("description"):
            short = meta_tags["description"][:100]
            p("Description", short)

        p("Scripts loaded", str(len(scripts)), "cyan")
        p("Stylesheets",   str(len([l for l in links if "stylesheet" in l.lower() or ".css" in l])), "cyan")

    else:
        # Regex fallback
        for pat in [r'<title>(.*?)</title>', r'<meta name="generator" content="([^"]+)"']:
            m = re.search(pat, html, re.IGNORECASE | re.DOTALL)
            if m:
                p(pat.split(">")[0].lstrip("<"), m.group(1).strip())

    return list(set(detected)), meta_tags


def analyze_extra_paths(domain):
    section("Common Paths Probe")
    paths = {
        "/robots.txt":     "Robots file",
        "/sitemap.xml":    "Sitemap",
        "/.well-known/security.txt": "Security.txt",
        "/wp-login.php":   "WordPress login",
        "/wp-json/wp/v2/": "WordPress REST API",
        "/admin":          "Admin panel",
        "/graphql":        "GraphQL endpoint",
        "/api":            "API endpoint",
        "/api/v1":         "API v1",
        "/swagger":        "Swagger docs",
        "/openapi.json":   "OpenAPI spec",
        "/__version__":    "Version endpoint",
        "/manifest.json":  "PWA manifest",
        "/.env":           "Exposed .env (dangerous!)",
    }
    found = []
    base = f"https://{domain}"

    for path, label in paths.items():
        resp, html = fetch_page(base + path, timeout=5)
        if resp is None:
            continue
        code = resp.status_code if HAS_REQUESTS else resp.status
        if code in (200, 301, 302):
            color = "red" if ".env" in path else "green"
            p(f"{label} ({path})", f"HTTP {code}", color)
            found.append(path)

    if not found:
        p("No common paths found", "—", "dim")
    return found


def analyze_whois(domain):
    section("WHOIS / Domain Info")
    if not HAS_WHOIS:
        p("python-whois not installed", "pip install python-whois", "yellow")
        return {}

    try:
        w = whois.whois(domain)
        registrar = getattr(w, "registrar", None)
        creation  = getattr(w, "creation_date", None)
        expiry    = getattr(w, "expiration_date", None)
        country   = getattr(w, "country", None)
        org       = getattr(w, "org", None)

        if registrar: p("Registrar", str(registrar)[:60])
        if org:       p("Organization", str(org)[:60])
        if country:   p("Country", str(country))

        def fmt_date(d):
            if isinstance(d, list): d = d[0]
            return d.strftime("%Y-%m-%d") if isinstance(d, datetime) else str(d)

        if creation: p("Created",  fmt_date(creation), "blue")
        if expiry:   p("Expires",  fmt_date(expiry),   "cyan")

        ns = getattr(w, "name_servers", None)
        if ns:
            ns_list = [str(n).lower() for n in (ns if isinstance(ns, list) else [ns])]
            p("Name Servers", ", ".join(sorted(set(ns_list))[:4]))

        return {"registrar": registrar, "creation": creation}
    except Exception as e:
        p("WHOIS error", str(e)[:80], "red")
        return {}


def print_summary(domain, all_tech, security_headers):
    section("Technology Summary")

    categories = {
        "Frontend Frameworks": ["React","Vue.js","Angular","Next.js","Nuxt.js",
                                "Svelte","Ember.js","Backbone.js","Alpine.js",
                                "Gatsby","Remix","Astro","HTMX"],
        "CSS Frameworks":      ["Bootstrap","Tailwind CSS","Bulma","Foundation","Materialize"],
        "CMS / Platforms":     ["WordPress","Drupal","Joomla","Shopify","Wix",
                                "Squarespace","Ghost","Webflow","Contentful"],
        "Backend / Server":    ["PHP","Laravel","Django","Ruby on Rails","ASP.NET",
                                "Express.js","FastAPI","Spring","Flask","Node.js"],
        "Web Servers":         ["Nginx","Apache","Caddy","LiteSpeed","IIS"],
        "CDN / Hosting":       ["Cloudflare","AWS CloudFront","Fastly","Vercel",
                                "Netlify","AWS S3","Google Cloud","Azure"],
        "Analytics":           ["Google Analytics","Google Tag Manager","Hotjar",
                                "Mixpanel","HubSpot","Intercom","Segment"],
        "Payments":            ["Stripe","PayPal"],
        "Security Tools":      ["reCAPTCHA","hCaptcha","Cloudflare Turnstile"],
        "JavaScript":          ["jQuery"],
    }

    found_any = False
    for cat, techs in categories.items():
        hits = [t for t in techs if t in all_tech]
        if hits:
            found_any = True
            p(cat, " · ".join(hits), "green")

    if not found_any:
        p("Detection", "Nothing conclusive detected (site may use obfuscation)", "yellow")

    # Recommendations
    section("Quick Observations")
    if "WordPress" in all_tech:
        p("⚠", "WordPress detected — ensure plugins are up to date", "yellow")
    if "Cloudflare" in all_tech:
        p("✓", "Behind Cloudflare — real origin IP may be hidden", "cyan")
    if "Next.js" in all_tech and "Vercel" in all_tech:
        p("✓", "Classic Next.js + Vercel stack", "green")
    if not security_headers:
        p("⚠", "Few/no security headers — consider hardening", "red")
    if len(all_tech) == 0:
        p("ℹ", "Site may be heavily obfuscated or behind a WAF", "yellow")


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def analyze(domain_input: str):
    domain = normalize_domain(domain_input)

    if HAS_RICH:
        console.print(Panel.fit(
            f"[bold white]Domain Analyzer[/bold white]\n[cyan]Target: {domain}[/cyan]",
            border_style="bright_blue"
        ))
    else:
        print(f"\n{'='*60}\n  Domain Analyzer — {domain}\n{'='*60}")

    all_tech = []

    # 1. DNS
    analyze_dns(domain)

    # 2. SSL
    analyze_ssl(domain)

    # 3. WHOIS
    analyze_whois(domain)

    # 4. HTTP fetch + headers + HTML analysis
    url = f"https://{domain}"
    resp, html = fetch_page(url)

    header_tech, security_headers = [], {}
    html_tech, meta_tags = [], {}

    if resp is not None and html is not None:
        header_tech, security_headers = analyze_headers(resp, domain)
        html_tech, meta_tags = analyze_html(html, url)
        all_tech = list(set(header_tech + html_tech))
    else:
        p("Fetch Error", f"Could not reach {url}", "red")
        # Try HTTP fallback
        resp, html = fetch_page(f"http://{domain}")
        if resp and html:
            header_tech, security_headers = analyze_headers(resp, domain)
            html_tech, meta_tags = analyze_html(html, url)
            all_tech = list(set(header_tech + html_tech))

    # 5. Probe common paths
    analyze_extra_paths(domain)

    # 6. Summary
    print_summary(domain, all_tech, security_headers)

    if HAS_RICH:
        console.print(f"\n[dim]Analysis complete for [bold]{domain}[/bold][/dim]\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python domain_analyzer.py <domain>")
        print("Example: python domain_analyzer.py github.com")
        sys.exit(1)

    analyze(sys.argv[1])

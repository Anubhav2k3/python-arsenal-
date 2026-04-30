import re
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Common API key patterns (simplified)
PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Public Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Generic API Key": r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]"
}

visited = set()

def fetch(url):
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            return res.text
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
    return ""

def find_keys(content, url):
    findings = []
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches:
            findings.append((name, match))
    if findings:
        print(f"\n[+] संभावित keys found in {url}")
        for name, key in findings:
            print(f"  - {name}: {key}")

def crawl(url, base_domain):
    if url in visited:
        return
    visited.add(url)

    print(f"[+] Crawling: {url}")
    html = fetch(url)
    if not html:
        return

    find_keys(html, url)

    soup = BeautifulSoup(html, "html.parser")

    # Extract links (same domain only)
    for tag in soup.find_all("a", href=True):
        link = urljoin(url, tag["href"])
        if urlparse(link).netloc == base_domain:
            crawl(link, base_domain)

    # Extract JS files
    for script in soup.find_all("script", src=True):
        script_url = urljoin(url, script["src"])
        js_content = fetch(script_url)
        find_keys(js_content, script_url)

if __name__ == "__main__":
    start_url = input("Enter website URL (e.g., https://example.com): ").strip()
    domain = urlparse(start_url).netloc
    crawl(start_url, domain)

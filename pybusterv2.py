#!/usr/bin/env python3

# my dirbuster tool - updated version!
# fixed the threading issues and added rate limiting
# also added recursive mode which is pretty cool
# UPDATE: added better error handling and wildcard detection
# TODO: maybe add POST method support later?

import requests
import threading
import sys
import time
import queue
import argparse
import random
import json
import os
from datetime import datetime
from urllib.parse import urljoin, urlparse
from collections import defaultdict

# i found these online they seem popular
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/7.88.1",
]

# colors for terminal because it looks cool
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

# thread lock for safe printing - figured out this prevents race conditions!
print_lock = threading.Lock()

# store all the found stuff here
found_stuff = []
found_lock  = threading.Lock()

# keep track of how many requests we did
req_count   = 0
req_lock    = threading.Lock()

# for the rate limiter thing
rate_tokens      = 0
rate_lock        = threading.Lock()
rate_last_refill = time.time()


def safe_print(msg):
    with print_lock:
        print(msg)


def update_req_count():
    global req_count
    with req_lock:
        req_count += 1
        return req_count


def get_rate_token(max_rps):
    """token bucket algorithm for rate limiting - learned this from a tutorial!"""
    global rate_tokens, rate_last_refill
    if max_rps <= 0:
        return True
    with rate_lock:
        now = time.time()
        elapsed = now - rate_last_refill
        rate_last_refill = now
        rate_tokens = min(max_rps, rate_tokens + elapsed * max_rps)
        if rate_tokens >= 1:
            rate_tokens -= 1
            return True
    return False


def build_headers(custom_headers=None, randomize_ua=True):
    """make the headers for requests"""
    headers = {
        "Accept"          : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language" : "en-US,en;q=0.5",
        "Accept-Encoding" : "gzip, deflate",
        "Connection"      : "keep-alive",
    }
    if randomize_ua:
        headers["User-Agent"] = random.choice(USER_AGENTS)
    else:
        headers["User-Agent"] = USER_AGENTS[0]

    if custom_headers:
        headers.update(custom_headers)
    return headers


def check_url(session, url, method="GET", timeout=10, allow_redirect=True):
    """
    actually does the http request
    returns (status_code, content_length, redirect_url, response_time)
    """
    start = time.time()
    try:
        resp = session.request(
            method,
            url,
            headers=build_headers(),
            timeout=timeout,
            allow_redirects=allow_redirect,
            stream=True,   # dont download whole body unless we need it
        )
        elapsed = time.time() - start

        # get content length without downloading everything
        content_len = int(resp.headers.get("Content-Length", 0))
        if content_len == 0 and resp.status_code == 200:
            # read a bit to get actual size
            chunk = resp.raw.read(4096, decode_content=True)
            content_len = len(chunk)

        redirect_to = ""
        if resp.history:
            redirect_to = resp.url

        resp.close()
        return resp.status_code, content_len, redirect_to, round(elapsed, 3)

    except requests.exceptions.SSLError:
        return -1, 0, "", 0
    except requests.exceptions.ConnectionError:
        return -2, 0, "", 0
    except requests.exceptions.Timeout:
        return -3, 0, "", 0
    except Exception:
        return -99, 0, "", 0


def detect_wildcard(session, base_url, timeout=10):
    """
    detects if server returns same response for non-existent paths
    this prevents false positives - learned this is super important!
    """
    fake_paths = [
        f"thisdoesnotexist_{random.randint(10000,99999)}",
        f"zzzznotreal_{random.randint(10000,99999)}.php",
        f"totally_fake_dir_{random.randint(10000,99999)}/",
    ]
    statuses = []
    for fp in fake_paths:
        url = urljoin(base_url.rstrip("/") + "/", fp)
        code, _, _, _ = check_url(session, url, timeout=timeout)
        statuses.append(code)

    # if all random urls return 200 or same code then its probably wildcard
    if all(s == 200 for s in statuses):
        return True, 200
    if len(set(statuses)) == 1 and statuses[0] not in (-1, -2, -3, -99):
        return True, statuses[0]
    return False, None


def load_wordlist(path):
    """load wordlist from file, skip comments and blank lines"""
    words = []
    if not os.path.isfile(path):
        print(f"{RED}[!] Wordlist not found: {path}{RESET}")
        sys.exit(1)
    with open(path, "r", errors="ignore") as f:
        for line in f:
            word = line.strip()
            if word and not word.startswith("#"):
                words.append(word)
    return words


def make_builtin_wordlist():
    """
    built-in wordlist for when user doesn't provide one
    curated from common web paths and security testing guides
    """
    return [
        "admin", "administrator", "login", "wp-admin", "wp-login.php",
        "phpmyadmin", "dashboard", "panel", "cpanel", "webmail",
        "mail", "email", "api", "api/v1", "api/v2", "api/v3",
        "backup", "backups", "db", "database", "sql", "dump",
        "config", "configuration", "settings", "setup", "install",
        "test", "tests", "dev", "development", "staging", "prod",
        "static", "assets", "uploads", "upload", "files", "file",
        "images", "img", "css", "js", "javascript", "fonts",
        "include", "includes", "lib", "libs", "vendor", "src",
        "robots.txt", "sitemap.xml", ".htaccess", ".env", ".git",
        ".git/config", ".git/HEAD", ".svn", ".DS_Store",
        "wp-content", "wp-includes", "xmlrpc.php", "readme.html",
        "license.txt", "changelog.txt", "info.php", "phpinfo.php",
        "server-status", "server-info", ".well-known",
        "swagger", "swagger-ui", "swagger.json", "openapi.json",
        "docs", "doc", "documentation", "help", "support",
        "user", "users", "account", "accounts", "profile",
        "register", "signup", "signin", "logout", "auth",
        "token", "oauth", "oauth2", "callback",
        "health", "healthcheck", "status", "ping", "version",
        "metrics", "monitoring", "grafana", "kibana", "elastic",
        "jenkins", "gitlab", "jira", "confluence",
        "cgi-bin", "scripts", "bin", "temp", "tmp", "log", "logs",
        "error", "errors", "debug", "trace",
        "old", "bak", "back", "new", "archive", "zip",
        "portal", "intranet", "internal", "private", "secret",
        "hidden", "manage", "management", "console",
        "shell", "cmd", "exec", "execute",
    ]


def worker_thread(thread_id, url_queue, session, results_queue,
                  ignore_codes, only_codes, timeout, max_rps,
                  wildcard_code, verbose):
    """
    this is the main worker thread
    it pulls urls from queue, checks them, puts results in result queue
    """
    while True:
        try:
            url = url_queue.get(timeout=2)
        except queue.Empty:
            break

        # rate limiting
        while not get_rate_token(max_rps):
            time.sleep(0.05)

        code, length, redirect, elapsed = check_url(session, url, timeout=timeout)

        update_req_count()

        # skip if wildcard match
        if wildcard_code and code == wildcard_code:
            url_queue.task_done()
            continue

        # skip ignored codes
        if code in ignore_codes:
            url_queue.task_done()
            continue

        # filter by only codes if specified
        if only_codes and code not in only_codes:
            url_queue.task_done()
            continue

        # only show actual responses (not our error codes like -1, -2)
        if code > 0:
            color = GREEN if code in (200, 201) else \
                    YELLOW if code in (301, 302, 307, 308) else \
                    CYAN   if code in (401, 403) else \
                    DIM
            msg = f"{color}[{code}]{RESET} {url}"
            if length:
                msg += f"  {DIM}({length} bytes){RESET}"
            if redirect:
                msg += f"  {YELLOW}-> {redirect}{RESET}"
            msg += f"  {DIM}[{elapsed}s]{RESET}"
            safe_print(msg)

            with found_lock:
                found_stuff.append({
                    "url"      : url,
                    "status"   : code,
                    "length"   : length,
                    "redirect" : redirect,
                    "time"     : elapsed,
                })

        elif verbose and code == -3:
            safe_print(f"{DIM}[TIMEOUT] {url}{RESET}")

        url_queue.task_done()


def recursive_scan(session, found_dirs, scanned_dirs, wordlist, extensions,
                   ignore_codes, only_codes, timeout, max_rps,
                   wildcard_code, verbose, threads, depth, max_depth):
    """go deeper into found directories recursively"""
    if depth >= max_depth:
        return

    new_dirs = []
    for item in found_dirs:
        url   = item["url"]
        code  = item["status"]
        # only recurse into directory-like things
        if code in (200, 301, 302, 307, 308) and url not in scanned_dirs:
            if url.endswith("/") or not "." in url.split("/")[-1]:
                new_dirs.append(url.rstrip("/") + "/")
                scanned_dirs.add(url)

    if not new_dirs:
        return

    safe_print(f"\n{BLUE}[*] Recursing into {len(new_dirs)} director(ies) at depth {depth+1}/{max_depth}...{RESET}")
    safe_print(f"{DIM}    (this might take a while depending on findings){RESET}\n")

    for base in new_dirs:
        urls        = generate_urls(base, wordlist, extensions)
        url_queue   = queue.Queue()
        results_q   = queue.Queue()
        before_count = len(found_stuff)

        for u in urls:
            url_queue.put(u)

        worker_list = []
        for i in range(threads):
            t = threading.Thread(
                target=worker_thread,
                args=(i, url_queue, session, results_q,
                      ignore_codes, only_codes, timeout, max_rps,
                      wildcard_code, verbose),
                daemon=True,
            )
            t.start()
            worker_list.append(t)

        url_queue.join()
        for t in worker_list:
            t.join(timeout=1)

        # recurse new finds
        new_finds = found_stuff[before_count:]
        if new_finds and depth + 1 < max_depth:
            recursive_scan(session, new_finds, scanned_dirs, wordlist, extensions,
                           ignore_codes, only_codes, timeout, max_rps,
                           wildcard_code, verbose, threads, depth + 1, max_depth)


def generate_urls(base_url, wordlist, extensions):
    """make all the urls we want to check"""
    base = base_url.rstrip("/")
    urls = []
    for word in wordlist:
        word = word.strip("/")
        # base word
        urls.append(f"{base}/{word}")
        # with trailing slash (for directories)
        if not "." in word:
            urls.append(f"{base}/{word}/")
        # with extensions
        for ext in extensions:
            if ext and not word.endswith(ext):
                urls.append(f"{base}/{word}{ext}")
    return urls


def print_banner():
    banner = f"""
{CYAN}{BOLD}
  ██████╗ ██╗██████╗ ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ 
  ██╔══██╗██║██╔══██╗██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ██║  ██║██║██████╔╝██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
  ██║  ██║██║██╔══██╗██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝██║██║  ██║██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RESET}{DIM}  web directory scanner v2.1 - now with better features!{RESET}
  {GREEN}[Updated: Feb 2026]{RESET} {DIM}- fixed bugs & improved performance{RESET}
"""
    print(banner)


def save_results(output_file, target_url, args):
    """save all the found stuff to a file"""
    data = {
        "scan_info": {
            "target"     : target_url,
            "date"       : datetime.now().isoformat(),
            "total_reqs" : req_count,
            "found"      : len(found_stuff),
            "threads"    : args.threads,
            "wordlist"   : getattr(args, "wordlist", "builtin"),
        },
        "results": sorted(found_stuff, key=lambda x: x["status"]),
    }

    ext = os.path.splitext(output_file)[1].lower()
    with open(output_file, "w") as f:
        if ext == ".json":
            json.dump(data, f, indent=2)
        else:
            # plain text
            f.write(f"# DirBuster Results - {target_url}\n")
            f.write(f"# Date: {data['scan_info']['date']}\n")
            f.write(f"# Total Requests: {req_count} | Found: {len(found_stuff)}\n\n")
            for r in data["results"]:
                line = f"[{r['status']}] {r['url']}"
                if r["length"]:
                    line += f"  ({r['length']} bytes)"
                if r["redirect"]:
                    line += f"  -> {r['redirect']}"
                f.write(line + "\n")

    safe_print(f"\n{GREEN}[✓] Results saved to: {output_file}{RESET}")
    safe_print(f"{DIM}    ({len(found_stuff)} endpoints exported){RESET}")


def progress_reporter(total_urls, stop_event):
    """background thread that displays scan progress in real-time"""
    while not stop_event.is_set():
        time.sleep(3)
        with req_lock:
            done = req_count
        pct = (done / total_urls * 100) if total_urls > 0 else 0
        with print_lock:
            # overwrite same line with updated stats
            print(f"\r{DIM}[~] Scanning: {done}/{total_urls} ({pct:.1f}%) | Endpoints found: {len(found_stuff)}{RESET}  ", end="", flush=True)


def main():
    parser = argparse.ArgumentParser(
        description="dirbuster - my web directory scanner project",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("url",              help="target url like http://example.com")
    parser.add_argument("-w", "--wordlist", help="wordlist file (uses builtin if not given)", default=None)
    parser.add_argument("-t", "--threads",  help="number of threads (default 10)", type=int, default=10)
    parser.add_argument("-x", "--extensions", help="extensions to try e.g. .php,.html,.txt", default="")
    parser.add_argument("-o", "--output",   help="save results to file (.txt or .json)", default=None)
    parser.add_argument("--timeout",        help="request timeout seconds (default 10)", type=int, default=10)
    parser.add_argument("--ignore",         help="status codes to ignore e.g. 404,503", default="404")
    parser.add_argument("--only",           help="only show these status codes e.g. 200,301", default="")
    parser.add_argument("--rps",            help="max requests per second (0=unlimited)", type=int, default=0)
    parser.add_argument("--proxy",          help="use a proxy e.g. http://127.0.0.1:8080", default=None)
    parser.add_argument("--cookie",         help="cookies to send e.g. session=abc123", default=None)
    parser.add_argument("--header",         help="extra header e.g. 'Authorization: Bearer TOKEN'", action="append", default=[])
    parser.add_argument("--no-tls-verify",  help="skip ssl certificate check", action="store_true")
    parser.add_argument("--recursive",      help="scan found directories recursively", action="store_true")
    parser.add_argument("--depth",          help="max recursion depth (default 2)", type=int, default=2)
    parser.add_argument("--method",         help="http method GET or HEAD (default GET)", default="GET")
    parser.add_argument("--no-wildcard",    help="skip wildcard detection", action="store_true")
    parser.add_argument("-v", "--verbose",  help="show timeouts and more info", action="store_true")
    args = parser.parse_args()

    print_banner()

    # fix url
    target = args.url.strip()
    if not target.startswith("http"):
        target = "http://" + target
    if not target.endswith("/"):
        target += "/"

    # parse ignore codes
    ignore_codes = set()
    for c in args.ignore.split(","):
        c = c.strip()
        if c.isdigit():
            ignore_codes.add(int(c))

    # parse only codes
    only_codes = set()
    for c in args.only.split(","):
        c = c.strip()
        if c.isdigit():
            only_codes.add(int(c))

    # parse extensions
    extensions = [""]
    for e in args.extensions.split(","):
        e = e.strip()
        if e:
            if not e.startswith("."):
                e = "." + e
            extensions.append(e)

    # parse custom headers
    custom_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()
    if args.cookie:
        custom_headers["Cookie"] = args.cookie

    # load wordlist
    if args.wordlist:
        safe_print(f"{BLUE}[*] Loading wordlist: {args.wordlist}{RESET}")
        wordlist = load_wordlist(args.wordlist)
        safe_print(f"{GREEN}[✓] Loaded {len(wordlist)} words{RESET}")
    else:
        safe_print(f"{YELLOW}[*] No wordlist specified - using built-in list{RESET}")
        wordlist = make_builtin_wordlist()
        safe_print(f"{DIM}    ({len(wordlist)} common paths - use -w for custom wordlist){RESET}")

    safe_print(f"{BLUE}[*] Target: {target}{RESET}")
    safe_print(f"{BLUE}[*] Words: {len(wordlist)} | Extensions: {extensions} | Threads: {args.threads}{RESET}")
    if args.timeout != 10:
        safe_print(f"{BLUE}[*] Request timeout: {args.timeout}s{RESET}")
    if args.rps > 0:
        safe_print(f"{BLUE}[*] Rate limit: {args.rps} req/sec (prevents server overload){RESET}")

    # setup session
    safe_print(f"{BLUE}[*] Initializing HTTP session...{RESET}")
    session = requests.Session()
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
        safe_print(f"{YELLOW}[*] Using proxy: {args.proxy}{RESET}")
    if args.no_tls_verify:
        session.verify = False
        import urllib3
        urllib3.disable_warnings()
        safe_print(f"{YELLOW}[*] TLS verification disabled{RESET}")

    # wildcard detection
    wildcard_code = None
    if not args.no_wildcard:
        safe_print(f"{BLUE}[*] Running wildcard detection (checks for false positives)...{RESET}")
        is_wildcard, wc_code = detect_wildcard(session, target, timeout=args.timeout)
        if is_wildcard:
            safe_print(f"{YELLOW}[!] Wildcard response detected! (Status: {wc_code}){RESET}")
            safe_print(f"{YELLOW}[!] Auto-filtering {wc_code} responses to reduce noise{RESET}")
            wildcard_code = wc_code
        else:
            safe_print(f"{GREEN}[✓] No wildcard detected - results should be accurate!{RESET}")

    safe_print(f"\n{BOLD}{'='*60}{RESET}\n")

    # generate urls and fill queue
    all_urls  = generate_urls(target, wordlist, extensions)
    url_queue = queue.Queue()
    for u in all_urls:
        url_queue.put(u)

    total_urls = len(all_urls)
    safe_print(f"{BLUE}[*] Total URLs to check: {total_urls}{RESET}")
    safe_print(f"{GREEN}[*] Starting scan... (press Ctrl+C to stop){RESET}\n")

    start_time = time.time()

    # start progress reporter
    stop_progress = threading.Event()
    prog_thread   = threading.Thread(
        target=progress_reporter,
        args=(total_urls, stop_progress),
        daemon=True,
    )
    prog_thread.start()

    # start worker threads
    results_q   = queue.Queue()
    worker_list = []
    for i in range(args.threads):
        t = threading.Thread(
            target=worker_thread,
            args=(i, url_queue, session, results_q,
                  ignore_codes, only_codes, args.timeout, args.rps,
                  wildcard_code, args.verbose),
            daemon=True,
        )
        t.start()
        worker_list.append(t)

    # wait for everything
    url_queue.join()
    for t in worker_list:
        t.join(timeout=1)

    stop_progress.set()
    print()  # newline after progress line

    # recursive mode
    if args.recursive and found_stuff:
        scanned = {target}
        recursive_scan(session, list(found_stuff), scanned, wordlist, extensions,
                       ignore_codes, only_codes, args.timeout, args.rps,
                       wildcard_code, args.verbose, args.threads, 0, args.depth)

    # summary
    elapsed_total = time.time() - start_time
    safe_print(f"\n{BOLD}{'='*60}{RESET}")
    safe_print(f"{GREEN}{BOLD}[✓] Scan Complete!{RESET}")
    safe_print(f"    Total requests : {req_count}")
    safe_print(f"    Endpoints found: {len(found_stuff)}")
    safe_print(f"    Elapsed time   : {elapsed_total:.2f}s")
    safe_print(f"    Average speed  : {req_count / max(elapsed_total, 1):.1f} req/sec")
    safe_print(f"{BOLD}{'='*60}{RESET}")

    if found_stuff:
        safe_print(f"\n{BOLD}📊 Results breakdown by status code:{RESET}")
        by_status = defaultdict(list)
        for r in found_stuff:
            by_status[r["status"]].append(r["url"])
        for code in sorted(by_status.keys()):
            color = GREEN if code in (200, 201) else YELLOW if str(code).startswith("3") else CYAN
            safe_print(f"  {color}[{code}]{RESET} {len(by_status[code])} endpoint(s) found")
    else:
        safe_print(f"\n{YELLOW}[!] No accessible endpoints found with current wordlist{RESET}")
        safe_print(f"{DIM}    Try a larger wordlist or different extensions{RESET}")

    if args.output:
        save_results(args.output, target, args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}[!] Scan interrupted by user (Ctrl+C){RESET}")
        if found_stuff:
            print(f"{GREEN}[✓] Found {len(found_stuff)} endpoint(s) before stopping{RESET}")
            print(f"{DIM}    Use -o option to save partial results next time{RESET}")
        sys.exit(0)

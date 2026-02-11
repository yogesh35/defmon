"""Attack log simulator — generates realistic Apache/Nginx access logs
with a mix of normal traffic and various attack patterns.

Usage:
    python -m simulator.generate_logs [--rate fast|medium|slow] [--duration SECONDS]
"""
import argparse
import os
import random
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.core.config import LOG_FILE, AUTH_LOG_FILE, APP_LOG_FILE, LOG_DIR

# Ensure log dir
os.makedirs(LOG_DIR, exist_ok=True)

# ── Data pools ────────────────────────────────────────────────────────────────
NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 60)]
ATTACKER_IPS = [
    "45.33.32.156", "185.220.101.42", "198.51.100.1", "203.0.113.66",
    "103.224.182.250", "77.247.181.162", "62.210.105.116", "178.62.60.166",
    "89.248.172.16", "23.129.64.100",
]

NORMAL_URLS = [
    "/", "/index.html", "/about", "/contact", "/products", "/api/v1/users",
    "/api/v1/items", "/blog", "/login", "/register", "/dashboard",
    "/static/css/style.css", "/static/js/app.js", "/images/logo.png",
    "/api/v1/health", "/api/v1/search?q=shoes",
]

SQLI_PAYLOADS = [
    "/search?q=' OR 1=1 --",
    "/api/v1/users?id=1 UNION SELECT username,password FROM users--",
    "/login?user=admin'--&pass=x",
    "/products?category=1; DROP TABLE users;--",
    "/api/v1/items?sort=name;SELECT * FROM information_schema.tables",
    "/search?q=' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "/api/v1/users?id=1' OR '1'='1",
    "/products?id=1 UNION SELECT concat(username,0x3a,password) FROM users",
]

XSS_PAYLOADS = [
    "/search?q=<script>alert('XSS')</script>",
    "/comment?body=<img src=x onerror=alert(1)>",
    "/profile?name=<iframe src='javascript:alert(1)'>",
    "/api/v1/feedback?msg=<script>document.cookie</script>",
    "/search?q=\"><script>alert(String.fromCharCode(88,83,83))</script>",
    "/blog?title=<svg onload=alert('xss')>",
]

TRAVERSAL_PAYLOADS = [
    "/static/../../etc/passwd",
    "/download?file=../../../etc/shadow",
    "/api/v1/files?path=....//....//etc/passwd",
    "/images/%2e%2e/%2e%2e/etc/hosts",
    "/download?file=/proc/self/environ",
    "/static/..\\..\\windows\\system32\\config\\sam",
]

SCAN_URLS = [
    "/admin", "/wp-admin", "/wp-login.php", "/.env", "/.git/config",
    "/phpmyadmin", "/server-status", "/actuator", "/console",
    "/api/swagger.json", "/debug", "/trace", "/.htaccess",
    "/backup.zip", "/db.sql", "/config.yml", "/robots.txt",
    "/sitemap.xml", "/.well-known/security.txt", "/xmlrpc.php",
    "/wp-content/uploads/", "/cgi-bin/", "/shell.php",
]

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/17.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

ATTACK_UAS = [
    "sqlmap/1.7.12#stable",
    "nikto/2.1.6",
    "Nmap Scripting Engine",
    "dirbuster/1.0",
    "gobuster/3.6",
    "python-requests/2.31.0",
    "curl/8.4.0",
    "Scrapy/2.11.0",
    "masscan/1.3.2",
    "WPScan v3.8.25",
]

METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]


def _ts():
    return datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def _log_line(ip, method, url, status, ua):
    size = random.randint(200, 50000)
    return f'{ip} - - [{_ts()}] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}"'


def generate_normal_traffic(f):
    """Write a normal-looking access log line."""
    ip = random.choice(NORMAL_IPS)
    url = random.choice(NORMAL_URLS)
    status = random.choices([200, 301, 304, 404, 500], weights=[70, 5, 10, 10, 5])[0]
    ua = random.choice(NORMAL_UAS)
    method = random.choices(["GET", "POST", "PUT"], weights=[80, 15, 5])[0]
    f.write(_log_line(ip, method, url, status, ua) + "\n")
    f.flush()


def generate_sqli_attack(f):
    ip = random.choice(ATTACKER_IPS)
    url = random.choice(SQLI_PAYLOADS)
    status = random.choice([200, 500, 403])
    ua = random.choice(ATTACK_UAS + NORMAL_UAS[:1])
    f.write(_log_line(ip, "GET", url, status, ua) + "\n")
    f.flush()


def generate_xss_attack(f):
    ip = random.choice(ATTACKER_IPS)
    url = random.choice(XSS_PAYLOADS)
    status = random.choice([200, 400, 403])
    ua = random.choice(NORMAL_UAS)
    f.write(_log_line(ip, "GET", url, status, ua) + "\n")
    f.flush()


def generate_traversal_attack(f):
    ip = random.choice(ATTACKER_IPS)
    url = random.choice(TRAVERSAL_PAYLOADS)
    status = random.choice([200, 403, 404])
    ua = random.choice(ATTACK_UAS[:3] + NORMAL_UAS[:1])
    f.write(_log_line(ip, "GET", url, status, ua) + "\n")
    f.flush()


def generate_brute_force(f, auth_f):
    """Generate a burst of failed login attempts."""
    ip = random.choice(ATTACKER_IPS)
    ua = random.choice(ATTACK_UAS[-3:])
    for _ in range(random.randint(5, 15)):
        f.write(_log_line(ip, "POST", "/login", 401, ua) + "\n")
    f.flush()
    # Also write auth log
    ts = datetime.now().strftime("%b %d %H:%M:%S")
    for user in ["admin", "root", "user", "test", "oracle"]:
        auth_f.write(f"{ts} server sshd[{random.randint(1000,9999)}]: "
                     f"Failed password for {user} from {ip} port 22 ssh2\n")
    auth_f.flush()


def generate_404_scan(f):
    """Generate a burst of 404s from a scanner."""
    ip = random.choice(ATTACKER_IPS)
    ua = random.choice(ATTACK_UAS)
    for _ in range(random.randint(20, 40)):
        url = random.choice(SCAN_URLS)
        f.write(_log_line(ip, "GET", url, 404, ua) + "\n")
    f.flush()


def generate_high_rate(f):
    """Generate a flood of requests from a single IP."""
    ip = random.choice(ATTACKER_IPS)
    ua = random.choice(ATTACK_UAS[-2:])
    for _ in range(random.randint(100, 200)):
        url = random.choice(NORMAL_URLS)
        f.write(_log_line(ip, "GET", url, 200, ua) + "\n")
    f.flush()


def generate_suspicious_ua(f):
    ip = random.choice(ATTACKER_IPS)
    url = random.choice(NORMAL_URLS + SCAN_URLS[:5])
    status = random.choice([200, 403, 404])
    ua = random.choice(ATTACK_UAS)
    f.write(_log_line(ip, "GET", url, status, ua) + "\n")
    f.flush()


def main():
    parser = argparse.ArgumentParser(description="Generate simulated web server logs")
    parser.add_argument("--rate", choices=["fast", "medium", "slow"], default="medium",
                        help="Log generation speed")
    parser.add_argument("--duration", type=int, default=0,
                        help="Run for N seconds (0 = infinite)")
    args = parser.parse_args()

    delays = {"fast": 0.1, "medium": 0.5, "slow": 2.0}
    delay = delays[args.rate]

    print(f"📝 Writing logs to {LOG_FILE}")
    print(f"   Auth logs to {AUTH_LOG_FILE}")
    print(f"   Rate: {args.rate} ({delay}s between events)")
    print(f"   Press Ctrl+C to stop\n")

    start = time.time()

    with open(LOG_FILE, "a") as f, open(AUTH_LOG_FILE, "a") as af, open(APP_LOG_FILE, "a") as appf:
        cycle = 0
        try:
            while True:
                if args.duration and (time.time() - start) > args.duration:
                    break

                # Weighted selection: mostly normal, sometimes attacks
                roll = random.random()
                if roll < 0.50:
                    generate_normal_traffic(f)
                    label = "normal"
                elif roll < 0.58:
                    generate_sqli_attack(f)
                    label = "🔴 SQLi"
                elif roll < 0.66:
                    generate_xss_attack(f)
                    label = "🟠 XSS"
                elif roll < 0.72:
                    generate_traversal_attack(f)
                    label = "🟠 Traversal"
                elif roll < 0.78:
                    generate_brute_force(f, af)
                    label = "🟡 Brute Force"
                elif roll < 0.84:
                    generate_404_scan(f)
                    label = "🟡 404 Scan"
                elif roll < 0.90:
                    generate_high_rate(f)
                    label = "🟡 DDoS Flood"
                else:
                    generate_suspicious_ua(f)
                    label = "🔵 Suspicious UA"

                cycle += 1
                if cycle % 5 == 0:
                    elapsed = int(time.time() - start)
                    print(f"  [{elapsed:>5}s] Generated {cycle} events | last: {label}")

                time.sleep(delay + random.uniform(0, delay * 0.5))

        except KeyboardInterrupt:
            print(f"\n✅ Stopped after {cycle} events")


if __name__ == "__main__":
    main()

"""Global configuration for the SIEM+SOAR platform."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR = DATA_DIR / "logs"
DB_DIR = DATA_DIR / "db"

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
DB_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{DB_DIR}/siem.db")
LOG_FILE = os.getenv("LOG_FILE", str(LOG_DIR / "access.log"))
AUTH_LOG_FILE = os.getenv("AUTH_LOG_FILE", str(LOG_DIR / "auth.log"))
APP_LOG_FILE = os.getenv("APP_LOG_FILE", str(LOG_DIR / "app.log"))

# Detection thresholds
BRUTE_FORCE_THRESHOLD = 5        # failed logins in window
BRUTE_FORCE_WINDOW = 60          # seconds
SCAN_404_THRESHOLD = 20          # 404s in window
SCAN_404_WINDOW = 60             # seconds
HIGH_RATE_THRESHOLD = 100        # requests in window
HIGH_RATE_WINDOW = 60            # seconds

# Blacklisted IPs (seed list — augmented at runtime)
SEED_BLACKLIST = {
    "198.51.100.1",
    "203.0.113.66",
    "192.0.2.99",
    "10.255.255.1",
}

# Suspicious user-agent substrings
SUSPICIOUS_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster",
    "wpscan", "hydra", "burpsuite", "metasploit", "zgrab", "curl/",
    "python-requests", "scrapy",
]

# MITRE ATT&CK mappings
MITRE_MAP = {
    "sql_injection":       {"tactic": "Initial Access",    "technique": "T1190", "name": "Exploit Public-Facing Application"},
    "xss_attempt":         {"tactic": "Initial Access",    "technique": "T1189", "name": "Drive-by Compromise"},
    "directory_traversal": {"tactic": "Discovery",         "technique": "T1083", "name": "File and Directory Discovery"},
    "brute_force":         {"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"},
    "scan_404":            {"tactic": "Reconnaissance",    "technique": "T1595", "name": "Active Scanning"},
    "high_request_rate":   {"tactic": "Impact",            "technique": "T1498", "name": "Network Denial of Service"},
    "suspicious_ua":       {"tactic": "Command and Control","technique": "T1071","name": "Application Layer Protocol"},
    "blacklisted_ip":      {"tactic": "Initial Access",    "technique": "T1190", "name": "Exploit Public-Facing Application"},
}

SEVERITY_SCORES = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 1,
}

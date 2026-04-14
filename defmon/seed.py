"""DefMon seed module — generates 500 synthetic attack log events for demo and testing."""

import random
import asyncio
from datetime import datetime, timedelta

from loguru import logger
from sqlalchemy import text

from defmon.database import get_engine, get_session_factory
from defmon.models import Base, User, UserRole
from defmon.api.auth import get_password_hash


# Sample data pools for generating realistic log lines
ATTACK_IPS = [
    "185.220.101.1", "23.129.64.100", "45.155.205.233", "194.165.16.77",
    "171.25.193.20", "109.70.100.1", "51.75.52.118", "89.248.167.131",
    "92.118.160.1", "185.56.83.100", "116.105.212.50", "103.251.167.10",
    "45.95.169.88", "162.247.74.204", "198.98.51.189",
]

NORMAL_IPS = [
    "192.168.1.10", "192.168.1.20", "10.0.0.5", "10.0.0.15",
    "172.16.0.100", "172.16.0.200",
]

SQLI_URIS = [
    "/search?q=1'+OR+1=1--",
    "/login?user=admin'--",
    "/api/data?id=1+UNION+SELECT+*+FROM+users--",
    "/products?cat=1;+DROP+TABLE+users--",
    "/search?q='+OR+'1'='1",
    "/api/users?id=1'+UNION+SELECT+password+FROM+users--",
]

XSS_URIS = [
    "/comment?text=<script>alert('xss')</script>",
    "/search?q=<img+src=x+onerror=alert(1)>",
    "/profile?name=<script>document.cookie</script>",
    "/feedback?msg=javascript:alert('XSS')",
]

TRAVERSAL_URIS = [
    "/static/../../../../etc/passwd",
    "/images/../../../etc/shadow",
    "/download?file=../../../etc/hosts",
    "/static/%2e%2e%2f%2e%2e%2fetc/passwd",
]

NORMAL_URIS = [
    "/index.html", "/about", "/contact", "/api/status",
    "/css/style.css", "/js/app.js", "/images/logo.png",
    "/api/products", "/api/users/me", "/dashboard",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "Nikto/2.1.6",
    "sqlmap/1.7",
]


def _generate_log_line(
    ip: str,
    uri: str,
    status: int,
    timestamp: datetime,
    method: str = "GET",
) -> str:
    """Generate a single Apache Combined Log Format line."""
    ts_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
    bytes_sent = random.randint(0, 50000)
    ua = random.choice(USER_AGENTS)
    return (
        f'{ip} - - [{ts_str}] "{method} {uri} HTTP/1.1" '
        f'{status} {bytes_sent} "-" "{ua}"'
    )


def generate_synthetic_events(count: int = 500) -> list[str]:
    """Generate a mix of attack and normal log lines."""
    events: list[str] = []
    base_time = datetime.utcnow() - timedelta(hours=24)

    for i in range(count):
        timestamp = base_time + timedelta(seconds=i * 60)
        roll = random.random()

        if roll < 0.15:
            # SQL Injection (15%)
            ip = random.choice(ATTACK_IPS)
            uri = random.choice(SQLI_URIS)
            status = random.choice([200, 403, 500])
            events.append(_generate_log_line(ip, uri, status, timestamp))

        elif roll < 0.25:
            # XSS (10%)
            ip = random.choice(ATTACK_IPS)
            uri = random.choice(XSS_URIS)
            status = random.choice([200, 403])
            events.append(_generate_log_line(ip, uri, status, timestamp))

        elif roll < 0.32:
            # Directory Traversal (7%)
            ip = random.choice(ATTACK_IPS)
            uri = random.choice(TRAVERSAL_URIS)
            status = 403
            events.append(_generate_log_line(ip, uri, status, timestamp))

        elif roll < 0.42:
            # Brute-force login attempts (10%)
            ip = random.choice(ATTACK_IPS[:5])
            uri = "/api/login"
            status = 401
            events.append(_generate_log_line(ip, uri, status, timestamp, method="POST"))

        elif roll < 0.52:
            # Path scanning / 404 flood (10%)
            ip = random.choice(ATTACK_IPS[5:10])
            uri = f"/admin/{random.choice(['config', 'backup', '.env', 'wp-login.php', 'phpmyadmin'])}"
            status = 404
            events.append(_generate_log_line(ip, uri, status, timestamp))

        else:
            # Normal traffic (48%)
            ip = random.choice(NORMAL_IPS)
            uri = random.choice(NORMAL_URIS)
            status = 200
            events.append(_generate_log_line(ip, uri, status, timestamp))

    random.shuffle(events)
    return events


async def seed_database() -> None:
    """Write seed log lines to the data/ directory for ingestion."""
    events = generate_synthetic_events(500)
    seed_path = "data/seed_access.log"

    with open(seed_path, "w") as f:
        for line in events:
            f.write(line + "\n")

    logger.info(f"✅ Wrote {len(events)} synthetic log events to {seed_path}")


async def seed_user() -> None:
    """Create a default admin user if one doesn't exist."""
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession
    
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(User).where(User.username == "admin"))
        admin_user = result.scalar_one_or_none()
        
        if not admin_user:
            pw_hash = get_password_hash("admin")
            new_admin = User(
                username="admin",
                hashed_password=pw_hash,
                role=UserRole.ADMIN,
                is_active=True,
                is_locked=False
            )
            session.add(new_admin)
            await session.commit()
            logger.info("✅ Seeded default admin user (admin / admin)")
        else:
            logger.info("ℹ️ Admin user already exists")


async def main() -> None:
    """Run all seed operations."""
    await seed_database()
    await seed_user()


if __name__ == "__main__":
    asyncio.run(main())

"""Shared pytest fixtures for DefMon test suite."""

import os
import pytest
from unittest.mock import patch

# Override database URL to SQLite for testing BEFORE importing app modules
os.environ["DB_USER"] = "test"
os.environ["DB_PASS"] = "test"
os.environ["DB_HOST"] = "localhost"
os.environ["DB_PORT"] = "5432"
os.environ["DB_NAME"] = "defmon_test"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-testing-only-64-chars-long-padding-here!!"
os.environ["DEBUG"] = "true"


@pytest.fixture
def sample_apache_log() -> str:
    """Sample Apache Combined Log Format line."""
    return (
        '192.168.1.100 - frank [10/Oct/2024:13:55:36 +0000] '
        '"GET /index.html HTTP/1.1" 200 2326 '
        '"http://www.example.com/start.html" '
        '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    )


@pytest.fixture
def sample_nginx_log() -> str:
    """Sample Nginx access log line."""
    return (
        '10.0.0.1 - admin [10/Oct/2024:14:00:00 +0000] '
        '"POST /api/login HTTP/1.1" 401 128 '
        '"-" '
        '"curl/7.68.0"'
    )


@pytest.fixture
def sample_sqli_log() -> str:
    """Log line with SQL injection attempt in URI."""
    return (
        "192.168.1.200 - - [10/Oct/2024:15:00:00 +0000] "
        "\"GET /search?q=1'+OR+1=1-- HTTP/1.1\" 200 5123 "
        '"-" "Mozilla/5.0"'
    )


@pytest.fixture
def sample_xss_log() -> str:
    """Log line with XSS attempt in URI."""
    return (
        "10.10.10.10 - - [10/Oct/2024:15:05:00 +0000] "
        '"GET /comment?text=<script>alert(1)</script> HTTP/1.1" 200 1024 '
        '"-" "Mozilla/5.0"'
    )


@pytest.fixture
def sample_traversal_log() -> str:
    """Log line with directory traversal attempt."""
    return (
        "172.16.0.50 - - [10/Oct/2024:15:10:00 +0000] "
        '"GET /static/../../../../etc/passwd HTTP/1.1" 403 0 '
        '"-" "Mozilla/5.0"'
    )

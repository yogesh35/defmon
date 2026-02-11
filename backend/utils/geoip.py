"""Lightweight GeoIP approximation using IP ranges.

In production you would use MaxMind GeoLite2.  Here we deterministically map
IPs to fake-but-consistent locations so the dashboard geo-map is functional.
"""
import hashlib

_LOCATIONS = [
    ("US", "New York",     40.71,  -74.01),
    ("US", "Los Angeles",  34.05, -118.24),
    ("US", "Chicago",      41.88,  -87.63),
    ("RU", "Moscow",       55.76,   37.62),
    ("CN", "Beijing",      39.90,  116.40),
    ("CN", "Shanghai",     31.23,  121.47),
    ("DE", "Berlin",       52.52,   13.41),
    ("GB", "London",       51.51,   -0.13),
    ("BR", "Sao Paulo",   -23.55,  -46.63),
    ("IN", "Mumbai",       19.08,   72.88),
    ("JP", "Tokyo",        35.68,  139.69),
    ("AU", "Sydney",      -33.87,  151.21),
    ("FR", "Paris",        48.86,    2.35),
    ("KR", "Seoul",        37.57,  126.98),
    ("NG", "Lagos",         6.52,    3.38),
    ("ZA", "Johannesburg", -26.20,   28.04),
    ("CA", "Toronto",      43.65,  -79.38),
    ("MX", "Mexico City",  19.43,  -99.13),
    ("SE", "Stockholm",    59.33,   18.07),
    ("IR", "Tehran",       35.69,   51.39),
]


def geoip_lookup(ip: str) -> dict:
    """Return a deterministic geo location for an IP."""
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    loc = _LOCATIONS[h % len(_LOCATIONS)]
    return {
        "country": loc[0],
        "city": loc[1],
        "latitude": loc[2],
        "longitude": loc[3],
    }

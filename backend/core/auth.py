"""Authentication & authorization — JWT-based auth with role-based access control.

Roles:
  - admin   : Full access — manage rules, playbooks, users, and all data
  - analyst : Read access to dashboard, alerts, incidents; can update status/notes
"""
import os
import datetime
import hashlib
import hmac
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_session

SECRET_KEY = os.getenv("JWT_SECRET", "defmon-secret-change-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

security = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Hash password using SHA-256 with salt."""
    import secrets
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify password against stored hash."""
    try:
        salt, stored_hash = hashed.split("$", 1)
        h = hashlib.sha256((salt + password).encode()).hexdigest()
        return hmac.compare_digest(h, stored_hash)
    except (ValueError, AttributeError):
        return False


def create_token(user_id: str, username: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRE_HOURS),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    """Extract and validate the current user from JWT token."""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    return payload


async def require_admin(user: dict = Depends(get_current_user)):
    """Dependency that requires admin role."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


async def require_analyst(user: dict = Depends(get_current_user)):
    """Dependency that requires at least analyst role."""
    if user.get("role") not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Analyst access required")
    return user

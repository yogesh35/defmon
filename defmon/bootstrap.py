"""Bootstrap utilities for production-safe setup without synthetic logs."""

import argparse
import asyncio

from sqlalchemy import select

from defmon.api.auth import get_password_hash
from defmon.database import get_session_factory
from defmon.models import User, UserRole


async def ensure_admin(username: str, password: str) -> None:
    """Create admin user if missing, otherwise reset password."""
    async with get_session_factory()() as session:
        result = await session.execute(select(User).where(User.username == username))
        existing = result.scalar_one_or_none()

        if existing is None:
            session.add(
                User(
                    username=username,
                    hashed_password=get_password_hash(password),
                    role=UserRole.ADMIN,
                    is_active=True,
                    is_locked=False,
                )
            )
            await session.commit()
            print(f"Created admin user '{username}'")
            return

        existing.hashed_password = get_password_hash(password)
        existing.is_active = True
        existing.is_locked = False
        await session.commit()
        print(f"Updated admin credentials for '{username}'")


def main() -> None:
    parser = argparse.ArgumentParser(description="Bootstrap DefMon admin user")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="admin")
    args = parser.parse_args()

    asyncio.run(ensure_admin(username=args.username, password=args.password))


if __name__ == "__main__":
    main()

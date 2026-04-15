"""DefMon bootstrap module for default admin account creation."""

import asyncio

from loguru import logger
from sqlalchemy import select

from defmon.api.auth import get_password_hash
from defmon.database import get_session_factory
from defmon.models import User, UserRole


async def seed_user() -> None:
    """Create the default admin user if one does not exist."""
    factory = get_session_factory()
    async with factory() as session:
        result = await session.execute(select(User).where(User.username == "admin"))
        admin_user = result.scalar_one_or_none()

        if admin_user is None:
            session.add(
                User(
                    username="admin",
                    hashed_password=get_password_hash("admin"),
                    role=UserRole.ADMIN,
                    is_active=True,
                    is_locked=False,
                )
            )
            await session.commit()
            logger.info("✅ Default admin user ready (admin / admin)")
        else:
            logger.info("ℹ️ Default admin user already exists")


async def main() -> None:
    await seed_user()


if __name__ == "__main__":
    asyncio.run(main())

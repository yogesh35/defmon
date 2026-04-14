"""DefMon admin endpoints for minimal user management."""

from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.api.auth import RoleChecker, get_password_hash
from defmon.database import get_db
from defmon.models import User, UserRole


admin_router = APIRouter(prefix="/admin", tags=["Admin"])
allow_admin = RoleChecker([UserRole.ADMIN])


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=6, max_length=128)
    role: UserRole = UserRole.VIEWER


class UpdateUserRoleRequest(BaseModel):
    role: UserRole


class UserLockRequest(BaseModel):
    is_locked: bool


@admin_router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: CreateUserRequest,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    existing = await db.execute(select(User).where(User.username == payload.username))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    new_user = User(
        username=payload.username,
        hashed_password=get_password_hash(payload.password),
        role=payload.role,
        is_active=True,
        is_locked=False,
    )
    db.add(new_user)
    await db.flush()

    return {
        "id": new_user.id,
        "username": new_user.username,
        "role": new_user.role,
        "is_active": new_user.is_active,
        "is_locked": new_user.is_locked,
    }


@admin_router.patch("/users/{username}/role")
async def update_user_role(
    username: str,
    payload: UpdateUserRoleRequest,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(User).where(User.username == username))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target.role = payload.role
    await db.flush()

    return {"username": target.username, "role": target.role}


@admin_router.patch("/users/{username}/lock")
async def set_user_lock(
    username: str,
    payload: UserLockRequest,
    user: User = Depends(allow_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(User).where(User.username == username))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    target.is_locked = payload.is_locked
    await db.flush()

    return {"username": target.username, "is_locked": target.is_locked}

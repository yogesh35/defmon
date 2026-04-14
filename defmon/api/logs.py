"""DefMon Logs API endpoints for browsing and downloading log files."""

from __future__ import annotations

from collections import deque
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.api.auth import RoleChecker
from defmon.config import get_settings
from defmon.database import get_db
from defmon.models import LogEntry, User, UserRole

logs_router = APIRouter(prefix="/logs", tags=["Logs"])
allow_read = RoleChecker([UserRole.VIEWER, UserRole.ANALYST, UserRole.ADMIN])


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _resolve_safe_log_path(raw_path: str) -> Path:
    if not raw_path:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Missing log path")

    project_root = _project_root()
    candidate = (project_root / raw_path).resolve()

    if not str(candidate).startswith(str(project_root.resolve())):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    if candidate.suffix.lower() != ".log":
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Only .log files are supported")

    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log file not found")

    return candidate


def _collect_log_files() -> list[Path]:
    root = _project_root()
    settings = get_settings()
    candidates: set[Path] = set()

    for source in settings.log_sources:
        source_path = Path(source)
        if not source_path.is_absolute():
            source_path = (root / source_path).resolve()
        if source_path.is_file() and source_path.suffix.lower() == ".log":
            candidates.add(source_path)
        elif source_path.is_dir():
            candidates.update(source_path.rglob("*.log"))

    for fallback_dir in [root / "data", root / "defmon"]:
        if fallback_dir.exists() and fallback_dir.is_dir():
            candidates.update(fallback_dir.rglob("*.log"))

    return sorted(candidates)


@logs_router.get("")
async def list_logs(user: User = Depends(allow_read)) -> list[dict]:
    """List available log files under configured sources and DefMon directories."""
    files = _collect_log_files()
    root = _project_root().resolve()

    results: list[dict] = []
    for log_file in files:
        try:
            relative_path = log_file.resolve().relative_to(root).as_posix()
        except ValueError:
            continue
        stat = log_file.stat()
        results.append(
            {
                "path": relative_path,
                "size_bytes": stat.st_size,
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        )

    return results


@logs_router.get("/content")
async def get_log_content(
    path: str = Query(..., description="Workspace-relative .log file path"),
    lines: int = Query(200, ge=1, le=5000),
    user: User = Depends(allow_read),
) -> dict:
    """Return last N lines of a selected log file."""
    log_path = _resolve_safe_log_path(path)

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        tail_lines = list(deque(f, maxlen=lines))

    return {
        "path": path,
        "lines": len(tail_lines),
        "content": "".join(tail_lines),
    }


@logs_router.get("/download")
async def download_log(
    path: str = Query(..., description="Workspace-relative .log file path"),
    user: User = Depends(allow_read),
):
    """Download a selected log file from the DefMon workspace."""
    log_path = _resolve_safe_log_path(path)
    return FileResponse(path=str(log_path), filename=log_path.name, media_type="text/plain")


@logs_router.get("/received")
async def get_received_logs(
    limit: int = Query(200, ge=1, le=2000),
    sender_id: str | None = Query(None),
    user: User = Depends(allow_read),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """Return latest ingested log entries persisted by DefMon backend."""
    stmt = select(LogEntry).order_by(desc(LogEntry.created_at)).limit(limit)
    if sender_id:
        stmt = (
            select(LogEntry)
            .where(LogEntry.sender_id == sender_id)
            .order_by(desc(LogEntry.created_at))
            .limit(limit)
        )

    result = await db.execute(stmt)
    rows = result.scalars().all()

    return [
        {
            "id": row.id,
            "timestamp": row.timestamp.isoformat() if row.timestamp else None,
            "ip": row.ip,
            "method": row.method,
            "uri": row.uri,
            "status_code": row.status_code,
            "sender_id": row.sender_id,
            "sender_name": row.sender_name,
            "classification": row.classification,
            "is_malicious": row.is_malicious,
            "raw_line": row.raw_line,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]

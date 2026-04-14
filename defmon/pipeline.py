"""DefMon runtime pipeline wiring for ingestion, detection, SOAR, and live updates."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from loguru import logger

from defmon.collector import LogCollector
from defmon.database import get_session_factory
from defmon.detection.engine import DetectionEngine, Alert as DetectionAlert
from defmon.models import Alert, LogEntry, SeverityLevel
from defmon.soar.playbooks import get_playbook_engine
from defmon.utils.threat_intel import ThreatIntelService
from defmon.api.websocket import manager


class DefmonPipeline:
    """Orchestrates DefMon real-time backend pipeline.

    Flow:
    collector -> parser -> threat intel -> detection -> DB -> SOAR -> websocket
    """

    def __init__(self) -> None:
        self._collector = LogCollector()
        self._detector = DetectionEngine()
        self._threat_intel = ThreatIntelService()
        self._playbook = get_playbook_engine()
        self._session_factory = get_session_factory()

    @staticmethod
    def _to_severity(value: str) -> SeverityLevel:
        try:
            return SeverityLevel(value)
        except ValueError:
            logger.warning(f"Unknown severity '{value}', defaulting to Low")
            return SeverityLevel.LOW

    @staticmethod
    def _to_naive_utc(dt: datetime) -> datetime:
        """Convert datetime to naive UTC for DB TIMESTAMP WITHOUT TIME ZONE columns."""
        if dt.tzinfo is None:
            return dt
        return dt.astimezone(timezone.utc).replace(tzinfo=None)

    async def _persist_log_entry(self, event, session, is_malicious: bool) -> None:
        session.add(
            LogEntry(
                timestamp=self._to_naive_utc(event.timestamp),
                ip=event.ip,
                method=event.method,
                uri=event.uri,
                status_code=event.status_code,
                bytes_sent=event.bytes_sent,
                user_agent=event.user_agent,
                referrer=event.referrer,
                raw_line=event.raw_line,
                classification="malicious" if is_malicious else "normal",
                is_malicious=is_malicious,
                created_at=datetime.utcnow(),
            )
        )

    async def _persist_alert(self, alert: DetectionAlert, tags: list[str], session) -> Alert:
        db_alert = Alert(
            alert_id=uuid.UUID(alert.alert_id),
            timestamp=self._to_naive_utc(alert.timestamp),
            ip=alert.ip,
            rule_id=alert.rule_id,
            severity=self._to_severity(alert.severity),
            description=alert.description,
            raw_event=alert.raw_event,
            risk_score=alert.risk_score,
            tags=tags,
            status="new",
            created_at=datetime.utcnow(),
        )
        session.add(db_alert)
        await session.flush()
        return db_alert

    async def process_event(self, event) -> None:
        """Process one parsed log event through the full backend pipeline."""
        intel = await self._threat_intel.lookup_ip(event.ip)
        alerts = await self._detector.analyze(event, threat_intel_score=float(intel.confidence_score))
        is_malicious = len(alerts) > 0

        async with self._session_factory() as session:
            await self._persist_log_entry(event, session, is_malicious=is_malicious)

            for alert in alerts:
                merged_tags = list(dict.fromkeys([*alert.tags, *intel.tags]))
                await self._persist_alert(alert, merged_tags, session)

                playbook_result = await self._playbook.execute(alert=alert, session=session)
                incident = playbook_result.get("incident")

                await manager.broadcast(
                    {
                        "type": "alert",
                        "alert": {
                            "alert_id": alert.alert_id,
                            "timestamp": alert.timestamp.isoformat(),
                            "ip": alert.ip,
                            "rule_id": alert.rule_id,
                            "severity": alert.severity,
                            "description": alert.description,
                            "risk_score": alert.risk_score,
                            "tags": merged_tags,
                            "status": "new",
                        },
                        "incident_case_id": str(incident.case_id) if incident else None,
                    }
                )

            await session.commit()

    async def run(self) -> None:
        """Start pipeline by ingesting existing logs and then watching live updates."""
        logger.info("Starting DefMon runtime pipeline")

        existing_events = await self._collector.ingest_existing()
        for event in existing_events:
            try:
                await self.process_event(event)
            except Exception as exc:
                logger.error(f"Error processing existing event: {exc}")

        async for event in self._collector.watch():
            try:
                await self.process_event(event)
            except Exception as exc:
                logger.error(f"Error processing live event: {exc}")

    def stop(self) -> None:
        self._collector.stop()

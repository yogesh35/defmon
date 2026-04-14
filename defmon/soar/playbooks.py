"""DefMon SOAR PlaybookEngine — YAML-driven automated response orchestration.

Loads playbook decision trees from config.yaml (soar.playbooks section).
Receives Alert objects and dispatches appropriate response actions based on
severity level.

Fault-tolerant: if one action raises an exception, the error is logged and
remaining actions continue executing.

Decision tree:
- Critical -> block_ip + lock_account (if username) + create_incident + send_alert_notification
- High     -> block_ip + create_incident + send_alert_notification
- Medium   -> create_incident + send_alert_notification
- Low      -> create_incident
"""

from typing import Optional

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from defmon.config import get_settings
from defmon.detection.engine import Alert
from defmon.models import Incident
from defmon.soar.actions import (
    block_ip,
    create_incident,
    lock_account,
    send_alert_notification,
)


class PlaybookEngine:
    """YAML-driven automated response engine for security alerts.

    Loads playbook configuration from config.yaml and dispatches
    the appropriate sequence of SOAR actions based on alert severity.
    Fault-tolerant: individual action failures are logged but do not
    stop remaining actions from executing.
    """

    def __init__(self, settings=None) -> None:
        """Initialize the playbook engine with config-driven playbooks.

        Args:
            settings: Optional Settings instance for dependency injection.
        """
        self._settings = settings or get_settings()
        soar_config = self._settings.soar_config
        self._playbooks: dict[str, list[str]] = soar_config.get("playbooks", {})

        logger.info(
            f"PlaybookEngine initialized with {len(self._playbooks)} severity playbooks: "
            f"{list(self._playbooks.keys())}"
        )

    async def execute(
        self,
        alert: Alert,
        session: AsyncSession,
    ) -> dict:
        """Execute the playbook for the given alert based on its severity.

        Dispatches actions defined in config.yaml for the alert's severity level.
        Each action is attempted independently — failures are logged but don't
        prevent subsequent actions from running.

        Args:
            alert: Alert dataclass from the detection engine.
            session: Active async database session.

        Returns:
            Dictionary with execution results:
            {
                "severity": str,
                "actions_attempted": list[str],
                "actions_succeeded": list[str],
                "actions_failed": list[dict],
                "incident": Incident or None
            }
        """
        severity = alert.severity
        actions = self._playbooks.get(severity, [])

        if not actions:
            logger.warning(
                f"No playbook defined for severity '{severity}' — "
                f"alert {alert.alert_id} will not trigger automated response"
            )
            return {
                "severity": severity,
                "actions_attempted": [],
                "actions_succeeded": [],
                "actions_failed": [],
                "incident": None,
            }

        logger.info(
            f"Executing playbook for {severity} alert {alert.alert_id}: "
            f"actions={actions}"
        )

        actions_succeeded: list[str] = []
        actions_failed: list[dict] = []
        incident: Optional[Incident] = None

        for action_name in actions:
            try:
                result = await self._dispatch_action(
                    action_name, alert, session
                )
                actions_succeeded.append(action_name)

                # Capture incident reference
                if action_name == "create_incident" and isinstance(result, Incident):
                    incident = result

            except Exception as e:
                # Fault-tolerant: log error and continue
                logger.error(
                    f"Playbook action '{action_name}' failed for alert "
                    f"{alert.alert_id}: {e}"
                )
                actions_failed.append({
                    "action": action_name,
                    "error": str(e),
                })

        # Summary log
        total = len(actions)
        succeeded = len(actions_succeeded)
        failed = len(actions_failed)
        logger.info(
            f"Playbook complete for alert {alert.alert_id}: "
            f"{succeeded}/{total} succeeded, {failed} failed"
        )

        return {
            "severity": severity,
            "actions_attempted": actions,
            "actions_succeeded": actions_succeeded,
            "actions_failed": actions_failed,
            "incident": incident,
        }

    async def _dispatch_action(
        self,
        action_name: str,
        alert: Alert,
        session: AsyncSession,
    ) -> Optional[Incident]:
        """Dispatch a single SOAR action by name.

        Args:
            action_name: Name of the action to execute.
            alert: Alert dataclass providing context.
            session: Active async database session.

        Returns:
            Incident object if action is create_incident, None otherwise.

        Raises:
            ValueError: If action_name is not recognized.
            Any exception from the underlying action function.
        """
        if action_name == "block_ip":
            await block_ip(
                ip=alert.ip,
                session=session,
                reason=f"Alert {alert.rule_id}: {alert.description}",
            )
            return None

        elif action_name == "lock_account":
            if alert.username:
                await lock_account(
                    username=alert.username,
                    session=session,
                )
            else:
                logger.debug(
                    f"Skipping lock_account — no username in alert {alert.alert_id}"
                )
            return None

        elif action_name == "create_incident":
            return await create_incident(alert=alert, session=session)

        elif action_name == "send_alert_notification":
            await send_alert_notification(alert=alert, session=session)
            return None

        else:
            raise ValueError(f"Unknown playbook action: {action_name}")


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------
def get_playbook_engine(settings=None) -> PlaybookEngine:
    """Create and return a PlaybookEngine instance.

    Args:
        settings: Optional Settings override for testing.

    Returns:
        Configured PlaybookEngine instance.
    """
    return PlaybookEngine(settings=settings)

"""DefMon REST API routes package."""

from defmon.api.auth import auth_router
from defmon.api.admin import admin_router
from defmon.api.audit import audit_router
from defmon.api.alerts import alerts_router
from defmon.api.incidents import incidents_router
from defmon.api.logs import logs_router
from defmon.api.metrics import metrics_router
from defmon.api.overview import overview_router
from defmon.api.reports import reports_router
from defmon.api.senders import senders_router
from defmon.api.websocket import ws_router

__all__ = [
	"auth_router",
	"admin_router",
	"audit_router",
	"alerts_router",
	"incidents_router",
	"logs_router",
	"metrics_router",
	"overview_router",
	"reports_router",
	"senders_router",
	"ws_router",
]

"""Resposta a incidentes de ML com estados e ações auditáveis."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4


class OperationalState(str, Enum):
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    DEGRADED = "DEGRADED"
    COMPROMISED = "COMPROMISED"
    ROLLBACK = "ROLLBACK"


@dataclass
class Incident:
    incident_id: str
    alert_type: str
    severity: str
    score: float
    state: str
    action: str
    model_version: str
    created_at: str

    def to_dict(self):
        return asdict(self)


class IncidentResponseManager:
    def __init__(self, model_version="unknown", safe_version=None):
        self.model_version = model_version
        self.safe_version = safe_version
        self.state = OperationalState.NORMAL
        self.quarantined_versions = set()
        self.incidents = []
        self.audit_log = []

    def register_alert(self, alert_type, score, evidence=None):
        score = float(max(0.0, min(1.0, score)))
        severity = "LOW" if score < 0.35 else "MEDIUM" if score < 0.65 else "HIGH" if score < 0.85 else "CRITICAL"
        if severity == "MEDIUM":
            self.state = OperationalState.SUSPICIOUS
        elif severity == "HIGH":
            self.state = OperationalState.DEGRADED
        elif severity == "CRITICAL":
            self.state = OperationalState.COMPROMISED
        action = {
            "LOW": "allow",
            "MEDIUM": "challenge",
            "HIGH": "fallback",
            "CRITICAL": "quarantine",
        }[severity]
        incident = Incident(
            incident_id=str(uuid4()),
            alert_type=alert_type,
            severity=severity,
            score=score,
            state=self.state.value,
            action=action,
            model_version=self.model_version,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.incidents.append(incident)
        self._audit(action, {"incident_id": incident.incident_id, "evidence": evidence or {}})
        return incident.to_dict()

    def aggregate_risk(self, signals, weights=None):
        if not signals:
            return 0.0
        weights = weights or {name: 1.0 for name in signals}
        total = sum(max(0.0, weights.get(name, 1.0)) for name in signals)
        if total == 0:
            return 0.0
        return min(1.0, sum(float(value) * max(0.0, weights.get(name, 1.0)) for name, value in signals.items()) / total)

    def trigger_fallback(self, reason):
        self.state = OperationalState.DEGRADED
        return self._audit("fallback", {"reason": reason})

    def quarantine_model(self, reason):
        self.state = OperationalState.COMPROMISED
        self.quarantined_versions.add(self.model_version)
        return self._audit("quarantine", {"reason": reason, "version": self.model_version})

    def trigger_rollback(self, reason):
        if not self.safe_version:
            raise RuntimeError("safe_version não configurada")
        previous = self.model_version
        self.state = OperationalState.ROLLBACK
        self.model_version = self.safe_version
        event = self._audit("rollback", {"reason": reason, "from": previous, "to": self.safe_version})
        self.state = OperationalState.NORMAL
        return event

    def restore_safe_version(self):
        if not self.safe_version:
            raise RuntimeError("safe_version não configurada")
        self.model_version = self.safe_version
        self.state = OperationalState.NORMAL
        return self._audit("restore", {"version": self.safe_version})

    def _audit(self, action, details):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "state": self.state.value,
            "model_version": self.model_version,
            "details": details,
        }
        self.audit_log.append(event)
        return event

"""Pipeline seguro de inferência: validação, correlação de risco e política."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import numpy as np

from .incident_response import IncidentResponseManager


@dataclass(frozen=True)
class RiskSignals:
    drift_score: float = 0.0
    query_rate: float = 0.0
    input_entropy: float = 0.0
    out_of_distribution: float = 0.0
    adversarial_suspicion: float = 0.0
    extraction_suspicion: float = 0.0

    def clipped(self):
        return {name: float(np.clip(value, 0.0, 1.0)) for name, value in self.__dict__.items()}


class MLSecOpsPipeline:
    """Core sem framework web, reutilizável por API, testes e notebooks."""

    def __init__(
        self,
        predict: Callable,
        feature_count: int,
        minimum: float = -1e6,
        maximum: float = 1e6,
        incident_manager: IncidentResponseManager | None = None,
    ):
        self.predict = predict
        self.feature_count = feature_count
        self.minimum = minimum
        self.maximum = maximum
        self.incidents = incident_manager or IncidentResponseManager()

    def validate(self, features):
        values = np.asarray(features, dtype=float)
        if values.ndim != 1 or len(values) != self.feature_count:
            raise ValueError(f"esperadas {self.feature_count} features")
        if not np.all(np.isfinite(values)):
            raise ValueError("features devem ser números finitos")
        if np.any(values < self.minimum) or np.any(values > self.maximum):
            raise ValueError("features fora do intervalo permitido")
        return values

    @staticmethod
    def correlate_risk(signals: RiskSignals):
        values = signals.clipped()
        # Drift isolado não é tratado como ataque: exige correlação operacional.
        malicious_context = max(
            values["query_rate"],
            values["adversarial_suspicion"],
            values["extraction_suspicion"],
        )
        drift_contribution = values["drift_score"] * (0.25 + 0.75 * malicious_context)
        risk = (
            0.20 * drift_contribution
            + 0.15 * values["query_rate"]
            + 0.10 * values["input_entropy"]
            + 0.15 * values["out_of_distribution"]
            + 0.20 * values["adversarial_suspicion"]
            + 0.20 * values["extraction_suspicion"]
        )
        return float(np.clip(risk, 0.0, 1.0))

    def process(self, features, signals=None, authenticated=True):
        if not authenticated:
            return {"action": "deny", "reason": "authentication_required"}
        values = self.validate(features)
        signals = signals or RiskSignals()
        risk = self.correlate_risk(signals)
        if risk >= 0.85:
            incident = self.incidents.register_alert("ml_abuse", risk, signals.clipped())
            return {"action": "quarantine", "risk_score": risk, "incident": incident}
        if risk >= 0.65:
            incident = self.incidents.register_alert("ml_abuse", risk, signals.clipped())
            return {"action": "fallback", "risk_score": risk, "incident": incident}
        if risk >= 0.35:
            incident = self.incidents.register_alert("ml_abuse", risk, signals.clipped())
            return {"action": "challenge", "risk_score": risk, "incident": incident}
        prediction = self.predict(values[None, :])
        return {
            "action": "allow",
            "risk_score": risk,
            "prediction": int(np.asarray(prediction).reshape(-1)[0]),
        }

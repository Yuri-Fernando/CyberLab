import numpy as np

from ml_security.incident_response import IncidentResponseManager, OperationalState
from ml_security.mlsecops_pipeline import MLSecOpsPipeline, RiskSignals


def test_incident_manager_can_fallback_quarantine_and_rollback():
    manager = IncidentResponseManager(model_version="2.3.0", safe_version="2.2.0")
    incident = manager.register_alert("extraction", 0.9)
    assert incident["severity"] == "CRITICAL"
    assert manager.state == OperationalState.COMPROMISED
    manager.quarantine_model("confirmed")
    event = manager.trigger_rollback("restore trusted artifact")
    assert event["details"]["to"] == "2.2.0"
    assert manager.state == OperationalState.NORMAL


def test_drift_alone_is_not_classified_as_attack():
    pipeline = MLSecOpsPipeline(lambda values: np.zeros(len(values), dtype=int), feature_count=2)
    result = pipeline.process([0.1, 0.2], RiskSignals(drift_score=1.0))
    assert result["action"] == "allow"
    abusive = pipeline.process(
        [0.1, 0.2],
        RiskSignals(drift_score=1.0, query_rate=1.0, extraction_suspicion=1.0),
    )
    assert abusive["action"] in {"challenge", "fallback", "quarantine"}

from ml_security.gradient_masking_audit import GradientMaskingAuditor
from test_whitebox_attacks import linear_model_and_data


def test_gradient_masking_audit_runs_independent_checks():
    model, x, y = linear_model_and_data()
    report = GradientMaskingAuditor().audit(
        model,
        x,
        y,
        epsilon=0.3,
        alpha=0.08,
        epsilon_values=(0.0, 0.1, 0.3),
        step_values=(1, 3, 6),
        restart_values=(1, 2),
    )
    assert report["checks_executed"] >= 5
    assert report["risk"] in {"LOW", "MEDIUM", "HIGH"}
    assert len(report["epsilon_curve"]) == 3
    assert len(report["steps_curve"]) == 3

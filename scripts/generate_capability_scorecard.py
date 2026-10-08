"""Gera o scorecard de cobertura do upgrade sem depender de serviços externos."""

from __future__ import annotations

import json
from pathlib import Path


COVERAGE = {
    "Threat Modeling": ("IMPLEMENTED", "docs/04_ml_security_threat_model.md"),
    "Poisoning": ("IMPLEMENTED", "scripts/python/ml_security/poisoning_attacks.py"),
    "Evasion": ("IMPLEMENTED", "scripts/python/ml_security/whitebox_attacks_torch.py"),
    "Extraction": ("IMPLEMENTED", "scripts/python/ml_security/model_extraction.py"),
    "Privacy": ("IMPLEMENTED", "scripts/python/ml_security/differential_privacy.py"),
    "Hardening": ("IMPLEMENTED", "services/model_api/app.py"),
    "ART": ("PARTIAL", "scripts/python/ml_security/art_lab.py"),
    "Foolbox": ("PARTIAL", "scripts/python/ml_security/foolbox_lab.py"),
    "Gradient Masking": ("IMPLEMENTED", "scripts/python/ml_security/gradient_masking_audit.py"),
    "DP-SGD": ("PARTIAL", "scripts/python/ml_security/differential_privacy.py"),
    "Watermarking": ("IMPLEMENTED", "scripts/python/ml_security/model_watermarking.py"),
    "MLSecOps": ("IMPLEMENTED", "scripts/python/ml_security/mlsecops_pipeline.py"),
    "Drift": ("IMPLEMENTED", "scripts/python/ml_security/observability_adapters.py"),
    "Incident Response": ("IMPLEMENTED", "scripts/python/ml_security/incident_response.py"),
    "MLaaS": ("PARTIAL", "services/model_api/app.py"),
    "Teaching Material": ("IMPLEMENTED", "notebooks/11_evasion_fgsm_pgd.ipynb"),
    "Supply Chain": ("PLANNED", "README.md#roadmap"),
    "Provenance / ML-BOM": ("PLANNED", "README.md#roadmap"),
    "Policy Engine / HITL": ("PLANNED", "README.md#roadmap"),
}


def generate(output_path: str | Path = "results/capability_scorecard.json") -> Path:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    items = {
        name: {"status": status, "evidence": evidence}
        for name, (status, evidence) in COVERAGE.items()
    }
    summary = {
        status: sum(item["status"] == status for item in items.values())
        for status in ("IMPLEMENTED", "PARTIAL", "PLANNED")
    }
    output.write_text(
        json.dumps({"summary": summary, "categories": items}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output


if __name__ == "__main__":
    print(generate())

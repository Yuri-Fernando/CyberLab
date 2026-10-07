"""
test_map_findings_report.py - Valida o parsing dos outputs reais de scan e o
relatorio consolidado gerado por cloud_security/mapping/map_findings.py.

Usa os JSONs reais versionados em cloud_security/results/ (gerados rodando
Checkov 3.2.459 e Trivy 0.75.0 contra os labs) - nao usa mocks do
comportamento central de parsing.
"""

from cloud_security.mapping.map_findings import (
    build_report,
    load_checkov_findings,
    load_trivy_findings,
)


def test_load_checkov_findings_parses_real_report():
    findings = load_checkov_findings("aws")
    assert len(findings) > 0
    assert all(f["tool"] == "checkov" and f["cloud"] == "aws" for f in findings)
    check_ids = {f["check_id"] for f in findings}
    assert "CKV_AWS_53" in check_ids  # bucket publico, achado real conhecido


def test_load_trivy_findings_parses_real_report():
    findings = load_trivy_findings("aws")
    assert len(findings) > 0
    assert all(f["tool"] == "trivy" and f["cloud"] == "aws" for f in findings)
    check_ids = {f["check_id"] for f in findings}
    assert "AWS-0107" in check_ids  # SG aberto, achado real conhecido


def test_load_findings_for_all_clouds_returns_data():
    for cloud in ("aws", "azure", "gcp"):
        assert load_checkov_findings(cloud), f"sem findings checkov reais para {cloud}"
        assert load_trivy_findings(cloud), f"sem findings trivy reais para {cloud}"


def test_build_report_is_internally_consistent():
    report = build_report()
    assert report["total_findings"] == len(report["findings"])
    assert report["mapped_findings"] + report["unmapped_findings"] == report["total_findings"]
    assert report["mapped_findings"] == sum(1 for f in report["findings"] if f["mapped"])
    assert sum(report["findings_by_cloud"].values()) == report["total_findings"]
    # pelo menos uma parcela relevante dos findings reais tem categoria conhecida
    assert report["mapped_findings"] > 0
    # o disclaimer deve deixar explicito que isto NAO e uma certificacao
    assert "disclaimer" in report
    assert "nao e uma certificacao" in report["disclaimer"].lower()

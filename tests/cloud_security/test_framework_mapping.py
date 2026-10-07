"""
test_framework_mapping.py - Verifica o mapeamento declarativo findings -> frameworks.

Cobre: categorizacao por check_id real (Checkov e Trivy), presenca de controles
reais de NIST CSF 2.0 / ISO 27001:2022 / LGPD para categorias conhecidas, e o
comportamento honesto para checks desconhecidos (mapped=False, sem controle
inventado).
"""

from cloud_security.mapping.framework_mapping import (
    CHECKOV_CHECK_TO_CATEGORY,
    ISO_27001_2022_CONTROLS,
    MAPPINGS,
    NIST_CSF2_CATEGORIES,
    TRIVY_ID_TO_CATEGORY,
    categorize_checkov,
    categorize_trivy,
    get_mapping,
)
from cloud_security.mapping.map_findings import map_finding


def test_known_checkov_check_maps_to_public_storage_exposure():
    assert categorize_checkov("CKV_AWS_53") == "public_storage_exposure"


def test_known_trivy_id_maps_to_open_network_ingress():
    assert categorize_trivy("AWS-0107") == "open_network_ingress"


def test_unknown_check_id_returns_none_not_a_guess():
    assert categorize_checkov("CKV_AWS_99999_DOES_NOT_EXIST") is None
    assert categorize_trivy("AWS-9999") is None


def test_every_category_used_in_tables_has_a_mapping_definition():
    used_categories = set(CHECKOV_CHECK_TO_CATEGORY.values()) | set(
        TRIVY_ID_TO_CATEGORY.values()
    )
    for category in used_categories:
        assert category in MAPPINGS, f"Categoria '{category}' sem ControlMapping definido"


def test_every_mapping_cites_at_least_one_real_control_per_framework():
    for category, mapping in MAPPINGS.items():
        assert mapping.nist_csf2, f"{category} sem NIST CSF 2.0"
        assert mapping.iso_27001_2022, f"{category} sem ISO 27001"
        assert mapping.lgpd, f"{category} sem LGPD"
        for code in mapping.nist_csf2:
            assert code in NIST_CSF2_CATEGORIES, f"NIST CSF code inventado: {code}"
        for code in mapping.iso_27001_2022:
            assert code in ISO_27001_2022_CONTROLS, f"ISO 27001 code inventado: {code}"


def test_map_finding_enriches_known_checkov_finding():
    finding = {
        "tool": "checkov",
        "cloud": "aws",
        "check_id": "CKV_AWS_24",
        "check_name": "x",
        "resource": "r",
        "file_path": "f",
        "severity": "HIGH",
    }
    enriched = map_finding(finding)
    assert enriched["mapped"] is True
    assert enriched["category"] == "open_network_ingress"
    assert "PR.IR" in enriched["nist_csf2"] or "PR.PS" in enriched["nist_csf2"]
    assert enriched["iso_27001_2022"]
    assert enriched["lgpd"]


def test_map_finding_preserves_unmapped_finding_without_inventing_controls():
    finding = {
        "tool": "checkov",
        "cloud": "aws",
        "check_id": "CKV_AWS_NOT_IN_TABLE",
        "check_name": "x",
        "resource": "r",
        "file_path": "f",
        "severity": "LOW",
    }
    enriched = map_finding(finding)
    assert enriched["mapped"] is False
    assert enriched["category"] is None
    assert enriched["nist_csf2"] == []
    assert enriched["iso_27001_2022"] == []
    assert enriched["lgpd"] == []
    # O finding original nunca e descartado
    assert enriched["check_id"] == "CKV_AWS_NOT_IN_TABLE"


def test_get_mapping_unknown_category_returns_none():
    assert get_mapping("categoria_que_nao_existe") is None

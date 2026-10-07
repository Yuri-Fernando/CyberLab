"""
map_findings.py - Le findings reais de Checkov/Trivy e mapeia para frameworks

Uso:
    python -m cloud_security.mapping.map_findings

Le os JSONs reais em cloud_security/results/{checkov,trivy}_{aws,azure,gcp}.json
(gerados rodando as ferramentas de verdade contra cloud_security/labs/), extrai
os findings com status de falha, mapeia cada um para uma categoria conhecida
(ver framework_mapping.py) e grava cloud_security/results/mapped_findings.json
com o mapeamento para NIST CSF 2.0 / ISO 27001:2022 / LGPD.

Findings sem categoria conhecida sao preservados no output com mapped=False,
nunca descartados e nunca mapeados por adivinhacao.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List

from cloud_security.mapping.framework_mapping import (
    categorize_checkov,
    categorize_trivy,
    get_mapping,
)

logger = logging.getLogger(__name__)

RESULTS_DIR = Path(__file__).resolve().parents[1] / "results"
CLOUDS = ("aws", "azure", "gcp")


def load_checkov_findings(cloud: str) -> List[Dict]:
    """Extrai failed_checks de um relatorio Checkov real."""
    path = RESULTS_DIR / f"checkov_{cloud}.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        data = data[0] if data else {}
    failed = data.get("results", {}).get("failed_checks", [])
    findings = []
    for f in failed:
        findings.append(
            {
                "tool": "checkov",
                "cloud": cloud,
                "check_id": f.get("check_id"),
                "check_name": f.get("check_name"),
                "resource": f.get("resource"),
                "file_path": f.get("file_path"),
                "severity": f.get("severity") or "UNKNOWN",
            }
        )
    return findings


def load_trivy_findings(cloud: str) -> List[Dict]:
    """Extrai misconfigs com Status=FAIL de um relatorio Trivy config real."""
    path = RESULTS_DIR / f"trivy_{cloud}.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for result in data.get("Results", []) or []:
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            resource = (m.get("CauseMetadata") or {}).get("Resource")
            findings.append(
                {
                    "tool": "trivy",
                    "cloud": cloud,
                    "check_id": m.get("ID"),
                    "check_name": m.get("Title"),
                    "resource": resource,
                    "file_path": result.get("Target"),
                    "severity": m.get("Severity") or "UNKNOWN",
                }
            )
    return findings


def map_finding(finding: Dict) -> Dict:
    """Enriquece um finding com a categoria e os controles de framework, se houver."""
    if finding["tool"] == "checkov":
        category = categorize_checkov(finding["check_id"])
    elif finding["tool"] == "trivy":
        category = categorize_trivy(finding["check_id"])
    else:
        category = None

    enriched = dict(finding)
    if category is None:
        enriched["mapped"] = False
        enriched["category"] = None
        enriched["nist_csf2"] = []
        enriched["iso_27001_2022"] = []
        enriched["lgpd"] = []
        return enriched

    mapping = get_mapping(category)
    enriched["mapped"] = True
    enriched["category"] = category
    enriched["nist_csf2"] = mapping.nist_csf2 if mapping else []
    enriched["iso_27001_2022"] = mapping.iso_27001_2022 if mapping else []
    enriched["lgpd"] = mapping.lgpd if mapping else []
    return enriched


def build_report() -> Dict:
    """Carrega todos os findings reais, mapeia, e monta o relatorio consolidado."""
    all_findings = []
    for cloud in CLOUDS:
        all_findings.extend(load_checkov_findings(cloud))
        all_findings.extend(load_trivy_findings(cloud))

    mapped = [map_finding(f) for f in all_findings]
    mapped_count = sum(1 for m in mapped if m["mapped"])

    by_cloud: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    for m in mapped:
        by_cloud[m["cloud"]] = by_cloud.get(m["cloud"], 0) + 1
        if m["category"]:
            by_category[m["category"]] = by_category.get(m["category"], 0) + 1

    return {
        "disclaimer": (
            "Mapeamento declarativo findings->controles conhecidos. NAO e uma "
            "certificacao, auditoria formal ou atestado de conformidade com "
            "NIST CSF 2.0, ISO/IEC 27001 ou LGPD. Exige revisao humana."
        ),
        "total_findings": len(mapped),
        "mapped_findings": mapped_count,
        "unmapped_findings": len(mapped) - mapped_count,
        "findings_by_cloud": by_cloud,
        "findings_by_category": by_category,
        "findings": mapped,
    }


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    report = build_report()
    out_path = RESULTS_DIR / "mapped_findings.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(
        "Mapeamento concluido: %d findings totais, %d mapeados, %d sem categoria conhecida -> %s",
        report["total_findings"],
        report["mapped_findings"],
        report["unmapped_findings"],
        out_path,
    )


if __name__ == "__main__":
    main()

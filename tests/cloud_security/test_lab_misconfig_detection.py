"""
test_lab_misconfig_detection.py - Regressao: os labs de misconfig devem
continuar sendo detectados pelas ferramentas reais (Checkov e Trivy).

Estes testes RODAM as ferramentas de verdade (subprocess) contra os arquivos
Terraform em cloud_security/labs/. Se alguem "corrigir" acidentalmente um dos
misconfigs propositais do lab, o check correspondente deixa de falhar e o
teste de regressao aponta exatamente qual check parou de ser detectado.

Marcados com @pytest.mark.slow porque invocam processos externos reais.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LABS_DIR = ROOT / "cloud_security" / "labs"

CHECKOV_BIN = shutil.which("checkov")
TRIVY_BIN = shutil.which("trivy")

# Checks que DEVEM continuar falhando enquanto os labs permanecerem
# intencionalmente mal configurados. Um unico check por categoria/cloud
# e suficiente para a regressao - nao precisa ser a lista completa.
EXPECTED_CHECKOV_FAILURES = {
    "aws": {"CKV_AWS_53", "CKV_AWS_24", "CKV_AWS_63", "CKV_AWS_16", "CKV_AWS_17"},
    "azure": {"CKV_AZURE_59", "CKV_AZURE_9", "CKV_AZURE_110"},
    "gcp": {"CKV_GCP_28", "CKV_GCP_2", "CKV_GCP_117"},
}

EXPECTED_TRIVY_FAILURES = {
    "aws": {"AWS-0092", "AWS-0107", "AWS-0080", "AWS-0180"},
    "azure": {"AZU-0047", "AZU-0061"},
    "gcp": {"GCP-0001", "GCP-0027"},
}


def _run_checkov(cloud: str) -> dict:
    result = subprocess.run(
        [CHECKOV_BIN, "-d", str(LABS_DIR / cloud), "-o", "json", "--compact"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    data = json.loads(result.stdout)
    if isinstance(data, list):
        data = data[0] if data else {}
    return data


def _run_trivy(cloud: str) -> dict:
    result = subprocess.run(
        [TRIVY_BIN, "config", "--format", "json", str(LABS_DIR / cloud)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    return json.loads(result.stdout)


@pytest.mark.skipif(CHECKOV_BIN is None, reason="checkov nao instalado neste ambiente")
@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_checkov_detects_known_misconfigs(cloud):
    data = _run_checkov(cloud)
    failed_ids = {f["check_id"] for f in data["results"]["failed_checks"]}
    missing = EXPECTED_CHECKOV_FAILURES[cloud] - failed_ids
    assert not missing, (
        f"Checkov parou de detectar {missing} no lab '{cloud}'. "
        "Isso indica que o misconfig proposital foi corrigido/removido "
        "do Terraform do lab (ou o check mudou de comportamento)."
    )


@pytest.mark.skipif(TRIVY_BIN is None, reason="trivy nao instalado neste ambiente")
@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_trivy_detects_known_misconfigs(cloud):
    data = _run_trivy(cloud)
    failed_ids = set()
    for result in data.get("Results", []) or []:
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") == "FAIL":
                failed_ids.add(m["ID"])
    missing = EXPECTED_TRIVY_FAILURES[cloud] - failed_ids
    assert not missing, (
        f"Trivy parou de detectar {missing} no lab '{cloud}'. "
        "Isso indica que o misconfig proposital foi corrigido/removido "
        "do Terraform do lab (ou o check mudou de comportamento)."
    )


def test_lab_terraform_files_exist():
    for cloud in ("aws", "azure", "gcp"):
        tf_file = LABS_DIR / cloud / "main.tf"
        assert tf_file.exists(), f"Lab Terraform ausente para {cloud}: {tf_file}"
        assert tf_file.stat().st_size > 0

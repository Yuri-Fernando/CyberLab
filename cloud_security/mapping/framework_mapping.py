"""
framework_mapping.py - Tabelas de mapeamento findings -> frameworks

Abordagem: cada finding real (identificado pelo check_id do Checkov, ou pelo
AVD-ID do Trivy) pertence a uma CATEGORIA de misconfig (ex: exposicao publica
de storage, rede aberta ao mundo, IAM superprivilegiado...). Cada categoria
e mapeada para:

- NIST CSF 2.0: Funcao + Categoria reais (das 6 funcoes oficiais do CSF 2.0:
  GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER).
- ISO/IEC 27001:2022, Anexo A: controles reais (ex: A.8.24 criptografia).
- LGPD: artigos reais relevantes a seguranca de dados pessoais.

Checks sem categoria conhecida retornam mapped=False e NAO recebem um
controle inventado - isso e intencional (ver Auditoria_Portfolio, regra
"nao alegar X sem uso real" aplicada tambem ao mapeamento de controles).

Este mapeamento e DECLARATIVO e EDUCACIONAL: acelera a triagem de um
analista de GRC, mas nao e uma certificacao nem substitui auditoria formal
contra NIST CSF, ISO 27001 ou LGPD.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class ControlMapping:
    """Mapeamento de uma categoria de misconfig para controles de 3 frameworks."""

    category: str
    description: str
    nist_csf2: List[str] = field(default_factory=list)
    iso_27001_2022: List[str] = field(default_factory=list)
    lgpd: List[str] = field(default_factory=list)


# --- NIST CSF 2.0 — referencia das Funcoes/Categorias oficiais usadas aqui ---
# (subconjunto real das 6 funcoes do CSF 2.0: GOVERN, IDENTIFY, PROTECT,
# DETECT, RESPOND, RECOVER — https://www.nist.gov/cyberframework)
NIST_CSF2_CATEGORIES = {
    "GV.SC": "GOVERN — Cybersecurity Supply Chain Risk Management",
    "ID.AM": "IDENTIFY — Asset Management",
    "ID.RA": "IDENTIFY — Risk Assessment",
    "PR.AA": "PROTECT — Identity Management, Authentication and Access Control",
    "PR.DS": "PROTECT — Data Security",
    "PR.PS": "PROTECT — Platform Security",
    "PR.IR": "PROTECT — Technology Infrastructure Resilience",
    "DE.CM": "DETECT — Continuous Monitoring",
    "DE.AE": "DETECT — Adverse Event Analysis",
}

# --- ISO/IEC 27001:2022 Anexo A — controles reais citados aqui ---
ISO_27001_2022_CONTROLS = {
    "A.5.15": "Access control",
    "A.5.18": "Access rights",
    "A.5.23": "Information security for use of cloud services",
    "A.8.3": "Information access restriction",
    "A.8.9": "Configuration management",
    "A.8.16": "Monitoring activities",
    "A.8.20": "Networks security",
    "A.8.21": "Security of network services",
    "A.8.24": "Use of cryptography",
}

# --- LGPD — artigos reais relevantes a seguranca de dados pessoais ---
LGPD_ARTICLES = {
    "Art. 6º, VII": "Princípio da segurança — medidas técnicas e administrativas de proteção",
    "Art. 37": "Registro das operações de tratamento de dados pessoais",
    "Art. 46": "Agentes de tratamento devem adotar medidas de segurança técnicas e "
    "administrativas aptas a proteger dados pessoais de acessos não autorizados",
    "Art. 48": "Comunicação à ANPD e ao titular de incidente de segurança que possa "
    "acarretar risco ou dano relevante",
}


MAPPINGS: Dict[str, ControlMapping] = {
    "public_storage_exposure": ControlMapping(
        category="public_storage_exposure",
        description="Bucket/storage account exposto publicamente (ACL, policy ou "
        "flag de acesso público).",
        nist_csf2=["PR.AA", "PR.DS"],
        iso_27001_2022=["A.8.3", "A.5.23"],
        lgpd=["Art. 46", "Art. 6º, VII"],
    ),
    "open_network_ingress": ControlMapping(
        category="open_network_ingress",
        description="Security group / NSG / firewall rule permitindo ingress "
        "irrestrito (0.0.0.0/0) em porta sensível (SSH/RDP).",
        nist_csf2=["PR.IR", "PR.PS"],
        iso_27001_2022=["A.8.20", "A.8.21"],
        lgpd=["Art. 46"],
    ),
    "excessive_iam_privilege": ControlMapping(
        category="excessive_iam_privilege",
        description="IAM policy/role/service account com privilégio excessivo "
        "(Action:\"*\"/Resource:\"*\", roles/owner, basic roles no projeto).",
        nist_csf2=["PR.AA", "ID.RA"],
        iso_27001_2022=["A.5.15", "A.5.18"],
        lgpd=["Art. 46", "Art. 6º, VII"],
    ),
    "unencrypted_data_at_rest": ControlMapping(
        category="unencrypted_data_at_rest",
        description="Dados em repouso sem criptografia (RDS sem encryption, "
        "storage sem CMK, Key Vault sem purge protection).",
        nist_csf2=["PR.DS"],
        iso_27001_2022=["A.8.24"],
        lgpd=["Art. 46"],
    ),
    "publicly_accessible_database": ControlMapping(
        category="publicly_accessible_database",
        description="Instância de banco de dados acessível publicamente.",
        nist_csf2=["PR.AA", "PR.IR"],
        iso_27001_2022=["A.8.3", "A.8.20"],
        lgpd=["Art. 46", "Art. 48"],
    ),
    "missing_logging_monitoring": ControlMapping(
        category="missing_logging_monitoring",
        description="Ausência de logging/monitoramento de acesso em recurso "
        "que armazena ou expõe dados.",
        nist_csf2=["DE.CM", "DE.AE"],
        iso_27001_2022=["A.8.16"],
        lgpd=["Art. 37"],
    ),
    "weak_transport_security": ControlMapping(
        category="weak_transport_security",
        description="Versão mínima de TLS desatualizada ou ausência de "
        "exigência de criptografia em trânsito.",
        nist_csf2=["PR.DS"],
        iso_27001_2022=["A.8.24"],
        lgpd=["Art. 46"],
    ),
    "resource_lifecycle_governance": ControlMapping(
        category="resource_lifecycle_governance",
        description="Ausência de versionamento, retenção, backup ou "
        "configuration management do ciclo de vida do recurso.",
        nist_csf2=["ID.AM", "PR.PS"],
        iso_27001_2022=["A.8.9"],
        lgpd=["Art. 37"],
    ),
}


# Tabela check_id (Checkov) -> categoria.
# Construída a partir dos findings REAIS observados ao rodar Checkov contra
# cloud_security/labs/{aws,azure,gcp} (ver cloud_security/results/). Checks
# fora desta tabela ficam sem categoria (mapped=False) em vez de receber um
# controle adivinhado.
CHECKOV_CHECK_TO_CATEGORY: Dict[str, str] = {
    # AWS — exposição pública de storage
    "CKV_AWS_53": "public_storage_exposure",
    "CKV_AWS_54": "public_storage_exposure",
    "CKV_AWS_55": "public_storage_exposure",
    "CKV_AWS_56": "public_storage_exposure",
    "CKV_AWS_20": "public_storage_exposure",
    "CKV2_AWS_6": "public_storage_exposure",
    # AWS — rede aberta
    "CKV_AWS_24": "open_network_ingress",
    "CKV_AWS_25": "open_network_ingress",
    "CKV_AWS_382": "open_network_ingress",
    # AWS — IAM superprivilegiado
    "CKV_AWS_62": "excessive_iam_privilege",
    "CKV_AWS_63": "excessive_iam_privilege",
    "CKV_AWS_355": "excessive_iam_privilege",
    "CKV_AWS_286": "excessive_iam_privilege",
    "CKV_AWS_287": "excessive_iam_privilege",
    "CKV_AWS_288": "excessive_iam_privilege",
    "CKV_AWS_289": "excessive_iam_privilege",
    "CKV_AWS_290": "excessive_iam_privilege",
    "CKV2_AWS_40": "excessive_iam_privilege",
    # AWS — criptografia em repouso
    "CKV_AWS_16": "unencrypted_data_at_rest",
    "CKV_AWS_145": "unencrypted_data_at_rest",
    # AWS — banco de dados público
    "CKV_AWS_17": "publicly_accessible_database",
    # AWS — logging ausente
    "CKV_AWS_18": "missing_logging_monitoring",
    "CKV_AWS_129": "missing_logging_monitoring",
    # AWS — ciclo de vida (versionamento, backup, lifecycle)
    "CKV_AWS_21": "resource_lifecycle_governance",
    "CKV_AWS_133": "resource_lifecycle_governance",
    "CKV2_AWS_61": "resource_lifecycle_governance",
    "CKV2_AWS_60": "resource_lifecycle_governance",
    # Azure — exposição pública de storage
    "CKV_AZURE_59": "public_storage_exposure",
    "CKV_AZURE_190": "public_storage_exposure",
    "CKV2_AZURE_47": "public_storage_exposure",
    # Azure — rede aberta
    "CKV_AZURE_9": "open_network_ingress",
    "CKV_AZURE_10": "open_network_ingress",
    # Azure — criptografia / Key Vault
    "CKV_AZURE_109": "unencrypted_data_at_rest",
    "CKV_AZURE_110": "unencrypted_data_at_rest",
    "CKV_AZURE_42": "unencrypted_data_at_rest",
    "CKV2_AZURE_1": "unencrypted_data_at_rest",
    "CKV_AZURE_189": "public_storage_exposure",
    # Azure — TLS fraco
    "CKV_AZURE_44": "weak_transport_security",
    # Azure — logging ausente
    "CKV_AZURE_33": "missing_logging_monitoring",
    # Azure — ciclo de vida
    "CKV_AZURE_206": "resource_lifecycle_governance",
    "CKV2_AZURE_41": "resource_lifecycle_governance",
    # GCP — exposição pública de storage
    "CKV_GCP_28": "public_storage_exposure",
    "CKV_GCP_29": "public_storage_exposure",
    "CKV_GCP_114": "public_storage_exposure",
    # GCP — rede aberta
    "CKV_GCP_2": "open_network_ingress",
    "CKV_GCP_3": "open_network_ingress",
    # GCP — IAM superprivilegiado
    "CKV_GCP_117": "excessive_iam_privilege",
    "CKV_GCP_49": "excessive_iam_privilege",
    # GCP — logging / ciclo de vida
    "CKV_GCP_62": "missing_logging_monitoring",
    "CKV_GCP_78": "resource_lifecycle_governance",
}

# Tabela ID (Trivy `config` scanner) -> categoria. IDs reais conforme
# observados no campo "ID" do output `trivy config --format json` rodado
# contra cloud_security/labs/{aws,azure,gcp} (ver cloud_security/results/).
# Formato real do Trivy e "<CLOUD>-NNNN" (ex: AWS-0107), nao "AVD-...".
TRIVY_ID_TO_CATEGORY: Dict[str, str] = {
    # AWS
    "AWS-0086": "public_storage_exposure",  # S3 access block: block public ACL
    "AWS-0087": "public_storage_exposure",  # S3 access block: block public policy
    "AWS-0091": "public_storage_exposure",  # S3 access block: ignore public ACL
    "AWS-0092": "public_storage_exposure",  # S3 bucket publico via ACL
    "AWS-0093": "public_storage_exposure",  # S3 access block: restrict public bucket
    "AWS-0104": "open_network_ingress",  # SG egress irrestrito
    "AWS-0107": "open_network_ingress",  # SG ingress irrestrito SSH/RDP
    "AWS-0124": "resource_lifecycle_governance",  # SG rule sem descricao
    "AWS-0132": "unencrypted_data_at_rest",  # S3 sem Customer Managed Key
    "AWS-0080": "unencrypted_data_at_rest",  # RDS sem encryption
    "AWS-0176": "publicly_accessible_database",  # RDS sem IAM DB auth
    "AWS-0177": "resource_lifecycle_governance",  # RDS sem deletion protection
    "AWS-0180": "publicly_accessible_database",  # RDS publicamente acessivel
    "AWS-0089": "missing_logging_monitoring",  # S3 bucket logging
    "AWS-0090": "resource_lifecycle_governance",  # S3 sem versionamento
    "AWS-0133": "missing_logging_monitoring",  # RDS sem Performance Insights
    "AWS-0077": "resource_lifecycle_governance",  # RDS backup retention baixo
    # Azure
    "AZU-0011": "weak_transport_security",  # TLS minimo abaixo de 1.2
    "AZU-0012": "public_storage_exposure",  # network rules default action
    "AZU-0013": "unencrypted_data_at_rest",  # Key Vault sem network acl
    "AZU-0016": "unencrypted_data_at_rest",  # Key Vault sem purge protection
    "AZU-0047": "open_network_ingress",  # SG/NSG ingress irrestrito
    "AZU-0048": "open_network_ingress",  # NSG RDP irrestrito
    "AZU-0050": "open_network_ingress",  # NSG SSH irrestrito
    "AZU-0056": "resource_lifecycle_governance",  # storage sem blob soft delete
    "AZU-0057": "missing_logging_monitoring",  # storage sem logging
    "AZU-0058": "resource_lifecycle_governance",  # storage sem geo-redundancia
    "AZU-0059": "weak_transport_security",  # secure transfer / TLS minimo
    "AZU-0061": "unencrypted_data_at_rest",  # storage sem infra encryption
    # GCP
    "GCP-0001": "public_storage_exposure",  # bucket publico/anonimo
    "GCP-0002": "public_storage_exposure",  # uniform bucket-level access
    "GCP-0027": "open_network_ingress",  # firewall ingress irrestrito
    "GCP-0066": "unencrypted_data_at_rest",  # bucket sem CMK
    "GCP-0070": "open_network_ingress",  # RDP irrestrito
    "GCP-0071": "open_network_ingress",  # SSH irrestrito
    "GCP-0073": "resource_lifecycle_governance",  # firewall rule default nao desabilitada
    "GCP-0077": "missing_logging_monitoring",  # bucket sem logging
    "GCP-0078": "resource_lifecycle_governance",  # bucket sem versionamento
}


def categorize_checkov(check_id: str) -> Optional[str]:
    """Retorna a categoria de misconfig de um check_id do Checkov, se conhecida."""
    return CHECKOV_CHECK_TO_CATEGORY.get(check_id)


def categorize_trivy(check_id: str) -> Optional[str]:
    """Retorna a categoria de misconfig de um ID do Trivy (ex: AWS-0107), se conhecida."""
    return TRIVY_ID_TO_CATEGORY.get(check_id)


def get_mapping(category: str) -> Optional[ControlMapping]:
    """Retorna o ControlMapping completo (NIST/ISO/LGPD) de uma categoria."""
    return MAPPINGS.get(category)

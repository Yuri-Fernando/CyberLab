"""
cloud_security - Cloud Security Posture Management (CSPM) educacional

Labs de infraestrutura-como-codigo propositalmente mal configurada (AWS, Azure,
GCP), scan estatico real contra esses labs com ferramentas de mercado (Checkov,
Trivy), e mapeamento declarativo dos findings reais para NIST CSF 2.0,
ISO/IEC 27001:2022 (Anexo A) e LGPD.

Nenhum dos labs e aplicado contra uma conta cloud real. Nenhuma credencial
cloud e usada. Ferramentas que exigem conta real para funcionar (ScoutSuite,
Steampipe) estao documentadas como limitacao conhecida em
cloud_security/README.md e NAO sao citadas como usadas.
"""

__version__ = "1.0.0"
__author__ = "CyberLab"

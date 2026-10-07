"""
mapping - Mapeamento de findings de scan para frameworks de controle

Transforma findings reais de Checkov/Trivy (identificados por check_id) em
referencias declarativas a NIST CSF 2.0, ISO/IEC 27001:2022 (Anexo A) e LGPD.

Isto NAO e uma certificacao, auditoria formal ou atestado de conformidade.
E um mapeamento findings -> controles conhecidos, do tipo que acelera o
trabalho de um analista de GRC, mas que ainda exige revisao humana antes de
qualquer afirmacao de conformidade.
"""

__version__ = "1.0.0"

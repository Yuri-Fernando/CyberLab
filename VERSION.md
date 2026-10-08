# VERSION — CyberLab Current Build

**Current Release:** 2.2.0
**Development Version:** 2.4.0-dev (2026-10-07)
**Next Release Target:** 2.4.0

## Build Info

| Propriedade | Valor |
|---|---|
| Versão | 2.4.0-dev |
| Status | DESENVOLVIMENTO VALIDADO LOCALMENTE |
| Branch | codex/release-cyberlab-v2-3 |
| Python mínimo | 3.10 |
| Core test suite (ML security) | 10 testes |
| Core test suite (cloud_security) | 19 testes |
| Legacy E2E suite | 20 testes |
| Ferramentas de scan cloud usadas de fato | Checkov 3.2.459, Trivy 0.75.0 |

## Feature status 2.4

- [x] cloud_security: labs IaC mal configurados (AWS/Azure/GCP)
- [x] scan real Checkov + Trivy contra os 3 labs (sem credencial cloud)
- [x] mapeamento declarativo findings -> NIST CSF 2.0 / ISO 27001:2022 / LGPD
- [x] 19 testes reais (7 de regressão via subprocess, 12 de parsing/mapeamento)
- [ ] Prowler — tentativa de instalação quebrou dependências do ambiente
      (botocore/s3transfer); abandonado, ver cloud_security/README.md
- [ ] ScoutSuite — exige credencial de conta cloud real; não usado
- [ ] Steampipe — exige credencial de conta cloud real; não usado

## Feature status 2.3

- [x] FGSM/PGD white-box PyTorch
- [x] projeção L∞/L2 e métricas padronizadas
- [x] taxonomia black-box com query budget
- [x] gradient masking audit
- [x] benchmark nativo com adapters ART/Foolbox
- [x] FastAPI, autenticação, rate limiting e output minimization
- [x] telemetria minimizada, risk pipeline e incident response
- [x] adapters Evidently/whylogs
- [x] notebooks 11–15
- [x] testes de aceitação determinísticos
- [ ] execução de paridade ART/Foolbox no ambiente local
- [ ] execução Evidently/whylogs no ambiente local
- [ ] model registry, ML-BOM e supply-chain gates

## Dependências

O core está em requirements.txt. Integrações pesadas permanecem opcionais:

- requirements-adversarial.txt: PyTorch, ART, Foolbox e EagerPy;
- requirements-observability.txt: Evidently e whylogs.

Esta separação substitui as afirmações antigas de que ART/Foolbox já eram dependências centrais.

cloud_security/ depende de Checkov e Trivy instalados localmente (não estão
em requirements.txt pois são ferramentas de CLI, não bibliotecas Python
importadas pelo código de produção) — ver cloud_security/README.md para
comandos de instalação e reprodução dos scans.

*Última atualização: 2026-10-07*

# VERSION — CyberLab Current Build

**Current Release:** 2.2.0
**Development Version:** 2.3.0-dev (2026-10-05)
**Next Release Target:** 2.3.0

## Build Info

| Propriedade | Valor |
|---|---|
| Versão | 2.3.0-dev |
| Status | DESENVOLVIMENTO VALIDADO LOCALMENTE |
| Branch | main |
| Python mínimo | 3.10 |
| Core test suite | 10 testes |
| Legacy E2E suite | 20 testes |

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

*Última atualização: 2026-10-05*

<h1 align="center">🛡️ CyberLab</h1>

<p align="center">
  <strong>AI Security, Adversarial ML & MLSecOps Engineering Lab</strong><br>
  Ataque, medição, defesa e operação segura de modelos de Machine Learning
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.3.0--dev-blue" alt="version">
  <img src="https://img.shields.io/badge/python-3.10+-green" alt="python">
  <img src="https://img.shields.io/badge/tests-30%2F30-brightgreen" alt="tests">
  <img src="https://img.shields.io/badge/Ruff-passing-brightgreen" alt="ruff">
  <img src="https://img.shields.io/badge/use-educational-orange" alt="educational use">
</p>

## Visão geral

O CyberLab é um laboratório aplicado de segurança para sistemas de Machine Learning. O projeto nasceu como um ambiente de cibersegurança ofensiva e defensiva e evoluiu para cobrir o ciclo completo de proteção de modelos: ameaças aos dados de treinamento, evasão em inferência, extração, vazamento de privacidade, monitoramento operacional e resposta a incidentes.

A versão 2.3 adiciona um núcleo adversarial PyTorch com gradientes reais, uma taxonomia explícita de ataques black-box, auditoria de gradient masking, uma API de inferência endurecida e um pipeline MLSecOps testável.

> Todo o conteúdo é destinado a estudo e execução controlada com dados sintéticos ou ambientes isolados.

## Problema abordado

Modelos podem apresentar boa accuracy convencional e ainda falhar sob condições adversariais. Uma avaliação defensável precisa responder, com evidência reproduzível:

- o atacante possui labels, scores ou acesso aos gradientes?
- a perturbação respeita realmente a norma e o epsilon definidos?
- a robustez persiste com mais steps, restarts e ataques por transferência?
- drift observado representa mudança legítima ou abuso deliberado?
- a API limita harvesting e reduz a informação devolvida?
- existe fallback, quarantine e rollback quando o modelo é comprometido?

O CyberLab transforma essas perguntas em código, testes, notebooks e métricas.

## Arquitetura

~~~text
DATA / REQUEST
      |
      v
SCHEMA + RANGE VALIDATION
      |
      v
AUTH + QUERY BUDGET + RATE LIMIT
      |
      v
ADVERSARIAL / DRIFT / EXTRACTION SIGNALS
      |
      v
RISK CORRELATION + POLICY
      |
      +-----------+------------+-------------+
      |           |            |             |
    ALLOW      CHALLENGE    FALLBACK     QUARANTINE
      |                                      |
      v                                      v
  INFERENCE                              INCIDENT
      |                                      |
      v                                      v
MINIMIZED OUTPUT                      ROLLBACK / RESTORE
      |
      v
HASHED TELEMETRY + AUDIT
~~~

O CLI, os módulos Python e a API constituem a fonte de verdade. Os notebooks apenas orquestram essas APIs para ensino e reprodução dos experimentos.

## Capacidades implementadas

### Red Team — ataques

| Capacidade | Implementação | Evidência |
|---|---|---|
| FGSM white-box | Autograd PyTorch e gradiente direto da loss | [whitebox_attacks_torch.py](scripts/python/ml_security/whitebox_attacks_torch.py) |
| PGD white-box | Random start, steps iterativos e projeção L∞/L2 | [whitebox_attacks_torch.py](scripts/python/ml_security/whitebox_attacks_torch.py) |
| Gradient estimation | Diferenças finitas sobre scores, corretamente classificada | [adversarial_attacks.py](scripts/python/ml_security/adversarial_attacks.py) |
| Decision-based | Observa somente labels e respeita query budget | [blackbox_attacks.py](scripts/python/ml_security/blackbox_attacks.py) |
| Score-based | Usa probabilidades sem acesso ao modelo interno | [blackbox_attacks.py](scripts/python/ml_security/blackbox_attacks.py) |
| Transfer-based | Treina surrogate e mede fidelity/transfer rate | [blackbox_attacks.py](scripts/python/ml_security/blackbox_attacks.py) |
| Data poisoning | Label flipping e backdoor | [poisoning_attacks.py](scripts/python/ml_security/poisoning_attacks.py) |
| Clean-label poisoning | Feature collision com preservação de labels | [clean_label_poisoning.py](scripts/python/ml_security/clean_label_poisoning.py) |
| Model extraction | Clone por consultas e fidelity | [model_extraction.py](scripts/python/ml_security/model_extraction.py) |
| Privacy attacks | Membership inference e model inversion | [model_extraction.py](scripts/python/ml_security/model_extraction.py), [model_inversion.py](scripts/python/ml_security/model_inversion.py) |

### Blue Team — defesa e avaliação

| Capacidade | Implementação |
|---|---|
| Auditoria de gradient masking | FGSM × PGD, epsilon curve, step curve, restarts, transfer e black-box |
| Adversarial training | Retreino com amostras adversariais |
| Differential privacy | DP-SGD didático com clipping e ruído |
| Watermarking | Evidência de propriedade contra extração |
| Activation clustering | Detecção de agrupamentos associados a poisoning |
| Input anomaly detection | Identificação de entradas fora do comportamento esperado |
| Framework parity | Adapters opcionais para ART e Foolbox |

A auditoria não declara um modelo robusto porque um ataque falhou. Ela agrega sinais independentes e registra quando BPDA ou EOT são necessários.

### MLSecOps — operação segura

- validação de schema, dimensionalidade, finitude e intervalo;
- correlação entre drift, query rate, OOD, suspeita adversarial e extração;
- separação explícita entre drift legítimo e possível ataque;
- estados NORMAL, SUSPICIOUS, DEGRADED, COMPROMISED e ROLLBACK;
- políticas allow, challenge, fallback e quarantine;
- incidentes e rollback auditáveis;
- adapters opcionais para Evidently e whylogs;
- telemetria minimizada, sem persistir vetores crus por padrão.

## API de inferência endurecida

O serviço FastAPI fica em [services/model_api](services/model_api) e falha fechado quando CYBERLAB_API_KEY não está configurada.

Controles implementados:

- autenticação centralizada por dependency;
- comparação constant-time da credencial;
- rate limiting associado à API key autenticada;
- modelos Pydantic estritos e response model explícito;
- TrustedHost configurável;
- output full, rounded ou label-only;
- query diversity e extraction suspicion;
- identificadores UUID e hashes para clientes/entradas;
- documentação OpenAPI desabilitada em produção.

~~~powershell
$env:CYBERLAB_API_KEY = "defina-um-segredo-local"
$env:CYBERLAB_ALLOWED_HOSTS = "localhost,127.0.0.1"
py -3.10 -m uvicorn services.model_api.app:app
~~~

O limiter atual é em memória e foi projetado para o laboratório. Uma implantação horizontal precisa de armazenamento compartilhado e limites adicionais no gateway ou proxy.

## Métricas padronizadas

| Domínio | Métricas |
|---|---|
| Evasion | clean accuracy, robust accuracy, ASR, confidence drop, L2 e L∞ |
| Black-box | query count, queries to success, transfer rate e surrogate fidelity |
| Poisoning | poisoned accuracy, poison fraction, targeted success e backdoor ASR |
| Extraction | clone accuracy, target accuracy, fidelity e efficiency |
| Privacy | attack accuracy, ROC AUC, membership advantage e inversion similarity |
| Drift | drift score, score por feature e alert level |
| MLSecOps | risk score, incident type, action, model version e rollback version |

## Benchmark reproduzível

O benchmark usa o mesmo modelo e o mesmo conjunto de dados para a implementação própria e para os adapters de referência.

Resultado nativo validado localmente:

| Métrica | Valor |
|---|---:|
| Clean accuracy | 1.00 |
| Robust accuracy | 0.25 |
| Attack success rate | 0.75 |
| L2 médio | 0.4243 |
| L∞ médio | 0.3000 |

ART e Foolbox são dependências opcionais. Quando não estão instalados, o relatório registra explicitamente a indisponibilidade em vez de simular paridade.

## Quickstart

Recomendado: Python 3.10.

~~~powershell
git clone https://github.com/Yuri-Fernando/CyberLab.git
cd CyberLab

py -3.10 -m pip install -r requirements.txt
py -3.10 -m pytest tests -q
py -3.10 scripts/test_e2e_ml_security.py
~~~

Dependências opcionais:

~~~powershell
py -3.10 -m pip install -r requirements-adversarial.txt
py -3.10 -m pip install -r requirements-observability.txt
~~~

Execução de um módulo isolado:

~~~powershell
py -3.10 scripts/python/ml_security/differential_privacy.py
py -3.10 scripts/python/ml_security/model_extraction.py
py -3.10 scripts/generate_upgrade_scorecard.py
~~~

## Notebooks

Os notebooks chamam os módulos de produção e foram executados de ponta a ponta:

1. [Evasion white-box: FGSM e PGD](notebooks/11_evasion_fgsm_pgd.ipynb)
2. [Poisoning e backdoor](notebooks/12_poisoning_backdoor.ipynb)
3. [Auditoria de gradient masking](notebooks/13_gradient_masking.ipynb)
4. [MLSecOps e resposta a incidentes](notebooks/14_mlsecops_incident_response.ipynb)
5. [Benchmark ART e Foolbox](notebooks/15_art_foolbox_benchmark.ipynb)

## Validação local

| Verificação | Resultado |
|---|---|
| Testes do upgrade | 10/10 passando |
| Suite E2E histórica | 20/20 passando |
| Ruff nos módulos novos | Aprovado |
| Compileall | Aprovado |
| Notebooks 11–15 | Executados integralmente |
| Serialização dos relatórios | JSON válido |
| Git diff check | Sem erros |

A suíte E2E também foi corrigida para serializar escalares NumPy corretamente no relatório final.

## Estrutura do repositório

~~~text
CyberLab/
├── scripts/
│   ├── python/
│   │   ├── ml_security/       # ataques, defesas, benchmarks e MLSecOps
│   │   ├── synthetic_media/   # voz, imagem, vídeo, texto e forense
│   │   ├── governance/        # NIST AI RMF, ISO 42001 e antifraude
│   │   └── malware/           # simulações educacionais controladas
│   ├── test_e2e_ml_security.py
│   └── generate_upgrade_scorecard.py
├── services/
│   └── model_api/             # API FastAPI endurecida
├── tests/                     # testes determinísticos do upgrade
├── notebooks/                 # trilha clássica + laboratórios 11–15
├── docs/                      # threat models, matrizes e arquitetura
├── results/                   # dashboard versionado; demais outputs ignorados
├── requirements.txt
├── requirements-adversarial.txt
└── requirements-observability.txt
~~~

## Documentação técnica

| Documento | Conteúdo |
|---|---|
| [Fundamentos](docs/00_fundamentals.md) | Diferença entre GAN e Adversarial ML |
| [Threat model](docs/04_ml_security_threat_model.md) | MITRE ATLAS aplicado ao pipeline |
| [OWASP ML Security](docs/07_owasp_ml_security_top10.md) | Riscos e controles |
| [Matriz adversarial](docs/08_adversarial_ml_attack_matrix.md) | Poisoning, backdoor e clean-label |
| [Benchmark](docs/09_framework_benchmark.md) | Comparação from scratch, ART e Foolbox |
| [Gradient masking](docs/10_gradient_masking.md) | Checks de falsa robustez |
| [Arquitetura MLSecOps](docs/11_mlsecops_architecture.md) | Serving, policy, incidentes e rollback |
| [ATLAS × OWASP](docs/14_atlas_owasp_crosswalk.md) | Crosswalk de TTPs, riscos e controles |

## Decisões de segurança

- nenhum segredo é versionado;
- a API não possui credencial padrão;
- autenticação é aplicada antes do rate limit e da inferência;
- o cliente informado no payload não é usado como identidade de segurança;
- payloads crus não entram no log por padrão;
- outputs, modelos, datasets e documentos internos ficam fora do Git;
- integrações opcionais não são apresentadas como validadas sem execução real.

## Limites conhecidos

Ainda não foram validados neste ambiente:

- paridade executável com ART e Foolbox;
- adapters Evidently e whylogs;
- DP-SGD via Opacus;
- execução GPU/CUDA;
- serving distribuído e rate limiter compartilhado;
- Docker, Prometheus/Grafana e cloud MLaaS;
- model registry, assinaturas, proveniência e ML-BOM;
- policy engines OPA/Cedar e aprovação humana para ações críticas.

Esses itens permanecem no roadmap e não são apresentados como capacidades concluídas.

## Roadmap

### v2.3 — núcleo adversarial e MLSecOps

- white-box PyTorch;
- black-box por threat model;
- gradient masking audit;
- API endurecida;
- incident response;
- notebooks e testes reproduzíveis.

### v2.4 — supply chain e governança operacional

- model registry e artifact integrity;
- proveniência, SBOM e ML-BOM;
- storage distribuído para rate limiting;
- security gates de CI/CD;
- HITL e policy engine.

### v2.5 — laboratório avançado

- Opacus e privacy/utility benchmark;
- AutoAttack e RobustBench;
- MLaaS threat lab;
- evidence pack e desafios estruturados.

---

<p align="center">
  <strong>CyberLab</strong><br>
  Segurança de modelos demonstrada com código, métricas e evidências reproduzíveis.
</p>

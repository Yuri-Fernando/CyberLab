# cloud_security — Cloud Security Posture Management (CSPM) educacional

Módulo adicionado na v2.4.0-dev do CyberLab, respondendo ao item #5 (Cyber /
AI Security / Cloud Security) da auditoria de portfólio. Objetivo: labs de
infraestrutura-como-código propositalmente mal configurada, scan estático
real contra esses labs, e mapeamento declarativo dos findings reais para
frameworks de controle.

**Nenhum dos labs abaixo foi ou será aplicado (`terraform apply`) contra uma
conta cloud real. Nenhuma credencial AWS/Azure/GCP é usada neste módulo.**

## Estrutura

```
cloud_security/
├── labs/
│   ├── aws/main.tf      # S3 público, SG aberto, IAM Action:"*", RDS sem encryption
│   ├── azure/main.tf    # Storage público, NSG aberto, Key Vault sem soft-delete
│   └── gcp/main.tf      # GCS público, firewall aberta, SA com roles/owner
├── mapping/
│   ├── framework_mapping.py   # tabelas check_id -> categoria -> NIST/ISO/LGPD
│   └── map_findings.py        # le resultados reais e gera o relatorio mapeado
├── results/
│   ├── checkov_{aws,azure,gcp}.json   # output bruto real do Checkov 3.2.459
│   ├── trivy_{aws,azure,gcp}.json     # output bruto real do Trivy 0.75.0 (config)
│   └── mapped_findings.json           # relatorio consolidado e mapeado
└── README.md (este arquivo)
```

## O que foi rodado de verdade

| Ferramenta | Versão | Modo | Credencial cloud? | Status |
|---|---|---|---|---|
| **Checkov** | 3.2.459 | `checkov -d <lab>` (scan estático de Terraform) | Não | ✅ Rodado contra os 3 labs |
| **Trivy** | 0.75.0 | `trivy config <lab>` (misconfig scanner, mesmo motor usado para IaC) | Não | ✅ Rodado contra os 3 labs |

Ambos rodaram localmente, sem nenhuma chamada de API para AWS/Azure/GCP, e
produziram os JSONs brutos versionados em `results/`. Esses dois scans
somados geraram **104 findings reais** (não simulados) contra os 3 labs.

## O que foi avaliado e descartado como limitação real (não fingido)

- **Prowler**: a versão corrente do Prowler (`prowler-cloud` 5.44.0, PyPI)
  foi avaliada para instalação. A tentativa de instalação neste ambiente
  (Python 3.10 global, compartilhado entre muitos outros projetos do
  usuário) causou um conflito de dependências real: o resolver do pip
  fez upgrade parcial de `botocore`/`s3transfer` perseguindo os requisitos
  do Prowler, não concluiu a instalação do pacote (`prowler-cloud` nunca
  ficou instalado) e deixou o próprio **Checkov** temporariamente quebrado
  (`ImportError: cannot import name 'DocumentModifiedShape'` ao importar
  `boto3`/`botocore`). O ambiente foi restaurado fixando
  `botocore>=1.43.74,<1.44.0` e `s3transfer>=0.19.0,<0.20.0` (os requisitos
  que o `boto3` já instalado declarava), e o Checkov voltou a funcionar
  (verificado re-rodando o scan e comparando o output byte a byte com o
  rodado antes do incidente). Dado o risco real já demonstrado de quebrar
  outras ferramentas deste ambiente compartilhado, a instalação do Prowler
  **não foi retentada**. Prowler não é usado em nenhum resultado deste
  módulo — isto é documentado como limitação conhecida, não fingido como
  uso real.
- **ScoutSuite**: por desenho, o ScoutSuite coleta configuração via API
  real do provedor cloud (precisa de credenciais de uma conta de verdade
  para enumerar recursos) — não tem um modo de scan estático de Terraform
  local. Sem uma conta cloud real disponível neste ambiente, ScoutSuite
  **não foi instalado nem usado**.
- **Steampipe**: os plugins `aws`/`azure`/`gcp` do Steampipe também
  consultam a API real do provedor via credenciais (ele materializa o
  estado *live* da conta como tabelas SQL). Existem plugins do Steampipe
  que leem arquivos locais (e vale investigar em uma iteração futura, ex.
  Steampipe + Powerpipe para compliance-as-code sobre Terraform plan), mas
  isso não foi validado nesta sessão. Para não alegar uso que não foi
  executado de fato, Steampipe **não foi instalado nem usado**.

Esta seção segue a mesma régua de rigor que o `CHANGELOG.md` do CyberLab já
aplica a outras áreas do projeto (ex.: a correção histórica sobre
FGSM/PGD não serem white-box de verdade na versão antiga) — e a mesma regra
da própria auditoria de portfólio: **não alegar ferramenta sem uso real.**

## Como reproduzir os scans

```bash
# Checkov (scan estático, sem credencial)
checkov -d cloud_security/labs/aws -o json --compact
checkov -d cloud_security/labs/azure -o json --compact
checkov -d cloud_security/labs/gcp -o json --compact

# Trivy (misconfig scanner, sem credencial)
trivy config --format json cloud_security/labs/aws
trivy config --format json cloud_security/labs/azure
trivy config --format json cloud_security/labs/gcp

# Gerar/atualizar o relatório mapeado a partir dos resultados em results/
python -m cloud_security.mapping.map_findings
```

## Mapeamento para frameworks — o que é e o que NÃO é

`cloud_security/mapping/framework_mapping.py` mapeia cada finding real (pelo
`check_id` do Checkov ou pelo `ID` do Trivy) para uma de 8 categorias de
misconfig (ex.: `public_storage_exposure`, `excessive_iam_privilege`), e cada
categoria para controles **reais** de:

- **NIST CSF 2.0** — função + categoria das 6 funções oficiais (GOVERN,
  IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER). Ex.: `PR.DS` (Data
  Security), `PR.AA` (Identity Management, Authentication and Access
  Control).
- **ISO/IEC 27001:2022, Anexo A** — controles reais. Ex.: `A.8.24` (Use of
  cryptography), `A.8.20` (Networks security).
- **LGPD** — artigos reais relacionados a segurança de dados pessoais. Ex.:
  Art. 46 (medidas de segurança), Art. 37 (registro de operações de
  tratamento).

Checks sem categoria conhecida (14 dos 104 findings reais coletados)
permanecem no relatório com `mapped: false` e controles vazios — **nunca**
recebem um controle "adivinhado" para preencher a lacuna.

**Isto é um mapeamento declarativo/educacional que acelera a triagem de um
analista de GRC — NÃO é uma certificação, auditoria formal ou atestado de
conformidade com NIST CSF 2.0, ISO/IEC 27001 ou LGPD.** Qualquer afirmação
de conformidade real exige revisão humana, evidências adicionais e, no caso
de ISO 27001, um processo de certificação formal por organismo acreditado.

## Resultados reais (resumo)

A partir de `cloud_security/results/mapped_findings.json` (gerado rodando as
ferramentas de verdade, ver tabela acima):

- **104** findings reais coletados (Checkov + Trivy, 3 clouds).
- **90** mapeados para pelo menos um controle de cada framework.
- **14** sem categoria conhecida, preservados no relatório sem controle
  inventado.
- Categorias mais frequentes: exposição pública de storage, rede aberta ao
  mundo (0.0.0.0/0 em SSH/RDP), IAM/role superprivilegiado, dados em
  repouso sem criptografia.

## Testes

Ver `tests/cloud_security/`:

- `test_lab_misconfig_detection.py` — roda Checkov e Trivy de verdade
  (subprocess) contra os labs. Teste de regressão: se alguém "corrigir"
  um misconfig proposital no Terraform, o check correspondente some dos
  resultados e o teste falha apontando exatamente qual.
- `test_framework_mapping.py` — valida a categorização e os controles
  citados (nenhum código de controle inventado).
- `test_map_findings_report.py` — valida o parsing dos outputs reais
  (Checkov/Trivy) e a consistência do relatório consolidado.

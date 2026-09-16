# CyberLab — Segurança de Cibernética Clássica + Machine Learning

### Laboratório Integrado de Cibersegurança Ofensiva, Defensiva e ML Security

## Status

🟢 **v2.0.0 — Ativo — Projeto de portfólio / Cybersecurity + ML Security**

Laboratório educacional de **segurança cibernética clássica + segurança de machine learning + detecção de fraude por IA**, desenvolvido com Python e Jupyter Notebooks para demonstrar, em ambiente isolado:

- **Cibersegurança Tradicional (v1.0):** Reconhecimento, brute force, simulação de malware, defesa
- **ML Security (NEW v2.0):** Ataques adversariais, data poisoning, adversarial training, detecção de anomalias
- **Synthetic Media Detection (NEW v2.0):** Deepfake, voice cloning, texto gerado por LLM, governança de IA

O projeto integra **ciclo de segurança clássico + ataque/defesa em modelos de ML + detecção de fraude habilitada por IA**.

Todos os experimentos são executados em máquinas virtuais e rede **Host-Only**, sem acesso a sistemas reais ou dados de produção.

### Roadmap
- **v1.0.0 (2026-04-09):** Laboratório de cibersegurança clássica (reconhecimento, brute force, malware, defesa)
- **v2.0.0 (2026-09-16):** Adição de ML Security + Synthetic Media Detection + Governance Framework
- **v2.1 (2026-12-31):** Drift monitoring, response playbooks, casos de uso reais (scoring, fraude)
- **v3.0 (2027-06-30):** Laboratório interativo com VMs, integração cloud (AWS SageMaker, Vertex AI)

---

## Sobre o Projeto

O CyberLab foi estruturado como um laboratório de experimentação para demonstrar como vulnerabilidades e configurações inadequadas podem ser identificadas, exploradas de forma controlada e posteriormente mitigadas.

O fluxo completo é organizado em:

```text
Reconhecimento
      ↓
Preparação
      ↓
Ataque Controlado
      ↓
Simulação de Ameaças
      ↓
Análise
      ↓
Defesa
      ↓
Validação
```

A abordagem permite observar o ciclo completo de **ataque → evidência → mitigação → revalidação**.

---

## Objetivo

Demonstrar, de forma prática e isolada:

* Reconhecimento e enumeração de serviços;
* Testes de força bruta em ambientes autorizados;
* Simulação educacional de malware;
* Análise de logs;
* Geração de inteligência a partir dos resultados;
* Implementação de controles defensivos;
* Reexecução dos cenários após mitigação;
* Avaliação da efetividade das medidas de segurança.

---

# Ciclo de Segurança

## 1. Reconhecimento

Utilização do **Nmap** para:

* Descoberta de hosts;
* Identificação de portas;
* Enumeração de serviços;
* Mapeamento inicial da superfície de ataque.

---

## 2. Preparação

Etapa destinada à organização do ambiente e dos dados utilizados nos testes.

Inclui:

* OSINT controlado;
* Preparação das wordlists;
* Configuração das máquinas virtuais;
* Definição dos parâmetros de teste.

---

## 3. Ataque Controlado

O laboratório contempla testes de força bruta contra serviços presentes no ambiente isolado:

* FTP;
* SMB;
* Aplicação web DVWA.

A ferramenta **Medusa** é utilizada para os testes automatizados de autenticação.

---

## 4. Simulação de Malware

O projeto possui módulos educacionais para simulação controlada de comportamentos associados a malware:

* Ransomware simulado;
* Keylogger simulado.

Esses componentes são destinados exclusivamente ao ambiente de laboratório e à análise do comportamento das ameaças.

---

## 5. Análise

Os resultados das execuções são processados para gerar informações sobre:

* Tentativas de autenticação;
* Eventos relevantes;
* Logs;
* Resultados dos testes;
* Evidências antes e depois das medidas de mitigação.

Os scripts Python realizam parsing e organização dos dados para posterior visualização e análise.

---

## 6. Defesa

Após os testes ofensivos, são implementadas medidas defensivas, incluindo:

* **Fail2ban**;
* Hardening;
* Multi-Factor Authentication (MFA);
* Estratégias de defesa em profundidade.

---

## 7. Validação

Os cenários são executados novamente após a aplicação das medidas defensivas.

```text
Ataque
   ↓
Coleta de evidências
   ↓
Mitigação
   ↓
Novo teste
   ↓
Comparação
```

O objetivo é verificar se os mecanismos implementados alteraram o comportamento observado no ambiente.

---

# Arquitetura do Laboratório

```text
                    ┌─────────────────────┐
                    │      Kali Linux     │
                    │  Estação de Testes  │
                    └──────────┬──────────┘
                               │
                               │ Host-Only Network
                               │
                ┌──────────────┴──────────────┐
                │                             │
                ▼                             ▼
      ┌──────────────────┐         ┌──────────────────┐
      │   Metasploitable │         │       DVWA       │
      │        2         │         │ Web Vulnerable  │
      └──────────────────┘         └──────────────────┘
```

### Componentes

| Componente            | Função                                       |
| --------------------- | -------------------------------------------- |
| **Kali Linux**        | Estação de testes e ferramentas de segurança |
| **Metasploitable 2**  | Ambiente Linux propositalmente vulnerável    |
| **DVWA**              | Aplicação web vulnerável para testes         |
| **VirtualBox**        | Virtualização do laboratório                 |
| **Host-Only Network** | Isolamento da comunicação                    |

---

# Tecnologias

| Categoria           | Tecnologia                     |
| ------------------- | ------------------------------ |
| Linguagem           | Python 3.10+                   |
| Notebooks           | Jupyter                        |
| Network Scanning    | Nmap                           |
| Brute Force         | Medusa                         |
| Criptografia        | Python `cryptography` / Fernet |
| Vulnerable Target   | Metasploitable 2               |
| Web Security Target | DVWA                           |
| Virtualização       | VirtualBox                     |
| Network Isolation   | Host-Only                      |
| Defesa              | Fail2ban · Hardening · MFA     |
| Análise             | Python · JSON · Logs           |

---

# Estrutura do Projeto

```text
cyberlab-ataque-defesa-malware/
│
├── README.md
├── .env.example
├── .gitignore
│
├── notebooks/
│   ├── 0_SETUP.ipynb
│   ├── 1_reconhecimento.ipynb
│   ├── 2_preparacao_ataque.ipynb
│   ├── 3_brute_force_ftp.ipynb
│   ├── 4_brute_force_smb.ipynb
│   ├── 5_brute_force_dvwa.ipynb
│   ├── 6_ransomware_simulado.ipynb
│   ├── 7_keylogger_simulado.ipynb
│   ├── 8_analise_logs.ipynb
│   ├── 9_defesa_mitigacao.ipynb
│   └── 10_validacao_final.ipynb
│
├── scripts/
│   └── python/
│       ├── scanner.py
│       ├── brute_force.py
│       ├── logs_analyzer.py
│       └── malware/
│           ├── ransomware.py
│           └── keylogger.py
│
├── wordlists/
│   ├── ftp_users.txt
│   ├── ftp_passwords.txt
│   ├── smb_users.txt
│   └── common_passwords.txt
│
├── docs/
│   ├── 01_metodologia.md
│   ├── 02_ataques_detalhes.md
│   └── 03_defesa_estrategia.md
│
├── results/
│   ├── logs/
│   └── ...
│
└── images/
```

---

# Como Executar

## Requisitos

* Python 3.10+
* Jupyter Lab
* Nmap
* Medusa
* VirtualBox
* Kali Linux
* Metasploitable 2
* DVWA

---

## 1. Configurar ambiente

Crie o arquivo `.env`:

```bash
cp .env.example .env
```

Configure apenas parâmetros relacionados ao laboratório, como IPs e credenciais de teste.

---

## 2. Instalar dependências

```bash
pip install -r requirements.txt
```

---

## 3. Inicializar Jupyter

```bash
jupyter lab
```

---

# Execução dos Notebooks

Os notebooks foram organizados para execução sequencial:

### 0 — Setup

```text
0_SETUP.ipynb
```

Validação inicial do ambiente.

### 1 — Reconhecimento

```text
1_reconhecimento.ipynb
```

Nmap e enumeração dos serviços.

### 2 — Preparação

```text
2_preparacao_ataque.ipynb
```

Preparação dos cenários e wordlists.

### 3–5 — Ataques de força bruta

```text
3_brute_force_ftp.ipynb
4_brute_force_smb.ipynb
5_brute_force_dvwa.ipynb
```

Testes controlados contra os alvos do laboratório.

### 6–7 — Simulações

```text
6_ransomware_simulado.ipynb
7_keylogger_simulado.ipynb
```

Simulações educacionais de comportamento de malware.

### 8 — Análise

```text
8_analise_logs.ipynb
```

Processamento de logs e geração de indicadores.

### 9 — Defesa

```text
9_defesa_mitigacao.ipynb
```

Implementação dos mecanismos de mitigação.

### 10 — Validação

```text
10_validacao_final.ipynb
```

Reexecução dos testes com os controles de segurança ativos.

---

# Saídas

Durante as execuções, o diretório `results/` pode receber:

* Resultados dos testes;
* Arquivos JSON;
* Logs de autenticação;
* Dados de análise;
* Dashboards HTML;
* Relatórios de validação;
* Evidências produzidas pelos notebooks.

A estrutura exata dos arquivos depende dos cenários executados.

---

# Documentação

### Metodologia

[`docs/01_metodologia.md`](docs/01_metodologia.md)

Apresenta o ciclo completo:

```text
Reconhecimento
→ Enumeração
→ Ataque
→ Análise
→ Defesa
→ Validação
```

### Ataques

[`docs/02_ataques_detalhes.md`](docs/02_ataques_detalhes.md)

Documenta os cenários de teste implementados.

### Defesa

[`docs/03_defesa_estrategia.md`](docs/03_defesa_estrategia.md)

Apresenta as estratégias de mitigação utilizadas.

---

# O que este projeto demonstra

* Reconhecimento e enumeração de redes;
* Network Security;
* Pentest em ambiente controlado;
* Automação de testes com Python;
* Uso de Nmap;
* Testes de autenticação com Medusa;
* Análise de logs;
* Simulação controlada de ameaças;
* Hardening;
* Fail2ban;
* MFA;
* Defesa em profundidade;
* Validação pós-mitigação;
* Organização de experimentos em Jupyter;
* Automação de análises de segurança.

---

# Limitações

* Os experimentos são executados exclusivamente em ambiente virtualizado e isolado;
* Os alvos utilizados são ambientes intencionalmente vulneráveis;
* Os resultados não representam comportamento de sistemas corporativos reais;
* As simulações de ransomware e keylogger são destinadas exclusivamente ao laboratório;
* A eficácia das mitigações depende da configuração específica do ambiente;
* O projeto não constitui uma solução IDS, SIEM ou plataforma corporativa de segurança.

---

# Melhorias Futuras

* Automação completa do provisionamento das VMs;
* Geração automática de relatórios de segurança;
* Dashboard consolidado dos experimentos;
* Integração de novas ferramentas de análise;
* Correlação automática de eventos;
* Detecção comportamental baseada em Machine Learning;
* Integração experimental com SIEM;
* Automação das etapas de validação;
* Expansão da cobertura de cenários ofensivos e defensivos.

---

# Segurança e Uso Responsável

Este projeto possui finalidade **educacional e de pesquisa aplicada em cibersegurança**.

Todos os testes devem ocorrer exclusivamente:

* em máquinas próprias;
* em ambientes virtualizados;
* em laboratórios autorizados;
* ou em sistemas para os quais exista autorização explícita.

**Não execute os notebooks de ataque ou os scripts de simulação contra sistemas de terceiros.**

---

# Status do Projeto

🟢 **Concluído**

O laboratório possui o ciclo completo implementado:

* ✅ Reconhecimento;
* ✅ Enumeração;
* ✅ Preparação;
* ✅ Testes de força bruta;
* ✅ Simulações educacionais de malware;
* ✅ Análise de logs;
* ✅ Implementação de defesas;
* ✅ Hardening;
* ✅ Fail2ban;
* ✅ MFA;
* ✅ Revalidação dos cenários;
* ✅ Documentação;
* ✅ Notebooks organizados por etapa.

O projeto permanece disponível como **laboratório de pesquisa e referência técnica** para experimentação com segurança ofensiva, defesa e automação de análises.

---

# Referências

### Ferramentas

* [Nmap](https://nmap.org/)
* [Medusa](https://github.com/jmk-foofus/medusa)
* [Metasploitable 2](https://sourceforge.net/projects/metasploitable/)
* [DVWA](https://github.com/digininja/DVWA)
* [Jupyter](https://jupyter.org/)
* [VirtualBox](https://www.virtualbox.org/)

---

# Licença

MIT License.

---

# Autor

**Yuri Fernando Dubbern**

AI/ML Engineer · Cybersecurity · Automation · Python · Data

[LinkedIn](https://www.linkedin.com/in/yuridubbern) · [GitHub](https://github.com/Yuri-Fernando) · [Lattes](http://lattes.cnpq.br/7151392692642166) · [Linktree](https://linktr.ee/yuri.f.dubbern)

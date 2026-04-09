# CyberLab: Ataque, Defesa e Simulação de Malware

Laboratório educacional de segurança ofensiva e defensiva implementado em Jupyter notebooks com Python.

## Objetivo

Demonstrar o ciclo completo de segurança cibernética através de:

- Reconhecimento e enumeração de serviços (Nmap)
- Ataques de força bruta contra FTP, SMB e aplicações web
- Simulação educacional de malware (ransomware, keylogger)
- Análise de vulnerabilidades e geração de inteligência
- Implementação de defesas (fail2ban, hardening, MFA)
- Validação e re-teste de mitigações

Todos os testes ocorrem em ambiente isolado (VMs virtualizadas, rede Host-Only) sem dados reais.

## Estrutura

Este projeto implementa uma cadeia completa de pentest:

1. Reconhecimento (Nmap, enumeração de serviços)
2. Preparação (OSINT, geração de wordlists)
3. Ataque (força bruta contra FTP, SMB, web)
4. Simulação de malware (ransomware, keylogger educacionais)
5. Análise (parsing de logs, dashboard)
6. Defesa (fail2ban, hardening, MFA)
7. Validação (re-teste com mitigações ativas)

## Tecnologias

| Componente | Tecnologia |
|-----------|-----------|
| Escaneamento | Nmap |
| Força bruta | Medusa |
| Análise | Python 3.10+ |
| Criptografia | cryptography (Fernet) |
| Notebooks | Jupyter |
| Target (desenvolvimento) | Metasploitable 2, DVWA |
| Isolamento | VirtualBox, rede Host-Only |

## Arquivos

Estrutura do projeto:

```
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
├── scripts/python/
│   ├── scanner.py
│   ├── brute_force.py
│   ├── logs_analyzer.py
│   └── malware/
│       ├── ransomware.py
│       └── keylogger.py
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
├── results/ (gerado durante execução)
│   ├── logs/
│   └── (JSON/reports gerados pelos notebooks)
│
└── images/ (para screenshots opcionais)
```

---

## Execução

Requisitos:
- Python 3.10+
- Jupyter Lab
- Nmap e Medusa instalados (para testes reais)

Setup:

```bash
cp .env.example .env
# Editar .env com IPs e credenciais de teste

pip install -r requirements.txt

jupyter lab
```

Execução sequencial via notebooks:

1. 0_SETUP.ipynb - Validar ambiente
2. 1_reconhecimento.ipynb - Scan inicial
3. 2_preparacao_ataque.ipynb - OSINT e wordlists
4. 3-5_brute_force_*.ipynb - Testes de força bruta
5. 6-7_malware_*.ipynb - Simulações educacionais
6. 8_analise_logs.ipynb - Gerar análise e dashboard
7. 9_defesa_mitigacao.ipynb - Implementar defesas
8. 10_validacao_final.ipynb - Re-testar e validar

Dados serão gerados automaticamente em /results durante execução dos notebooks.

## Escopo

Ambiente isolado (Host-Only network) com VMs virtualizadas:
- Metasploitable 2: Sistema Linux com serviços vulneráveis (FTP, SMB, SSH)
- DVWA: Aplicação web propositalmente vulnerável
- Kali Linux: Estação de teste com ferramentas de pentest

Nenhum acesso a sistemas reais ou dados produção.

## Saídas

Durante execução dos notebooks, os seguintes dados são gerados em /results:

- Arquivos JSON com resultados de ataques
- Logs de tentativas de força bruta
- Dashboard HTML com análise
- Relatórios de validação pós-defesa

Estes arquivos refletem o que cada script Python gera e são consumidos pelos notebooks.

## Documentação

Referência técnica em docs/:

- 01_metodologia.md - Ciclo de vida completo (recon, enum, ataque, análise, defesa, validação)
- 02_ataques_detalhes.md - Detalhes técnicos de cada ataque
- 03_defesa_estrategia.md - Defense in depth, implementações de mitigação

## Referências

Ferramentas utilizadas:

- Nmap: Escaneamento de portas e enumeração de serviços
- Medusa: Força bruta paralela contra múltiplos serviços
- Metasploitable 2: Sistema Linux vulnerable para testes
- DVWA: Aplicação web vulnerable
- Python 3.10+: Scripts de análise e simulação
- Jupyter: Notebooks para documentação interativa

## Nota

Este projeto é educacional. Toda execução ocorre em ambiente isolado sem acesso a sistemas reais.🚀

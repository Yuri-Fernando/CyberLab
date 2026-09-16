# CHANGELOG — CyberLab

Todas as alterações significativas neste projeto serão documentadas neste arquivo.

## [2.0.0] — Unreleased (2026-09-16+)

### 🎯 Nova Seção: ML Security & Adversarial ML

#### Adicionado
- **Notebook 11:** ML Security - Poisoning Attacks (label flipping, backdoors)
- **Notebook 12:** ML Security - Adversarial Training & Defense
- **Notebook 13:** Synthetic Media Detection - Text Analysis
- **Notebook 14:** Deepfake Detection - Video/Audio Analysis
- **Módulo `ml_security/`:** Classes para ataques e defesas de ML
- **Módulo `synthetic_media/`:** Detectores de mídia sintética
- **Documentação:** MITRE ATLAS threat model para ML
- **Dashboard ML Security:** Análise de ataques adversariais
- **Dashboard Synthetic Media:** Detecção de deepfakes

#### Mudanças (Breaking)
- `requirements.txt`: Adicionado ART (Adversarial Robustness Toolbox), Foolbox, librosa
- Estrutura de notebooks renumerada (de 10 fases para 14)

#### Corrigido
- N/A (primeira release v2.0)

### Contexto de Motivação (v2.0)
O projeto original focava em cibersegurança ofensiva/defensiva clássica (brute force, malware). O update v2.0 responde a uma mudança crítica na indústria: **os modelos de IA agora são alvo de ataques especializados**. Este update posiciona CyberLab como referência educacional para:

1. **Red Teaming de Modelos:** Como envenenar dados de treino e gerar ataques adversariais
2. **Detecção de Fraude por IA:** Identificar deepfakes, voice cloning, texto gerado por LLM
3. **Governança de IA:** Implementar monitoramento de drift e resposta a incidente de modelo comprometido

Alinhado com vagas sênior em ML Security e Forense Digital com IA.

---

## [1.0.0] — 2026-04-09

### Adicionado
- Estrutura base de laboratório de cibersegurança
- 10 notebooks Jupyter (reconhecimento, ataques, defesa)
- Módulos Python: scanner, brute_force, logs_analyzer
- Simulação segura de ransomware e keylogger
- Documentação técnica (3 docs de metodologia)
- .env.example e .gitignore
- wordlists básicas para teste

### Características
- Ciclo completo: Recon → Enum → Attack → Analysis → Defense → Validation
- Ambiente isolado (VirtualBox, Host-Only network)
- Nenhum acesso a sistemas reais
- Documentação profissional estilo portfólio

---

## Convenção de Versionamento

**Padrão:** `MAJOR.MINOR.PATCH`

- **MAJOR:** Novo módulo temático (ex: v1→v2 = Ofensiva/Defensiva → ML Security)
- **MINOR:** Features dentro de um módulo
- **PATCH:** Bugfixes e refinamentos

**Git Tags:** Cada release terá tag `v{VERSION}` no repositório.

---

## Como Contribuir

1. Trabalhe em branch `dev/v2.0.0`
2. Documente mudanças neste arquivo ANTES de commit
3. Use conventional commits: `feat:`, `fix:`, `docs:`, `chore:`
4. Tag ao finalizar release: `git tag -a v2.0.0`

---

*Última Atualização: 2026-09-16*

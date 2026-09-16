# CHANGELOG — CyberLab

Todas as alterações significativas neste projeto serão documentadas neste arquivo.

## [2.1.0] — Released (2026-09-16)

### 🚀 ML Security completo, testado e com dashboard

#### Adicionado
- **`differential_privacy.py`**: DP-SGD implementado do zero (per-example gradient
  clipping + ruído gaussiano), com medição do trade-off ε (privacidade) vs acurácia.
- **`model_inversion.py`**: Model inversion por otimização black-box; mede privacy
  leakage via similaridade cosseno com a média real da classe.
- **`adversarial_attacks.py`**: FGSM, PGD e ataque black-box por queries (agora com
  correção de bug de shape que impedia a avaliação de robustez).
- **`audio_detector.py`**: Detecção de voice cloning com **MFCC/librosa reais**
  (spectral centroid, bandwidth, ZCR) — discrimina voz humana vs sintética.
- **`image_forensics.py`**: **ELA (Error Level Analysis) localizado** + análise de
  ruído + EXIF para detectar splicing/manipulação de imagem.
- **`governance/ai_risk_assessment.py`**: Assessment executável de **NIST AI RMF**
  e **ISO/IEC 42001** com relatório de maturidade priorizado.
- **`test_e2e_ml_security.py`**: Suite E2E reescrita — **12/12 testes passando**,
  determinística, cobrindo todos os módulos.
- **`generate_dashboard.py`**: Dashboard visual consolidado (PNG).

#### Corrigido
- Bug crítico no teste E2E: path de import apontava para `scripts/` em vez de
  `scripts/python/` — os testes nunca rodavam. Agora corrigido.
- FGSM/PGD: `model.predict([X[i:i+1]])` gerava array 3D. Corrigido.
- Drift detector: métrica MAPE dividia por média ~0 em dados centrados (falso
  positivo). Substituída por effect size padronizado (robusto).

#### Mudanças
- `requirements.txt`: limpo para conter apenas dependências realmente usadas e
  instaláveis (removido `evidently-ai`, que não existe no PyPI com esse nome, e
  libs pesadas não utilizadas). Bibliotecas de mercado citadas como referência.

---

## [2.0.0] — Released (2026-09-16)

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

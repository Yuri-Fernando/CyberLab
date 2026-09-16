# VERSION — CyberLab Current Build

**Current Release:** 1.0.0  
**Development Version:** 2.0.0-dev (09-16-2026)  
**Next Release Target:** 2.0.0 (2026-09-30)

---

## Build Info

| Propriedade | Valor |
|-----------|-------|
| **Versão Principal** | 2 |
| **Versão Minor** | 0 |
| **Patch** | 0-dev |
| **Status** | DESENVOLVIMENTO |
| **Branch Principal** | main |
| **Branch Desenvolvimento** | v2.0.0-dev |
| **Data de Início** | 2026-09-16 |
| **Python Mínimo** | 3.10 |

---

## Histórico de Releases

### v1.0.0 (2026-04-09) — Laboratório Clássico
- Cibersegurança ofensiva/defensiva tradicional
- 10 notebooks, 6 módulos Python
- ~3.500 linhas de código

### v2.0.0-dev (2026-09-16+) — ML Security & Synthetic Media
- Novas disciplinas: Adversarial ML, Deepfake Detection
- 4 novos notebooks (11-14)
- 3 novos módulos Python (ml_security, synthetic_media, governance)
- Integração de ART, Foolbox, librosa

### v2.0.0 (Planejado: 2026-09-30) — Primeira Release ML
- Estável em produção
- Documentação completa
- 14 notebooks, 9 módulos Python
- ~8.000 linhas de código

---

## Feature Status (v2.0.0-dev)

### ML Security
- [ ] Poisoning Attack Simulator
- [ ] Adversarial Training Module
- [ ] Model Extraction Detection
- [ ] Adversarial Evasion (FGSM, PGD)

### Synthetic Media Detection
- [ ] Text Detector (perplexity, estilometria)
- [ ] Audio Detector (voice cloning)
- [ ] Deepfake Detector (facial artifacts)

### Governance & Monitoring
- [ ] Risk Assessment Dashboard
- [ ] Model Drift Monitoring
- [ ] Incident Response Playbook

---

## Dependências Críticas

### Novas (v2.0.0)
```
adversarial-robustness-toolbox>=1.15.0  # ART
foolbox>=3.6.0                          # Adversarial attacks
librosa>=0.10.0                         # Audio analysis
evidently-ai>=0.4.0                     # Drift monitoring
scikit-learn>=1.3.0                     # ML baseline
torch>=2.0.0                            # PyTorch
```

### Mantidas (v1.0.0)
```
jupyter>=1.0.0
numpy>=1.23.0
pandas>=1.5.0
cryptography>=39.0.0
paramiko>=3.0.0
requests>=2.28.0
```

---

*Última Atualização: 2026-09-16*

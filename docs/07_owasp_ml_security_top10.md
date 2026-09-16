# OWASP ML Security Top 10

**Versão:** 1.0  
**Data:** 2026-09-16  
**Referência:** https://owasp.org/www-project-machine-learning-security-top-10/

Implementação dos 10 principais riscos de segurança em sistemas de ML.

---

## 1. Data Poisoning (ML01)

**Risco:** Dados de treino são modificados para fazer modelo aprender comportamento malicioso.

**Implementado em CyberLab:**
- ✅ Label flipping indiscriminado
- ✅ Label flipping direcionado
- ✅ Backdoor attacks
- ✅ Clean-label poisoning (conceitual)

**Arquivo:** `ml_security/poisoning_attacks.py`

**Impacto:** Modelo aprende a tomar decisões erradas.  
**Exemplo:** Modelo de scoring de crédito aprova 100% de fraudes após poisoning.

---

## 2. Model Inversion (ML02)

**Risco:** Atacante reconstrói dados de treino a partir do modelo.

**Implementado em CyberLab:**
- ✅ Membership Inference Attack (proxy para inversion)
- ❓ Model Inversion completo (gradientes inversos)

**Arquivo:** `ml_security/model_extraction.py`

**Impacto:** Vazamento de dados privados de treino (PII, dados sensíveis).  
**Defesa:** Differential Privacy em treino.

---

## 3. Model Extraction (ML03)

**Risco:** Modelo proprietário é clonado via queries a API.

**Implementado em CyberLab:**
- ✅ Model Extraction via queries
- ✅ Avaliação de sucesso (agreement rate)
- ✅ Detecção via logging de queries

**Arquivo:** `ml_security/model_extraction.py`

**Impacto:** Roubo de propriedade intelectual.  
**Defesa:** Rate limiting, logging de queries, watermarking.

---

## 4. Adversarial Examples (ML04)

**Risco:** Exemplos levemente perturbados enganam modelo.

**Implementado em CyberLab:**
- ✅ FGSM (white-box, rápido)
- ✅ PGD (white-box, iterativo, potente)
- ✅ Black-box query-based attacks
- ✅ Transferability entre modelos

**Arquivo:** `ml_security/adversarial_attacks.py`

**Impacto:** Erro de classificação em tempo de inferência.  
**Defesa:** Adversarial training, defensive distillation, input anomaly detection.

---

## 5. Membership Inference (ML05)

**Risco:** Descobrir se um exemplo foi usado no treino.

**Implementado em CyberLab:**
- ✅ Confidence-based membership inference
- ✅ Avaliação de risco de privacidade
- ✅ Attack model training

**Arquivo:** `ml_security/model_extraction.py`

**Impacto:** Vazamento de informação sobre dataset de treino.  
**Defesa:** Differential privacy, regularização.

---

## 6. Performance Degradation (ML06)

**Risco:** Modelo degrada após deployment (drift, poisoning).

**Implementado em CyberLab:**
- ✅ Drift detection (data drift)
- ✅ Malicious drift detection
- ✅ Automatic alerts e incident response

**Arquivo:** `ml_security/mlsecops_monitoring.py`

**Impacto:** Modelo toma decisões incorretas em produção.  
**Defesa:** Continuous monitoring, drift detection, retraining.

---

## 7. API Abuse (ML07)

**Risco:** APIs de modelo são abusadas (fuzzing, extraction, DoS).

**Implementado em CyberLab:**
- ✅ Query-based model extraction (proxy para API abuse)
- ✅ Anomaly detection em padrões de queries
- ✅ Rate limiting framework

**Arquivo:** `ml_security/mlsecops_monitoring.py`

**Impacto:** Indisponibilidade de serviço, extração de modelo.  
**Defesa:** Rate limiting, authentication, query logging, anomaly detection.

---

## 8. Feedback Loop Poisoning (ML08)

**Risco:** Modelo usa seu próprio output para retreinar (amplificação de erro).

**Implementado em CyberLab:**
- ✅ Conceitual (documentation)
- ❓ Implementação prática (requer RLHF)

**Arquivo:** `docs/04_ml_security_threat_model.md`

**Impacto:** Degradação progressiva do modelo ao longo do tempo.  
**Defesa:** Human-in-the-loop validation, output filtering.

---

## 9. Model Poisoning via Supply Chain (ML09)

**Risco:** Modelo pré-treinado (ex: BERT, GPT) contém backdoor.

**Implementado em CyberLab:**
- ✅ Backdoor attack (conceitual)
- ❓ Supply chain validation framework

**Arquivo:** `ml_security/poisoning_attacks.py`

**Impacto:** Qualquer aplicativo usando modelo é comprometido.  
**Defesa:** Model inspection, watermarking, proveniência.

---

## 10. Transfer Learning Risks (ML10)

**Risco:** Features de transfer learning contêm vulnerabilidades.

**Implementado em CyberLab:**
- ✅ Transferability de adversarial examples
- ❓ Feature-level poisoning (futuro)

**Arquivo:** `ml_security/adversarial_attacks.py`

**Impacto:** Modelo fine-tuned herda vulnerabilidades do base model.  
**Defesa:** Fine-tuning com dados validados, robustness testing.

---

## Matriz de Implementação

| # | Risco | Status | Arquivo | Defesa Status |
|---|-------|--------|---------|---------------|
| 1 | Data Poisoning | ✅ Completo | poisoning_attacks.py | ✅ adversarial_defense.py |
| 2 | Model Inversion | ✅ Completo | model_inversion.py | ✅ differential_privacy.py (DP-SGD) |
| 3 | Model Extraction | ✅ Completo | model_extraction.py | ✅ Logging, rate limit |
| 4 | Adversarial Examples | ✅ Completo | adversarial_attacks.py (FGSM/PGD) | ✅ adversarial_defense.py |
| 5 | Membership Inference | ✅ Completo | model_extraction.py | ✅ differential_privacy.py (DP-SGD) |
| 6 | Performance Degradation | ✅ Completo | mlsecops_monitoring.py | ✅ Drift detection |
| 7 | API Abuse | 🟡 Parcial | mlsecops_monitoring.py | ✅ Rate limiting |
| 8 | Feedback Loop Poisoning | 🟡 Conceitual | docs/ | ❓ |
| 9 | Model Poisoning (Supply Chain) | ✅ Completo | clean_label_poisoning.py | ✅ model_watermarking.py (activation clustering) |
| 10 | Transfer Learning Risks | ✅ Completo | adversarial_transferability.py | ✅ robustness benchmark |

---

## Roadmap v2.1

- [ ] Model Inversion completo (gradiente reverso)
- [ ] Feedback loop poisoning demo
- [ ] Supply chain validation framework
- [ ] Feature-level poisoning attacks
- [ ] Differential Privacy (DP-SGD) implementado
- [ ] Watermarking de modelos
- [ ] NIST AI RMF governance framework

---

*CyberLab v2.0 — OWASP ML Security Top 10 Implementation*

# ML Security Threat Model — MITRE ATLAS

**Versão:** 2.0.0  
**Data:** 2026-09-16  
**Foco:** Segurança de modelos preditivos contra ataques adversariais

---

## 📋 Contexto

O pipeline de ML é uma superfície de ataque tão crítica quanto aplicações web tradicionais, mas frequentemente negligenciada. Este documento mapeia ameaças específicas usando **MITRE ATLAS** (Adversarial Threat Landscape for Artificial-Intelligence Systems).

**MITRE ATLAS** define 5 fases do ciclo de vida de um ataque:

| Fase | Descrição | Exemplos |
|------|-----------|----------|
| **Reconnaissance** | Coleta de informações sobre o modelo | OSINT, API fuzzing, model querying |
| **Resource Development** | Preparação do ataque | Geração de adversarial examples, crafting |
| **ML Attack Staging** | Staging do ataque | Preparar dados envenenados |
| **Attack & Exfiltration** | Execução do ataque | Envenenar dados, exfiltrar modelo |
| **Post-Compromise** | Pós-ataque | Manutenção de acesso, cobertura |

---

## 🎯 Ataques Implementados Neste Projeto

### 1. Data Poisoning (ML Attack Staging + Execution)

#### Label Flipping Indiscriminado
```
Objetivo: Degradar performance geral do modelo
Método: Inverter labels aleatoriamente de X% dos dados de treino
Impacto: Reduz acurácia de ~95% para ~75% com 10% de envenenamento
Defesa: Outlier detection, data sanitization
```

**Como funciona:**
```
Dados originais: [classe A, classe A, classe B, classe B]
Após poisoning:   [classe B, classe A, classe A, classe B]  ← 25% invertidos
```

#### Label Flipping Direcionado
```
Objetivo: Fazer modelo misclassificar classe específica
Método: Inverter APENAS labels de uma classe alvo
Impacto: Classe alvo tem recall ~0%, outras classes preservadas
Defesa: Per-class detection, attention mechanisms
```

**Caso Real:** Ataque a detector de fraude — inverte labels de transações fraudulentas para "legítimo".

#### Backdoor Attack (Trojan)
```
Objetivo: Criar comportamento secreto ativado por padrão específico
Método: Injetar trigger pattern em subset de dados, fazer label apontar para classe backdoor
Impacto: Modelo se comporta normalmente, mas responde a trigger com comportamento anômalo
Defesa: Activation clustering, neural cleanse
```

**Exemplo:**
```
Padrão secreto: Última feature = 99.9
Quando modelo vê 99.9 na última feature → classifica como "Admin Access" (classe backdoor)
Nem que a entrada seja qualquer coisa mais
```

---

### 2. Evasion Attacks (ATLAS: Attack & Exfiltration)

Ataques em tempo de INFERÊNCIA: adicionar perturbações adversariais a exemplos de teste para enganar o modelo.

#### FGSM (Fast Gradient Sign Method)
```
White-box attack que move exemplos na direção de maior gradiente
Fórmula: x_adv = x + ε * sign(∇_x L(x, y))
Impacto: Perturba imagem de forma imperceptível, degrada classificador
```

#### PGD (Projected Gradient Descent)
```
Versão iterativa de FGSM
Mais potente, mas mais lento
Projeta no espaço de perturbações permitidas após cada iteração
```

---

### 3. Model Extraction (ATLAS: Reconnaissance + Exfiltration)

Clonar modelo proprietário através de queries:
```
1. Atacante chama API do modelo (MLaaS)
2. Extrai predições em larga escala
3. Treina modelo local que imita o original
4. Roubo de propriedade intelectual
```

**Defesa:**
- Rate limiting
- Logging de queries
- Detecção de padrões de extraction
- API access control

---

### 4. Model Inversion (ATLAS: Exfiltration)

Reconstruir dados de treino a partir do modelo:
```
Objetivo: Recuperar exemplos de treino (dados sensíveis)
Método: Otimizar entrada que maximize probabilidade de uma classe
Impacto: Vazamento de dados privados
```

---

## 🛡️ Defesas Implementadas

### Adversarial Training
```
Treinar modelo com dados adversariais misturados com dados limpos
Aumenta robustez contra ataques evasion
Trade-off: Pequena redução em acurácia normal (2-3%)
```

### Defensive Distillation
```
Usar modelo grande ("teacher") para treinar modelo menor ("student")
Suaviza superfície de decisão, reduz sensibilidade a perturbações pequenas
```

### Input Validation & Anomaly Detection
```
Detectar exemplos fora-de-distribuição (adversariais)
Usar dropout, ensemble methods, uncertainty quantification
```

### Differential Privacy (DP)
```
Adicionar ruído à gradiente durante treino
DP-SGD: Cada passo de gradiente é clipeado e ruído é adicionado
Defende contra: Model inversion, membership inference
```

---

## 📊 Framework Mapping

### OWASP Machine Learning Top 10 ↔ MITRE ATLAS

| OWASP ML | Risco | ATLAS Fase | Controle |
|----------|-------|-----------|----------|
| ML01 | Poisoning de dados treino | ML Attack Staging | Data sanitization, outlier detection |
| ML02 | Evasão em produção | Attack/Exfiltration | Adversarial training, input validation |
| ML03 | Extração de modelo | Reconnaissance/Exfiltration | Rate limiting, query logging |
| ML04 | Inversão de modelo | Exfiltration | DP, gradient clipping |
| ML05 | Degradação de performance | Attack | Monitoring, drift detection |
| ML06 | API abuse | Reconnaissance | Authentication, rate limits |
| ML07 | Envenenamento de feedback | Attack Staging | Feedback validation |
| ML08 | Vazamento de métricas | Reconnaissance | Access control |
| ML09 | Modelo fora-de-especificação | Post-Compromise | Testing, monitoring |
| ML10 | Privacidade de treino | Exfiltration | Differential privacy, access control |

---

## 🔍 Indicadores de Ataque (IoCs)

### IoC de Data Poisoning
- Redução abrupta de acurácia
- Padrão de erro concentrado em classes específicas
- Comportamento anômalo com triggering específico
- Discrepância entre treino/validação Loss

### IoC de Model Extraction
- Padrão de queries: scanning sistemático do espaço de entrada
- Alta frequência de queries de baixa confiança
- Reconstituição de decision boundary
- Queries similares ao conjunto de treino

### IoC de Evasion
- Exemplos com gradientes extremos
- Perturbações em features específicas
- Clustering de misclassifications
- Baixa confiança em exemplos adversariais

---

## 📈 Métricas de Robustez

```
Adversarial Robustness = min{ε : ∃x' : ||x' - x||_p ≤ ε, model(x') ≠ model(x)}
```

**Interpretação:** Qual é a perturbação mínima necessária para enganar o modelo?

**Benchmark:**
- Modelo não-robusto: ε ~ 0.01-0.05 (perturbação imperceptível)
- Modelo robusto: ε ~ 0.3+ (perturbação óbvia)

---

## 🎓 Como Este Projeto Aplica ATLAS

Este projeto implementa os ataques **Fases 1-4** de MITRE ATLAS em ambiente isolado:

1. **Reconnaissance** → Model querying, OSINT
2. **Resource Development** → Geração de exemplos adversariais com FGSM/PGD
3. **ML Attack Staging** → Preparação de dados envenenados
4. **Attack & Exfiltration** → Execução de poisoning, extraction, evasion
5. **Post-Compromise** (Demo) → Manutenção de backdoor, detecção

**Defesas Demonstradas:**
- Adversarial training
- Drift monitoring
- Input validation
- Differential privacy

---

## 📚 Referências

- MITRE ATLAS: https://atlas.mitre.org
- OWASP ML Top 10: https://owasp.org/www-project-machine-learning-security-top-10/
- Goodfellow et al. "Explaining and Harnessing Adversarial Examples" (ICLR 2015)
- Carlini & Wagner "Towards Evaluating the Robustness of Neural Networks" (S&P 2017)
- IBM ART (Adversarial Robustness Toolbox): https://github.com/Trusted-AI/adversarial-robustness-toolbox

---

*CyberLab v2.0 — ML Security Documentation*

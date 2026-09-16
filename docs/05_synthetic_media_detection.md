# Synthetic Media Detection — Deepfake, Voice Cloning, AI-Generated Text

**Versão:** 2.0.0  
**Data:** 2026-09-16  
**Foco:** Detecção técnica de conteúdo gerado por IA generativa

---

## 🎬 Contexto: A Ameaça Habilitada por IA

Ferramentas comerciais de síntese tornaram deepfakes, voice cloning e texto gerado por IA **acessíveis e escalonáveis**:

| Ferramenta | O que faz | Custo |
|-----------|----------|-------|
| **ElevenLabs** | Voice cloning natural | $11/mês |
| **DeepFaceLab** | Deepfake de vídeo | Grátis (open source) |
| **Stable Diffusion** | Geração de imagem IA | Grátis |
| **GPT-4/Claude** | Texto gerado por LLM | API |

**Impacto Real:**
- Caso Arup (2023): Deepfake de CEO em videochamada → $25M transferidos
- LastPass (2023): Voice cloning do CEO em vishing → acesso a cofre de senhas
- Phishing 2024: 80% dos emails phishing agora incluem componente de IA

---

## 🔊 1. Voice Cloning Detection

### Análise Espectral com MFCC
```
Mel-Frequency Cepstral Coefficients = compressão perceptual do áudio
Voz humana tem padrões naturais em MFCC
Voz sintética tem artefatos detectos (robótica, repetições)
```

**Features para detectar síntese:**
- Coeficientes MFCC com padrão anormal
- Ausência de micro-variações naturais
- Picos anormais em frequências específicas
- Latência entre palavras artificial

### Anti-Spoofing com ASVspoof
```
Sistema treinado especificamente para distinguir voz real de sintética
Datasets: VoxCeleb (real), AASIST trained models
```

### Callback Verification
```
Defesa organizacional: ligar de volta para número conhecido
Simples mas efetivo contra voice cloning
```

---

## 🎭 2. Deepfake Detection

### Artefatos Visuais
```
Detecção baseada em imperfeições que modelos generativos deixam:

1. Eye Blinking:
   - Deepfakes frequentemente perdem piscar de olhos
   - Real humans piscam ~17 vezes por minuto
   - Deepfake pode não ter piscar ou ter padrão anômalo

2. Facial Landmarks:
   - Músculos faciais mal sincronizados
   - Landmarks (nariz, olhos, boca) com posições incoerentes
   - Distorção de bordas (artifacts ao redor de face)

3. Frequential Analysis:
   - FFT de frame revela patterns não-naturais
   - Fase inconsistente entre frames
```

### Forensic Analysis
```
Error Level Analysis (ELA):
- Salvar JPEG em diferentes qualidades
- Recompressão revela regiões edited
- Deepfakes deixam "cicatrizes" de compressão

Metadata Inspection:
- EXIF data (data, câmera)
- Deepfakes gerados sem EXIF = suspeita
- Buscar inconsistências em timestamps
```

### Face Morphing Detection
```
Detectar morphing de múltiplos rostos em um
Usar face recognition para detectar múltiplas identidades
```

---

## 📝 3. AI-Generated Text Detection

### Perplexidade & Entropia
```
Perplexidade: Mede como um modelo de linguagem prediz o texto
- Texto natural: Perplexidade ~100-150
- Texto LLM: Perplexidade ~40-80 (mais previsível)

Entropia: Distribuição de palavras
- Texto natural: Entropia alta (mais variado)
- Texto IA: Entropia mais uniforme
```

### Estilometria
```
Análise de padrões de escrita:
- Tamanho médio de palavras
- Tamanho médio de sentenças
- Proporção de pontuação
- Diversidade lexical (Type-Token Ratio)

LLMs tem assinatura distintiva:
- Muito uso de "furthermore", "ultimately", "in conclusion"
- Pontuação consistente demais
- Sentençasmusicalmente similares
```

### Classificadores Treinados
```
Fine-tuned RoBERTa/DistilBERT em datasets:
- Real text vs GPT-3/GPT-4/Claude generated
- Detecção bidirecional

Dataset de treinamento:
- WebText (real)
- OpenWebText (real)
- GPT-generated (IAC, GLTR datasets)
```

### LLM-as-Judge
```
Usar um LLM para julgar se outro texto é IA-generated
Contraditório: usar IA para detectar IA
Mas funciona porque modelos diferentes têm assinaturas diferentes
```

---

## 🎯 Casos de Uso: Fraude habilitada por IA

### CEO Fraud com Deepfake + Voice Cloning
```
1. Hacker cria deepfake do CEO em videochamada
2. Voice cloning do CEO em áudio
3. Aborda CFO: "Preciso que faça uma transferência urgente"
4. CFO vê vídeo + ouve voz → convencido
5. Transferência bilionária realizada

Defesa:
- Callback verification (ligar de volta para número conhecido)
- Autenticação multifator (não só vídeo)
- Canais de autorização separados
```

### Phishing com Texto LLM-Generated
```
1. Email phishing gerado por LLM (muito mais convincente)
2. Texto personalizado via data mining (OSINT)
3. Usuário menos suspeita porque texto é fluente
4. Taxa de sucesso aumenta ~60%

Defesa:
- Detectar LLM-generated text
- Adicionar headers DMARC/DKIM
- Training em identificação de phishing LLM
```

### Fake News com Deepfake + Voice
```
1. Vídeo deepfake de político dizendo algo comprometedor
2. Voice cloning também
3. Disseminado via social media
4. Impacto político/reputacional massivo

Defesa:
- Proveniência de conteúdo (C2PA/Content Credentials)
- Digital signatures
- Blockchain verification
```

---

## 🛡️ Defesas: Camadas de Proteção

### 1. Prevenção (Prevention)
```
- Educar usuários sobre deepfakes
- Usar MFA (não só vídeo/áudio)
- Callback verification para operações críticas
- Rate limiting em APIs sensíveis
```

### 2. Detecção (Detection)
```
- Análise espectral de áudio (MFCC)
- Eye blinking detection em vídeo
- Perplexidade de texto
- Classificadores treinados (RoBERTa, etc)
```

### 3. Resposta (Response)
```
- Playbook de incidente de deepfake
- Preservação forense de mídia
- Análise de cadeia de custódia
- Comunicação com stakeholders
```

### 4. Recuperação (Recovery)
```
- Takedown notices
- Comunicado público
- Monitoramento de reputação
- Compliance com regulação
```

---

## 📊 Organizando uma Defesa Corporativa

### NIST AI Risk Management Framework (AI RMF)
```
Govern:
- Política de uso de IA generativa
- Governança de detecção de deepfake
- Programa de conciência

Map:
- Mapear riscos de deepfake/voice cloning
- Identificar superfícies de ataque (videochamadas, email, etc)

Measure:
- Métricas de detecção
- Taxa de falsos positivos/negativos
- Time-to-detect

Manage:
- Implementar defesas
- Monitoramento contínuo
```

---

## 📚 Referências

**Deepfake Detection:**
- MesoNet: Afchar et al. (2018)
- FaceForensics: Roessler et al. (2019)
- InVID WeVerify: Plugin do navegador

**Voice Cloning Detection:**
- ASVspoof Challenge: https://www.asvspoof.org
- AASIST: Min et al. (2021)

**Text Detection:**
- GLTR: Gehrmann et al. (2019)
- Detextify: Lee et al. (2023)

**Governança:**
- NIST AI Risk Management Framework: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
- EU AI Act: https://european-union.europa.eu/topics/artificial-intelligence-act_en

---

*CyberLab v2.0 — Synthetic Media Detection Documentation*

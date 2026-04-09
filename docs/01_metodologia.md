# Metodologia - CyberLab

## Ciclo de Vida do Ataque

Este projeto segue a metodologia padrão de teste de penetração (pentest):

```
RECON → ENUMERATION → ATTACK → ANALYSIS → DEFENSE → VALIDATION
```

### 1. RECONHECIMENTO (Notebook 0-1)

**Objetivo:** Mapear a superfície de ataque do target

**Técnicas:**
- **Passive Recon:** Pesquisa sem deixar rastros
  - WHOIS lookup
  - DNS enumeration
  - Certificate transparency logs
  - Shodan/Censys search

- **Active Recon:** Interação direta com target
  - Port scanning (Nmap)
  - Service enumeration
  - Vulnerability assessment

**Ferramentas:**
- Nmap (port scanning, service detection)
- NSE scripts (vulnerability detection)

**Output:**
- Lista de portas abertas
- Serviços identificados
- Versões de software
- Potenciais vulnerabilidades

---

### 2. ENUMERAÇÃO (Notebook 2)

**Objetivo:** Extrair informações detalhadas sobre serviços vulneráveis

**Por Serviço:**

#### FTP (Porta 21)
```
1. Tentar login anônimo
2. Enumerar usuários válidos
3. Listar conteúdo do servidor
4. Preparar brute force
```

#### SMB (Porta 445)
```
1. Enumerar shares disponíveis
2. Listar usuários do domínio
3. Verificar grupos
4. Testar null session
```

#### HTTP (Porta 80)
```
1. Identificar tecnologia (CMS, framework)
2. Mapear estrutura do site
3. Localizar formulários (login, etc)
4. Enumerar diretórios e arquivos
```

#### SSH (Porta 22)
```
1. Banner grabbing (versão SSH)
2. Enumerar algoritmos suportados
3. Coletar chaves públicas
4. Preparar brute force
```

**Ferramentas:**
- enum4linux (SMB enumeration)
- nmap NSE scripts
- Burp Suite (web enumeration)
- curl/wget (web reconnaissance)

**Output:**
- Lista de usuários válidos
- Estrutura de diretórios
- Configurações do servidor
- Potenciais pontos fracos

---

### 3. ATAQUE (Notebooks 3-5)

**Objetivo:** Explorar vulnerabilidades identificadas

#### Força Bruta contra Serviços

**FTP Brute Force (Notebook 3)**
```bash
medusa -h TARGET -u USERNAME -P wordlist.txt -M ftp -f
```

Testa combinações de usuário/senha contra FTP.

**SMB Brute Force (Notebook 4)**
```bash
medusa -h TARGET -U users.txt -P passwords.txt -M smbnt -f
```

Testa contra Samba/Windows file sharing.

**Web Brute Force (Notebook 5)**
```
1. Analisar formulário de login (DVWA)
2. Configurar Burp Suite Intruder
3. Usar wordlist de senhas
4. Testar combinações
5. Validar credenciais bem-sucedidas
```

#### Wordlists Estratégicas

**Tier 1 - Padrão:**
- admin, root, test, user
- password, 123456, admin123

**Tier 2 - Contextual:**
- Baseado em OSINT sobre target
- Nomes de empresas, domínios
- Termos da indústria

**Tier 3 - Customizado:**
- Gerado por algoritmo
- Combinações intelligentes
- Padrões comuns em alvo específico

**Métricas de Ataque:**
```
Total de tentativas = usuários × senhas × threads
Ex: 10 usuários × 100 senhas × 4 threads = 4000 testes
Tempo estimado: 10-30 minutos (dependendo do serviço)
```

---

### 4. SIMULAÇÃO DE MALWARE (Notebooks 6-7)

**Objetivo:** Demonstrar funcionamento de malware real de forma educacional

#### Ransomware Simulado

**Ciclo:**
1. Infecção → Arquivo executado
2. Enumeração → Identifica arquivos
3. Criptografia → Usa chave pública
4. Mensagem → Exibe nota de resgate
5. Impacto → Dados inacessíveis

**Implementação Segura:**
- Opera em diretório isolado `/results/test_files`
- Criptografia reversível (chave local)
- Sem propagação de rede
- Sem dados reais

#### Keylogger Simulado

**Ciclo:**
1. Infecção → Hook do sistema
2. Captura → Registra teclas
3. Log → Armazena em arquivo
4. Exfiltração → Envia para atacante (simulado)
5. Sigilo → Executa sem detecção

**Implementação Segura:**
- Não captura teclado real
- Registra apenas em arquivo de teste
- Nenhum envio de dados real
- Totalmente documentado

---

### 5. ANÁLISE (Notebook 8)

**Objetivo:** Interpretar resultados dos ataques

**Análise de Logs:**
- Parse de tentativas de login
- Identificação de IPs atacantes
- Timeline de eventos
- Padrões de ataque

**Estatísticas:**
- Taxa de sucesso
- Tempo médio por tentativa
- Usuários válidos descobertos
- Senhas corretas

**Dashboard:**
- Gráficos de tentativas
- Mapa de IPs
- Timeline de eventos
- Recomendações

---

### 6. DEFESA (Notebook 9)

**Objetivo:** Implementar mitigações e testar efetividade

#### Técnicas de Mitigação

**Contra Força Bruta:**
```
✓ fail2ban - Bloqueia IPs após N tentativas
✓ Account lockout - Desabilita conta após falhas
✓ Rate limiting - Limita tentativas por unidade de tempo
✓ Multi-factor auth - 2FA obrigatório
✓ Senhas fortes - Política de senha robusta
```

**Contra Malware:**
```
✓ Antivírus/Antimalware - Detecção de assinatura
✓ Firewall - Controle de tráfego
✓ Sandboxing - Isolamento de processos
✓ EDR - Detecção comportamental
✓ Backup offline - Recuperação sem pagar resgate
```

**Hardening:**
- Desabilitar serviços desnecessários
- Remover contas padrão
- Aplicar patches de segurança
- Configurar ACLs apropriados
- Monitoramento contínuo

---

### 7. VALIDAÇÃO (Notebook 10)

**Objetivo:** Provar que defesa é efetiva

**Testes:**
1. Re-executar brute force → Deve falhar
2. Re-executar ataques → Deve ser bloqueado
3. Verificar logs → Ataques registrados
4. Validar integridade → Sistema funciona normal

**Métricas de Sucesso:**
- ✅ 0% taxa de sucesso em ataques brute force
- ✅ Tentativas bloqueadas por fail2ban
- ✅ Alertas em SIEM/logs
- ✅ Sistema funcional pós-mitigação
- ✅ Sem falsos positivos

---

## Fluxo de Execução

```
START
  ↓
[Notebook 0] SETUP
  ↓ Dependências ok?
[Notebook 1] RECONHECIMENTO
  ↓ Serviços identificados?
[Notebook 2] PREPARAÇÃO
  ↓ Wordlists prontas?
[Notebook 3-5] ATAQUES BRUTE FORCE
  ↓ Credenciais encontradas?
[Notebook 6-7] MALWARE SIMULADO
  ↓ Simulações concluídas?
[Notebook 8] ANÁLISE
  ↓ Dados analisados?
[Notebook 9] DEFESA
  ↓ Mitigações implementadas?
[Notebook 10] VALIDAÇÃO
  ↓ Defesa efetiva?
END ✅
```

---

## Métricas e KPIs

| Métrica | Baseline | Target |
|---------|----------|--------|
| Portas abertas descobertas | - | >5 |
| Serviços enumerados | - | >3 |
| Credenciais válidas encontradas | - | >1 |
| Taxa de falso positivo | <5% | <2% |
| Tempo de ataque total | - | <2 horas |
| Tempo de mitigação | - | <1 hora |
| Taxa de bloqueio pós-defesa | - | 100% |

---

## Notas Importantes

### Ambiente Controlado
- ✅ VMs virtualizadas (Metasploitable 2, DVWA)
- ✅ Rede isolada (Host-Only)
- ✅ Sem dados reais
- ✅ Sem acesso à internet pública
- ✅ Fins educacionais apenas

### Ética e Legalidade
- ⚠️ NUNCA execute contra sistemas que você não possui
- ⚠️ Sempre tenha autorização por escrito
- ⚠️ Respeite leis de cibersegurança locais
- ⚠️ Proteja dados capturados durante testes
- ⚠️ Documente todos os passos

---

## Referências

- NIST Cybersecurity Framework
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- CIS Controls
- MITRE ATT&CK Framework

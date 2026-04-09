# Detalhes dos Ataques - CyberLab

## Força Bruta Contra Serviços

### FTP (Porta 21)

#### Vulnerabilidade
- Credenciais fracas
- Sem rate limiting padrão
- Sem autenticação multifator
- Protocolo legado inseguro

#### Ataque

**Ferramentas:**
```bash
# Verificar banner FTP
nc TARGET 21

# Brute force com Medusa
medusa -h TARGET -u USERNAME -P wordlist.txt -M ftp -f

# Brute force com Hydra
hydra -l root -P wordlist.txt ftp://TARGET
```

**Processo:**
1. Verificar FTP está acessível
2. Testar login anônimo
3. Enumerar usuários válidos
4. Brute force de senhas
5. Ao encontrar credencial válida, parar (-f flag)

**Detecção (logs):**
```
[Brute Force Attack]
Service: FTP
Target: 192.168.56.101:21
Attempts: 500+
Duration: 15 minutos
Result: msfadmin:msfadmin (SUCESSO)
```

#### Defesa

```bash
# fail2ban para FTP
# /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
maxretry = 3
findtime = 600
bantime = 3600

# Aplicar
systemctl restart fail2ban
```

---

### SMB (Porta 445)

#### Vulnerabilidade
- Múltiplos protocolos (SMB v1, v2, v3)
- Histórico de vulnerabilidades críticas
- Senhas fracas
- Null sessions (antiga)

#### Ataque

**Ferramentas:**
```bash
# Enum4linux - enumeração completa
enum4linux TARGET

# Enumerar shares
smbclient -L TARGET -U ""

# Brute force com Medusa
medusa -h TARGET -U users.txt -P passwords.txt -M smbnt -f

# RidEnum - enumerar usuários
ridenum TARGET 500 5000
```

**Processo:**
1. Verificar SMB acessível
2. Enumerar shares disponíveis
3. Enumerar usuários do domínio
4. Brute force de senhas
5. Validar acesso aos shares

**Exemplo de Sucesso:**
```
\\TARGET\IPC$          Accessible
\\TARGET\ADMIN$        Accessible (requer admin)
\\TARGET\C$            Accessible (requer admin)

Usuários descobertos:
  - root
  - msfadmin
  - ftp
  - mail
  - www-data

Credenciais válidas:
  root:root
  msfadmin:msfadmin
```

#### Defesa

```bash
# Desabilitar SMB v1 (Windows)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

# Linux - Samba hardening
# /etc/samba/smb.conf
min protocol = SMB3
max protocol = SMB3
disable netbios = yes
```

---

### HTTP/DVWA (Porta 80)

#### Vulnerabilidade
- Autenticação fraca (DVWA por design)
- Sem rate limiting no login
- Sem CAPTCHA
- Sem autenticação multifator

#### Ataque - Burp Suite

**Ferramentas:**
```bash
# Burp Suite Community Edition
# Intruder module para brute force
```

**Processo:**
1. Capturar request de login em Burp
2. Enviar para Intruder
3. Marcar campos username/password
4. Carrega wordlist
5. Executar ataque
6. Analisar respostas (código HTTP 302 = sucesso)

**Request de Exemplo:**
```http
POST /dvwa/login.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

username=admin&password=password&user_token=TOKEN&Login=Login
```

**Indicadores de Sucesso:**
- HTTP 302 (redirect para dashboard)
- Set-Cookie com valor PHPSESSID
- HTML response contém "Logout"

#### Defesa

```php
// Implementar rate limiting
function checkRateLimit($username, $ip) {
    $attempts = getLoginAttempts($username, $ip);
    $timeSinceReset = time() - $attempts['last_attempt'];
    
    if ($attempts['count'] > 5 && $timeSinceReset < 900) {
        http_response_code(429); // Too Many Requests
        die("Muitas tentativas. Tente novamente em 15 minutos.");
    }
    
    recordLoginAttempt($username, $ip);
}

// Implementar CAPTCHA
if ($loginAttempts > 3) {
    requireCaptcha();
}

// Implementar account lockout
if ($failedAttempts > 5) {
    lockAccount($username);
    sendAlertEmail($username);
}
```

---

### SSH (Porta 22)

#### Vulnerabilidade
- Versão antiga (Metasploitable 2)
- Algoritmos fracos
- Sem autenticação de chave
- Senhas fracas

#### Ataque

**Ferramentas:**
```bash
# Banner grabbing
ssh -v TARGET

# Brute force com Medusa
medusa -h TARGET -u root -P wordlist.txt -M ssh -f

# Hydra
hydra -l root -P wordlist.txt ssh://TARGET:22
```

**Processo:**
1. Verificar versão SSH
2. Verificar algoritmos suportados
3. Brute force de senhas
4. Acesso ao shell

**Detecção (via Honeypot):**
```
Failed password for root from 192.168.56.101 port 12345 ssh2
Failed password for root from 192.168.56.101 port 12346 ssh2
Failed password for root from 192.168.56.101 port 12347 ssh2
...
Accepted password for root from 192.168.56.101 port 12500 ssh2
```

#### Defesa

```bash
# /etc/ssh/sshd_config

# Desabilitar root login
PermitRootLogin no

# Desabilitar password auth (usar chaves)
PasswordAuthentication no
PubkeyAuthentication yes

# Rate limiting (fail2ban)
MaxAuthTries 3
MaxSessions 10

# Usar apenas SSH v2
Protocol 2

# Customizar porta
Port 2222

# Desabilitar empty passwords
PermitEmptyPasswords no

# Reiniciar
systemctl restart ssh
```

---

## Simulação de Malware

### Ransomware - Fluxo Técnico

**Cadeia de Infecção:**
```
1. DELIVERY
   └─→ Email malicioso
   └─→ Drive-by download
   └─→ USB infectado
   └─→ Compartilhamento compromissado

2. EXECUTION
   └─→ Arquivo .exe, .js, .macro
   └─→ Evasão de antivírus
   └─→ UAC bypass
   └─→ Execution policy bypass (PowerShell)

3. PERSISTENCE
   └─→ Registry run keys
   └─→ Scheduled tasks
   └─→ Services
   └─→ WMI event subscriptions

4. PRIVILEGE ESCALATION
   └─→ UAC bypass
   └─→ Token impersonation
   └─→ Kernel exploits

5. DEFENSE EVASION
   └─→ Kill antivirus
   └─→ Disable Windows Defender
   └─→ Delete logs
   └─→ Disable firewall

6. DISCOVERY
   └─→ Enumerate drives
   └─→ List file extensions
   └─→ Map network shares
   └─→ Identify backup systems

7. LATERAL MOVEMENT
   └─→ SMB/RDP exploitation
   └─→ Credenciais descobertas
   └─→ Propagação na rede

8. COLLECTION
   └─→ Arquivos importantes
   └─→ Documentos
   └─→ Fotos
   └─→ Banco de dados

9. EXFILTRATION (Opcional)
   └─→ Roubar dados antes criptografar
   └─→ Aumentar pressão por resgate

10. IMPACT
    └─→ Criptografia com chave pública
    └─→ Mensagem de resgate
    └─→ Extorsão
```

### Keylogger - Fluxo Técnico

**Captura de Entrada:**
```
KEYBOARD EVENTS
├─→ Teclas normais (a-z, 0-9)
├─→ Teclas especiais (Shift, Ctrl, Alt)
├─→ Sequências (Ctrl+C, Alt+Tab)
└─→ Combinações (Ctrl+Alt+Delete)

CONTEXTO CAPTURADO
├─→ Título da janela (qual aplicação?)
├─→ Timestamp de cada keystroke
├─→ Duração entre keystrokes
├─→ IP da máquina
└─→ Identificador único do dispositivo

DADOS EXTRAÍDOS
├─→ Senhas (padrões: "password: xxx")
├─→ Números de cartão
├─→ SSN / documentos
├─→ Mensagens de email
└─→ Chats privados
```

**Exfiltração:**
```
MÉTODOS DE ENVIO
├─→ Email (SMTP)
├─→ HTTP POST
├─→ FTP
├─→ C2 (Command & Control)
├─→ Telegram bot
└─→ Cloud storage

TIMING
├─→ Em tempo real
├─→ Batch (diário)
├─→ Sob demanda (por comando)
└─→ Ao atingir tamanho máximo
```

---

## Indicadores de Compromise (IoCs)

### Ataques de Força Bruta
```
[IOC] Múltiplas tentativas de login falhadas
    └─→ 5+ falhas em 10 minutos = Suspeito
    └─→ Mesmo usuário de múltiplos IPs = Suspeito
    └─→ Múltiplos usuários do mesmo IP = Suspeito

[IOC] Atividade de rede anormal
    └─→ Scan de portas
    └─→ DNS queries inusitadas
    └─→ Tráfego para IPs conhecidos maliciosos

[IOC] Padrões de autenticação
    └─→ Tentativas durante horário atípico
    └─→ Acesso a recursos não utilizados
    └─→ Atividade imediata após primeiro sucesso
```

### Malware
```
[IOC] Comportamento de arquivo
    └─→ Alteração massiça de extensões (.LOCKED, .ENCRYPTED)
    └─→ Arquivos de resgate criados
    └─→ Processos com permissões elevadas

[IOC] Atividade de rede
    └─→ Conexões para C2 servers
    └─→ Comunicação criptografada inusitada
    └─→ DNS tunneling

[IOC] Atividade de registro (Registry)
    └─→ Chaves de boot modificadas
    └─→ Scheduled tasks criadas
    └─→ Run keys alteradas

[IOC] Processo (Memory)
    └─→ Processos injetados
    └─→ Threads em processos do sistema
    └─→ Alocação de memória executável
```

---

## Referências de Ataques Reais

### Ransomware
- **WannaCry (2017):** Explorou EternalBlue (SMB)
- **Ryuk (2018-2020):** Ataque direcionado com payload de ransomware
- **LockBit (2020+):** RaaS com dupla extorsão
- **Conti (2020-2022):** Grupo sofisticado, afetou setor crítico

### Força Bruta
- **Shodan:** IoT devices com credenciais padrão
- **Mirai Botnet:** Brute force em IoT em massa
- **Credential Stuffing:** Reuso de senhas roubadas

---

## Conclusão

Esses ataques demonstram por que:
1. **Senhas fortes** são essenciais
2. **Patches atualizados** são críticos
3. **Monitoramento** é obrigatório
4. **Redundância** salva vidas (backup)
5. **Educação** é melhor que reação

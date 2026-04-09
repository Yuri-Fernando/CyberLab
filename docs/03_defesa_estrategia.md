# Estratégia de Defesa - CyberLab

## Defesa em Profundidade (Defense in Depth)

O modelo de defesa em camadas cria múltiplas barreiras contra ataques:

```
┌─────────────────────────────────────────┐
│    PERÍMETRO (Firewall, WAF)           │
├─────────────────────────────────────────┤
│    NETWORK (IDS, Segmentação)          │
├─────────────────────────────────────────┤
│    HOST (Antivírus, Firewall local)    │
├─────────────────────────────────────────┤
│    APPLICATION (Auth, Encryption)       │
├─────────────────────────────────────────┤
│    DATA (Backup, Encryption, DLP)      │
└─────────────────────────────────────────┘
```

Mesmo se uma camada falha, outras continuam protegendo.

---

## Contra Força Bruta

### 1. Rate Limiting

**Implementação:**
```python
from datetime import datetime, timedelta

class RateLimiter:
    def __init__(self):
        self.attempts = {}  # {username: [(timestamp, success)]}
        self.threshold = 5
        self.window = timedelta(minutes=15)
    
    def is_blocked(self, username):
        now = datetime.now()
        if username not in self.attempts:
            return False
        
        # Remover tentativas antigas
        self.attempts[username] = [
            (ts, success) for ts, success in self.attempts[username]
            if now - ts < self.window
        ]
        
        failed_attempts = sum(1 for ts, success in self.attempts[username] if not success)
        return failed_attempts >= self.threshold
    
    def record_attempt(self, username, success):
        if username not in self.attempts:
            self.attempts[username] = []
        self.attempts[username].append((datetime.now(), success))
```

**Efeito:**
```
┌─────────────────────────────────────┐
│ Tentativa 1: FALHA                  │
├─────────────────────────────────────┤
│ Tentativa 2: FALHA                  │
├─────────────────────────────────────┤
│ Tentativa 3: FALHA                  │
├─────────────────────────────────────┤
│ Tentativa 4: FALHA                  │
├─────────────────────────────────────┤
│ Tentativa 5: FALHA                  │
├─────────────────────────────────────┤
│ Tentativa 6: BLOQUEADO por 15 min   │ ← Rate limit ativado
├─────────────────────────────────────┤
│ Tentativa 7+: BLOQUEADO             │ ← Todas bloqueadas
└─────────────────────────────────────┘
```

### 2. Account Lockout

**Política:**
- Máximo 3 tentativas falhadas
- Lockout por 30 minutos
- Admin pode desbloquear manualmente
- Log de todas as tentativas

**Implementação:**
```sql
-- Tabela de login
CREATE TABLE login_attempts (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255),
    timestamp DATETIME,
    success BOOLEAN,
    ip_address VARCHAR(45),
    user_agent TEXT
);

-- Trigger para lockout
CREATE TRIGGER check_lockout
BEFORE INSERT ON login_attempts
FOR EACH ROW
BEGIN
    DECLARE failed_count INT;
    
    SELECT COUNT(*) INTO failed_count
    FROM login_attempts
    WHERE username = NEW.username
    AND success = FALSE
    AND timestamp > DATE_SUB(NOW(), INTERVAL 30 MINUTE);
    
    IF failed_count >= 3 THEN
        UPDATE users SET locked = TRUE WHERE username = NEW.username;
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Account locked';
    END IF;
END;
```

### 3. fail2ban - Bloqueio por IP

**Instalação:**
```bash
sudo apt-get install fail2ban
```

**Configuração:**
```ini
# /etc/fail2ban/jail.local

[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log

[ftp-aggressive]
enabled = true
port = ftp
filter = ftp
logpath = /var/log/vsftpd.log
maxretry = 3

[samba]
enabled = true
port = 445
filter = samba
logpath = /var/log/samba/log.smbd
```

**Efeito:**
```
IP 192.168.1.100 tenta FTP:
  Tentativa 1: FALHA
  Tentativa 2: FALHA
  Tentativa 3: FALHA
  → IP bloqueado por fail2ban
  → Iptables rule adicionada
  → Qualquer conexão desse IP é recusada por 1 hora
```

### 4. Autenticação Multifator (MFA)

**Implementação com TOTP:**
```python
import pyotp
import qrcode

class MFAManager:
    def generate_secret(self, username):
        secret = pyotp.random_base32()
        user.mfa_secret = secret
        return secret
    
    def get_qr_code(self, username, secret):
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=username, issuer_name='CyberLab')
        qr = qrcode.make(uri)
        return qr
    
    def verify(self, username, token):
        secret = user.mfa_secret
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
```

**Fluxo:**
```
1. Usuario digita: usuario + senha
2. Sistema verifica: OK
3. Sistema pede: código TOTP de 6 dígitos
4. Usuario abre: aplicativo (Google Authenticator)
5. Usuario digita: código TOTP
6. Sistema verifica: OK
7. Usuario acessa: sistema
```

---

## Contra Malware

### 1. Antivírus & Antimalware

**Camadas:**
```
DETECÇÃO BASEADA EM ASSINATURA
└─→ Padrões conhecidos de malware
└─→ Banco de dados de vírus
└─→ Rápido mas não detecta novo malware

DETECÇÃO COMPORTAMENTAL
└─→ Monitora ações suspeitas
└─→ Criptografia em massa = ransomware
└─→ Captura de teclado = keylogger
└─→ Conexão C2 = botnet

HEURÍSTICA
└─→ Análise de código
└─→ Padrões de execução
└─→ Detecção de polimorfismo
```

**Ferramentas:**
- Windows Defender (built-in)
- Malwarebytes
- Kaspersky
- Norton
- McAfee

### 2. Sandboxing & Isolamento

**Windows Sandbox:**
```
Arquivo suspeito?
  └─→ Executar em sandbox isolada
  └─→ Malware executa mas não afeta sistema real
  └─→ Analisar comportamento
  └─→ Deletar sem risco
```

**Containerização:**
```docker
# Dockerfile para isolamento
FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y antivirus tools

# Usuário não-root
RUN useradd -m -s /bin/bash sandbox
USER sandbox

# Apenas leitura de arquivos de entrada
VOLUME ["/input"]

WORKDIR /tmp
```

### 3. Backup & Disaster Recovery

**Estratégia 3-2-1:**
```
3 CÓPIAS DE DADOS
├─→ Cópia 1: Sistema de produção
├─→ Cópia 2: Backup local (NAS)
└─→ Cópia 3: Backup remoto (cloud)

2 TIPOS DE MÍDIA
├─→ Mídia 1: Disco rápido (NAS)
└─→ Mídia 2: Fita offline (archive)

1 CÓPIA OFFLINE
└─→ Armazenada offline (protegida de ransomware)
```

**Testagem:**
```bash
# Testar restauração regularmente
Week 1: Full backup
Week 2: Restore test (dados)
Week 3: Restore test (sistema completo)
Week 4: Audit

# Log de backup
2026-04-09 02:00:00 | Full Backup | 500 GB | SUCCESS
2026-04-10 02:00:00 | Incremental | 50 GB  | SUCCESS
2026-04-11 02:00:00 | Incremental | 45 GB  | SUCCESS
[Restore Test 2026-04-12] | 100% SUCCESS
```

---

## Contra Reconhecimento

### 1. Minimizar Superfície de Ataque

**Serviços:**
```bash
# Verificar serviços rodando
systemctl list-units --type=service --state=running

# Desabilitar desnecessários
systemctl disable apache2  # Se não usa web
systemctl disable ftp      # Se não usa FTP
systemctl stop apache2
```

**Portas Abertas:**
```
ANTES (Inseguro):
  21/tcp   - FTP (aberto)
  23/tcp   - Telnet (aberto)
  80/tcp   - HTTP (aberto)
  445/tcp  - SMB (aberto)
  3306/tcp - MySQL (aberto)
  → 5 portas vulneráveis

DEPOIS (Hardened):
  22/tcp   - SSH (apenas interna)
  80/tcp   - HTTP (atrás de WAF)
  443/tcp  - HTTPS (certificado válido)
  → 3 portas, todas com proteção
```

### 2. Ocultar Informações Sensíveis

**Banner Grabbing:**
```bash
# ANTES (Inseguro)
$ nc -v TARGET 21
220 Metasploitable FTP Server (vsFTPd 2.0.1)
↑ Versão exposta!

# DEPOIS (Seguro)
$ ssh -v TARGET
OpenSSH_7.4_generic
↑ Genérico, versão oculta
```

**HTTP Headers:**
```http
# ANTES (Inseguro)
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9

# DEPOIS (Seguro)
Server: WebServer/1.0
X-Powered-By: [removido]
```

### 3. Implementar WAF (Web Application Firewall)

```
REQUEST
  ↓
[WAF]
├─ Verifica SQL injection? → BLOQUEIA
├─ Verifica XSS? → BLOQUEIA
├─ Verifica Path traversal? → BLOQUEIA
├─ Verifica Rate limit? → BLOQUEIA
├─ Verifica GeoIP? → BLOQUEIA se suspeito
└─ Tudo OK → PERMITE
  ↓
APLICAÇÃO
```

---

## Monitoramento & Detecção

### 1. SIEM (Security Information Event Management)

**Centralizar Logs:**
```
┌──────────┐
│ FTP Log  │\
└──────────┘ \
              \  ┌──────────────┐
┌──────────┐   →│ SIEM (ELK)   │→ Alertas
│ SSH Log  │  / └──────────────┘
└──────────┘ /
            /
┌──────────┐
│ SMB Log  │/
└──────────┘
```

**Regras de Detecção:**
```yaml
# Detectar força bruta SSH
rule: "SSH Brute Force"
condition: |
  ssh_failed_auth_count >= 5 AND
  time_window = 5_minutes AND
  same_username OR same_source_ip
action: "ALERT | Block IP for 1 hour"

# Detectar criar arquivo massivo
rule: "Possible Ransomware"
condition: |
  file_creation_rate > 100_per_minute AND
  file_extension_changes > 50% AND
  process_elevation = true
action: "ALERT | Isolate host | Kill process"

# Detectar exfiltração de dados
rule: "Data Exfiltration"
condition: |
  outbound_traffic > 1_GB AND
  destination_country != home_country AND
  protocol = encrypted
action: "ALERT | Block connection | Investigate"
```

### 2. EDR (Endpoint Detection & Response)

**Real-time Monitoring:**
```
ENDPOINT MONITORING
├─ Processos em execução
├─ Arquivo criados/modificados
├─ Conexões de rede
├─ Execução de scripts
├─ Modificação de registro (Windows)
└─ Acesso a sensíveis
  ↓
COMPORTAMENTO SUSPEITO?
  ├─→ Registrar em tempo real
  ├─→ Alertar analista
  ├─→ Coletar evidência digital
  └─→ Permitir resposta rápida
```

---

## Resposta a Incidente

### 1. Contenção

**Imediato (0-5 min):**
```
INCIDENTE DETECTADO
  ↓
1. Isolar máquina da rede (desconectar cabo)
2. NÃO desligar (não perde RAM)
3. Fotografar tela para evidência
4. Ativar runbook de resposta
5. Notificar gerenciamento
```

**Curto Prazo (5-30 min):**
```
6. Iniciar captura de memória (forensic)
7. Coletar logs de sistema
8. Analisar processos ativos
9. Identificar método de entrada
10. Bloquear C2 IPs
```

### 2. Recuperação

**Opção 1 - Restaurar Backup:**
```
Ransomware ativo?
  → Restaurar do backup offline
  → Tempo: 2-24 horas (dependendo do tamanho)
  → Custo: 0 resgate (MELHOR)
```

**Opção 2 - Reparar Manualmente:**
```
Remover malware?
  → Antivírus em modo seguro
  → Análise forense
  → Reconstruir sistema
  → Tempo: dias/semanas
  → Risco: resíduos de malware
```

### 3. Aprendizado Pós-Incidente

```
POST-INCIDENT REVIEW
├─ Timeline completa do incidente
├─ O que funcionou na defesa?
├─ O que falhou?
├─ Como foi detectado?
├─ Como foi contido?
├─ Como foi remediado?
└─ Lições aprendidas → Implementar controles
```

---

## Checklist de Segurança

### Servidores

- [ ] SSH: Não permite root login
- [ ] SSH: Password auth desabilitado (usar chaves)
- [ ] SSH: Muda porta padrão (22)
- [ ] FTP: Desabilitado (usar SFTP)
- [ ] Telnet: Desabilitado (usar SSH)
- [ ] MySQL: Sem porta aberta externamente
- [ ] Serviços desnecessários: Desabilitados
- [ ] Firewall: Ativo e configurado
- [ ] Fail2ban: Ativo
- [ ] Antivírus: Ativo
- [ ] Backup: Testado regularmente
- [ ] Updates: Automáticos habilitados
- [ ] Logs: Centralizados e monitorados
- [ ] Senhas: Politica forte obrigatória
- [ ] MFA: Habilitado para acesso crítico

### Aplicações

- [ ] Input validation: Implementado
- [ ] SQL injection: Protegido (prepared statements)
- [ ] XSS: Protegido (sanitização)
- [ ] CSRF: Token CSRF em todos os forms
- [ ] Rate limiting: Implementado no login
- [ ] Account lockout: Implementado
- [ ] Password hashing: bcrypt/scrypt (não MD5)
- [ ] HTTPS: Obrigatório
- [ ] Certificado SSL/TLS: Válido e não expirado
- [ ] Security headers: Implementados (CSP, X-Frame-Options, etc)
- [ ] Logging: Todas as ações críticas registradas
- [ ] Error handling: Mensagens genéricas (não expõe stack trace)

### Rede

- [ ] Segmentação: VLANs implementadas
- [ ] DMZ: Servidores web isolados
- [ ] WAF: Ativo na frente de aplicações web
- [ ] IDS/IPS: Monitorando tráfego
- [ ] DLP: Detectando exfiltração de dados
- [ ] VPN: Para acesso remoto
- [ ] Firewall: Permite apenas tráfego necessário
- [ ] DNS filtering: Bloqueando C2 domains

---

## Conclusão

Defesa em profundidade não é uma instalação única, mas um **processo contínuo**:

1. **Prevenir** - Reduzir superfície de ataque
2. **Detectar** - Monitorar comportamento anormal
3. **Responder** - Agir rápido quando detectado
4. **Recuperar** - Restaurar de backup seguro
5. **Aprender** - Melhorar processos

**O ataque sempre evolui. A defesa deve evoluir junto.**

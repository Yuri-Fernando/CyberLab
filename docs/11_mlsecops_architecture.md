# Arquitetura MLSecOps

Fluxo implementado:

INPUT → schema/range validation → risk correlation → policy → inference ou challenge/fallback/quarantine → incident → rollback.

## Princípios

- Drift isolado não é ataque. O pipeline correlaciona drift, query rate, OOD, suspeita adversarial e extração.
- A API falha fechada quando CYBERLAB_API_KEY não está configurada.
- Rate limiting é por identidade derivada, com budget explícito.
- Telemetria padrão guarda hashes e estatísticas; vetores crus não são persistidos.
- Fallback, quarantine e rollback geram audit events.
- O limiter em memória é adequado ao laboratório; produção distribuída requer backend compartilhado.

## Estados

NORMAL → SUSPICIOUS → DEGRADED → COMPROMISED → ROLLBACK → NORMAL.

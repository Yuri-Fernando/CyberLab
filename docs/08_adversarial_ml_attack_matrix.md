# Matriz de Ataques de Adversarial ML

| Ataque | Label alterado | Direcionado | Trigger | Objetivo | Evidência no CyberLab |
|---|---:|---:|---:|---|---|
| Label flipping | Sim | Opcional | Não | Disponibilidade/integridade | poisoning_attacks.py |
| Backdoor | Opcional | Sim | Sim | Integridade direcionada | poisoning_attacks.py |
| Clean-label | Não | Sim | Opcional | Integridade furtiva | clean_label_poisoning.py |
| Feature collision | Não | Sim | Não | Colidir representação do alvo | clean_label_poisoning.py |
| Availability poisoning | Sim/não | Não | Não | Degradar desempenho global | poisoning_attacks.py |
| Integrity poisoning | Sim/não | Sim | Opcional | Alterar casos específicos | poisoning_attacks.py |

Métricas mínimas: clean accuracy, poisoned accuracy, poison fraction, targeted success rate, backdoor ASR e integridade de labels.

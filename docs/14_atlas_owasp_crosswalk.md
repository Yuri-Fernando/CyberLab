# Crosswalk MITRE ATLAS × OWASP ML Security

| Cenário | MITRE ATLAS | OWASP ML | Módulo | Detecção | Mitigação |
|---|---|---|---|---|---|
| Evasion | Adversarial Example | ML01 Input Manipulation | whitebox_attacks_torch.py | gradient masking audit | adversarial training, validation |
| Poisoning/backdoor | Poison Training Data | ML02 Data Poisoning | poisoning_attacks.py | activation clustering | lineage, quarantine |
| Model extraction | Discover/Exfiltrate Model | ML04 Model Theft | model_extraction.py, model_api | query diversity/rate | auth, quota, output minimization |
| Membership/inversion | Infer Training Data | ML06 Sensitive Data Exposure | model_extraction.py, model_inversion.py | privacy benchmark | DP-SGD, minimized outputs |
| Artifact tampering | Supply Chain Compromise | ML03 Supply Chain | roadmap ML-BOM | hash/provenance | signed registry |

MITRE ATLAS descreve TTPs do adversário; OWASP organiza riscos e controles de engenharia. São complementares.

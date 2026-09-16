"""
antifraud_controls.py - Controles Antifraude & EU AI Act

Implementa os controles organizacionais que barram fraudes com IA generativa mesmo
quando a detecção técnica falha (defesa em profundidade):

1. DUPLA AUTORIZAÇÃO: transações acima de limiar exigem dois aprovadores distintos.
2. HOLD DE MUDANÇA BANCÁRIA: alteração de dados bancários entra em quarentena com
   verificação por canal independente (bloqueia o golpe clássico de "novo IBAN").
3. CALLBACK VERIFICATION: operações críticas exigem retorno por canal conhecido.

Também classifica sistemas de IA por risco segundo o EU AI Act (proibido / alto /
limitado / mínimo), complementando NIST AI RMF e ISO/IEC 42001.
"""

import json
import logging
from typing import Dict, List
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class AntifraudControls:
    """Motor de controles antifraude para operações sensíveis."""

    def __init__(self, dual_auth_threshold: float = 10000.0, log_dir: Path = None):
        self.dual_auth_threshold = dual_auth_threshold
        self.log_dir = log_dir or Path("./results/governance")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.audit = []

    def evaluate_transaction(
        self,
        amount: float,
        approvers: List[str],
        changes_bank_details: bool = False,
        channel_verified: bool = False,
    ) -> Dict:
        """Aplica os controles a uma transação e decide se pode prosseguir."""
        controls = []
        blocks = []

        # 1) Dupla autorização
        if amount >= self.dual_auth_threshold:
            distinct = len(set(approvers)) >= 2
            controls.append("dupla_autorizacao")
            if not distinct:
                blocks.append("Exige 2 aprovadores distintos para o valor")

        # 2) Hold de mudança bancária
        if changes_bank_details:
            controls.append("hold_mudanca_bancaria")
            if not channel_verified:
                blocks.append("Mudança de dados bancários requer verificação por canal independente")

        # 3) Callback para valores críticos
        if amount >= self.dual_auth_threshold * 5 and not channel_verified:
            controls.append("callback_verification")
            blocks.append("Valor crítico exige callback para número cadastrado")

        decision = {
            "timestamp": datetime.now().isoformat(),
            "amount": amount,
            "approvers": approvers,
            "changes_bank_details": changes_bank_details,
            "channel_verified": channel_verified,
            "controls_triggered": controls,
            "blocks": blocks,
            "approved": len(blocks) == 0,
        }
        self.audit.append(decision)
        status = "APROVADA" if decision["approved"] else "BLOQUEADA"
        logger.info(f"Transação R${amount:,.0f}: {status} ({len(blocks)} bloqueios)")
        return decision

    def save_audit(self) -> str:
        out = self.log_dir / f"antifraud_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump(self.audit, f, indent=2, ensure_ascii=False)
        return str(out)


class EUAIActClassifier:
    """Classifica sistemas de IA por nível de risco segundo o EU AI Act."""

    PROHIBITED = ["social scoring", "manipulação subliminar", "identificação biométrica em tempo real em espaço público"]
    HIGH_RISK = ["scoring de crédito", "recrutamento", "biometria", "infraestrutura crítica",
                 "aplicação da lei", "educação", "dispositivos médicos"]
    LIMITED_RISK = ["chatbot", "deepfake", "geração de conteúdo", "reconhecimento de emoção"]

    def classify(self, system_purpose: str) -> Dict:
        """Classifica pelo propósito declarado do sistema."""
        p = system_purpose.lower()
        if any(k in p for k in self.PROHIBITED):
            tier, obligations = "PROIBIDO", ["Uso vedado pelo EU AI Act"]
        elif any(k in p for k in self.HIGH_RISK):
            tier = "ALTO RISCO"
            obligations = [
                "Sistema de gestão de risco (Art. 9)",
                "Governança de dados (Art. 10)",
                "Documentação técnica (Art. 11)",
                "Registro de logs (Art. 12)",
                "Supervisão humana (Art. 14)",
                "Avaliação de conformidade antes do mercado",
            ]
        elif any(k in p for k in self.LIMITED_RISK):
            tier = "RISCO LIMITADO"
            obligations = ["Transparência: informar que o usuário interage com IA / conteúdo é sintético"]
        else:
            tier, obligations = "RISCO MÍNIMO", ["Sem obrigações específicas (boas práticas voluntárias)"]

        return {
            "system_purpose": system_purpose,
            "eu_ai_act_tier": tier,
            "obligations": obligations,
        }


def demo():
    logging.basicConfig(level=logging.INFO)
    controls = AntifraudControls(dual_auth_threshold=10000)

    print("\n=== Controles Antifraude ===")
    # Golpe do deepfake do CEO: valor alto, 1 aprovador, muda banco, sem verificação
    d1 = controls.evaluate_transaction(250000, ["cfo"], changes_bank_details=True, channel_verified=False)
    print(f"Transferência suspeita: {'APROVADA' if d1['approved'] else 'BLOQUEADA'} -> {d1['blocks']}")
    # Transação legítima
    d2 = controls.evaluate_transaction(5000, ["analyst"], changes_bank_details=False)
    print(f"Transação normal: {'APROVADA' if d2['approved'] else 'BLOQUEADA'}")

    print("\n=== EU AI Act ===")
    clf = EUAIActClassifier()
    for purpose in ["scoring de crédito para empréstimo", "chatbot de atendimento", "social scoring de cidadãos"]:
        r = clf.classify(purpose)
        print(f"  {purpose} -> {r['eu_ai_act_tier']}")


if __name__ == "__main__":
    demo()

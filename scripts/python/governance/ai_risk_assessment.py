"""
ai_risk_assessment.py - Assessment de Governança de IA (NIST AI RMF + ISO/IEC 42001)

Transforma dois frameworks de governança em uma ferramenta executável que:
1. Avalia a maturidade de um sistema de IA nas funções do NIST AI RMF
   (GOVERN, MAP, MEASURE, MANAGE).
2. Verifica controles-chave do ISO/IEC 42001 (AI Management System).
3. Gera um relatório de maturidade com score e recomendações priorizadas.

Uso real: rode contra um projeto de ML respondendo aos controles, e obtenha
um relatório defensável de maturidade de governança — o tipo de artefato que
uma vaga de governança de risco de IA espera ver.
"""

import json
import logging
from typing import Dict, List
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


# NIST AI RMF 1.0 — funções e categorias (subconjunto representativo)
NIST_AI_RMF = {
    "GOVERN": [
        "Políticas e procedimentos de risco de IA documentados",
        "Papéis e responsabilidades de accountability definidos",
        "Cultura de gestão de risco de IA estabelecida",
        "Processos de inventário de sistemas de IA",
    ],
    "MAP": [
        "Contexto e finalidade do sistema de IA documentados",
        "Riscos e impactos mapeados (incl. partes afetadas)",
        "Categorização do sistema por criticidade",
        "Superfície de ataque de ML identificada (MITRE ATLAS)",
    ],
    "MEASURE": [
        "Métricas de performance e robustez definidas",
        "Testes de robustez adversarial executados",
        "Avaliação de viés/fairness realizada",
        "Monitoramento de drift em produção",
    ],
    "MANAGE": [
        "Priorização e tratamento de riscos",
        "Plano de resposta a incidente de modelo",
        "Controles de acesso e auditoria de API",
        "Processo de melhoria contínua e revisão",
    ],
}

# ISO/IEC 42001 — controles-chave de um AI Management System (AIMS)
ISO_42001_CONTROLS = [
    "Política de IA aprovada pela liderança",
    "Objetivos de IA mensuráveis e monitorados",
    "Avaliação de impacto do sistema de IA (AIA)",
    "Gestão de dados: qualidade, proveniência e privacidade",
    "Gestão do ciclo de vida do modelo (dev→deploy→retire)",
    "Documentação técnica e transparência",
    "Controles de segurança da informação para IA",
    "Gestão de fornecedores/terceiros de IA",
    "Registro de incidentes e ações corretivas",
    "Auditoria interna e revisão de gestão",
]


class AIGovernanceAssessment:
    """Executa assessment de governança e gera relatório de maturidade."""

    MATURITY_LEVELS = {
        0: "Inexistente",
        1: "Inicial",
        2: "Em desenvolvimento",
        3: "Definido",
        4: "Gerenciado",
        5: "Otimizado",
    }

    def __init__(self, system_name: str, log_dir: Path = None):
        self.system_name = system_name
        self.log_dir = log_dir or Path("./results/governance")
        self.log_dir.mkdir(exist_ok=True, parents=True)

    def assess_nist_rmf(self, responses: Dict[str, List[int]]) -> Dict:
        """
        Avalia maturidade NIST AI RMF.

        Args:
            responses: {função: [score 0-5 por controle]}
        """
        function_scores = {}
        for function, controls in NIST_AI_RMF.items():
            scores = responses.get(function, [0] * len(controls))
            avg = sum(scores) / len(controls)
            function_scores[function] = {
                "average_score": round(avg, 2),
                "maturity_level": self.MATURITY_LEVELS[round(avg)],
                "controls_assessed": len(controls),
                "gaps": [
                    controls[i] for i, s in enumerate(scores) if s <= 2
                ],
            }

        overall = sum(f["average_score"] for f in function_scores.values()) / len(
            function_scores
        )
        return {
            "framework": "NIST AI RMF 1.0",
            "function_scores": function_scores,
            "overall_maturity": round(overall, 2),
            "overall_level": self.MATURITY_LEVELS[round(overall)],
        }

    def assess_iso_42001(self, control_scores: List[int]) -> Dict:
        """Avalia conformidade ISO/IEC 42001 (scores 0-5 por controle)."""
        if len(control_scores) != len(ISO_42001_CONTROLS):
            control_scores = (control_scores + [0] * len(ISO_42001_CONTROLS))[
                : len(ISO_42001_CONTROLS)
            ]
        avg = sum(control_scores) / len(ISO_42001_CONTROLS)
        conformity_pct = 100 * sum(1 for s in control_scores if s >= 3) / len(
            ISO_42001_CONTROLS
        )
        return {
            "framework": "ISO/IEC 42001",
            "average_score": round(avg, 2),
            "conformity_percentage": round(conformity_pct, 1),
            "maturity_level": self.MATURITY_LEVELS[round(avg)],
            "non_conformities": [
                ISO_42001_CONTROLS[i] for i, s in enumerate(control_scores) if s < 3
            ],
        }

    def generate_report(self, nist_result: Dict, iso_result: Dict) -> Dict:
        """Gera relatório consolidado com recomendações priorizadas."""
        recommendations = []
        for function, data in nist_result["function_scores"].items():
            for gap in data["gaps"]:
                recommendations.append(
                    {"priority": "Alta", "framework": "NIST", "function": function, "gap": gap}
                )
        for nc in iso_result["non_conformities"]:
            recommendations.append(
                {"priority": "Média", "framework": "ISO 42001", "control": nc}
            )

        report = {
            "report_type": "AI Governance Maturity Assessment",
            "system_name": self.system_name,
            "date": datetime.now().isoformat(),
            "nist_ai_rmf": nist_result,
            "iso_42001": iso_result,
            "combined_maturity": round(
                (nist_result["overall_maturity"] + iso_result["average_score"]) / 2, 2
            ),
            "total_recommendations": len(recommendations),
            "prioritized_recommendations": recommendations[:15],
        }

        out = self.log_dir / f"governance_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        logger.info(f"Relatório de governança salvo em {out}")
        report["report_file"] = str(out)
        return report


def demo():
    logging.basicConfig(level=logging.INFO)
    assessment = AIGovernanceAssessment("CyberLab ML Pipeline")

    # Respostas de exemplo (simulando um sistema em maturidade média)
    nist_responses = {
        "GOVERN": [3, 3, 2, 3],
        "MAP": [4, 3, 3, 4],   # MITRE ATLAS mapeado = 4
        "MEASURE": [4, 4, 2, 4],  # robustez adversarial testada = 4
        "MANAGE": [3, 4, 3, 2],
    }
    iso_scores = [3, 2, 3, 4, 3, 4, 3, 2, 3, 2]

    nist = assessment.assess_nist_rmf(nist_responses)
    iso = assessment.assess_iso_42001(iso_scores)
    report = assessment.generate_report(nist, iso)

    print(f"\n=== AI Governance Assessment: {assessment.system_name} ===")
    print(f"NIST AI RMF maturidade: {nist['overall_maturity']}/5 ({nist['overall_level']})")
    print(f"ISO/IEC 42001 conformidade: {iso['conformity_percentage']}%")
    print(f"Maturidade combinada: {report['combined_maturity']}/5")
    print(f"Recomendações priorizadas: {report['total_recommendations']}")


if __name__ == "__main__":
    demo()

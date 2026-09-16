"""
phishing_detector.py - Detecção de Phishing por IA (texto + URL)

Complementa o text_detector com sinais específicos de phishing gerado por IA:

1. BURSTINESS: texto humano alterna sentenças curtas e longas (alta variância de
   comprimento); texto de LLM tende a ser mais uniforme (baixa burstiness).
2. HEURÍSTICAS DE URL: typosquatting (distância de edição a domínios legítimos),
   homoglyphs (caracteres visualmente idênticos), TLD suspeito, subdomínio-isca.
3. LLM-AS-JUDGE: interface para um LLM avaliar o texto (aqui, um juiz heurístico
   determinístico que emula o padrão de decisão — plugável a uma API real).
"""

import re
import json
import logging
from typing import Dict, List
from pathlib import Path
from datetime import datetime
import numpy as np

logger = logging.getLogger(__name__)


class PhishingDetector:
    """Detecção de phishing combinando sinais de texto e URL."""

    LEGIT_DOMAINS = [
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "paypal.com", "netflix.com", "itau.com.br", "bradesco.com.br",
        "nubank.com.br", "gov.br",
    ]
    SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".zip", ".mov"}
    # Mapa simples de homoglyphs comuns
    HOMOGLYPHS = {"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "rn": "m"}
    URGENCY_WORDS = ["urgent", "immediately", "verify now", "suspended", "expire",
                     "urgente", "imediatamente", "verifique agora", "bloqueado", "expira"]

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/synthetic_media")
        self.log_dir.mkdir(exist_ok=True, parents=True)

    # ---- Texto ----
    def burstiness(self, text: str) -> float:
        """Variância normalizada dos comprimentos de sentença (humano = alta)."""
        sents = [s for s in re.split(r"[.!?]+", text) if s.strip()]
        lengths = [len(s.split()) for s in sents]
        if len(lengths) < 2:
            return 0.0
        return float(np.std(lengths) / (np.mean(lengths) + 1e-9))

    # ---- URL ----
    @staticmethod
    def _edit_distance(a: str, b: str) -> int:
        dp = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            prev, dp[0] = dp[0], i
            for j, cb in enumerate(b, 1):
                prev, dp[j] = dp[j], min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
        return dp[-1]

    def _normalize_homoglyphs(self, domain: str) -> str:
        d = domain.lower()
        for k, v in self.HOMOGLYPHS.items():
            d = d.replace(k, v)
        return d

    def analyze_url(self, url: str) -> Dict:
        """Analisa uma URL em busca de sinais de phishing."""
        url_l = url.lower()
        domain = re.sub(r"^https?://", "", url_l).split("/")[0]
        tld = "." + domain.split(".")[-1] if "." in domain else ""

        indicators = []
        score = 0.0

        # Typosquatting: perto de um domínio legítimo mas não idêntico
        normalized = self._normalize_homoglyphs(domain)
        for legit in self.LEGIT_DOMAINS:
            dist = self._edit_distance(normalized, legit)
            if 0 < dist <= 2:
                indicators.append(f"typosquatting de {legit} (distância {dist})")
                score += 0.5
                break

        # Homoglyph detectado (normalização mudou o domínio p/ um legítimo)
        if normalized != domain and normalized in self.LEGIT_DOMAINS:
            indicators.append("homoglyph imitando domínio legítimo")
            score += 0.4

        # TLD suspeito
        if tld in self.SUSPICIOUS_TLDS:
            indicators.append(f"TLD suspeito ({tld})")
            score += 0.3

        # Marca legítima em subdomínio de outro domínio (ex: paypal.secure-login.xyz)
        for legit in self.LEGIT_DOMAINS:
            brand = legit.split(".")[0]
            if brand in domain and not domain.endswith(legit):
                indicators.append(f"marca '{brand}' em domínio não-oficial")
                score += 0.4
                break

        return {
            "url": url,
            "domain": domain,
            "phishing_score": float(min(1.0, score)),
            "indicators": indicators,
            "is_phishing_url": score >= 0.5,
        }

    def llm_as_judge(self, text: str) -> Dict:
        """
        Juiz heurístico que emula um LLM-as-judge (plugável a uma API real).
        Avalia urgência, pedido de credenciais e tom genérico.
        """
        t = text.lower()
        urgency = sum(1 for w in self.URGENCY_WORDS if w in t)
        asks_credentials = any(w in t for w in ["password", "senha", "cpf", "cartão",
                                                 "card number", "login", "account"])
        generic_greeting = any(w in t for w in ["dear customer", "prezado cliente",
                                                "dear user", "caro usuário"])
        verdict_score = min(1.0, 0.25 * urgency + 0.4 * asks_credentials + 0.2 * generic_greeting)
        return {
            "urgency_signals": urgency,
            "asks_credentials": asks_credentials,
            "generic_greeting": generic_greeting,
            "judge_score": float(verdict_score),
            "verdict": "PHISHING provável" if verdict_score >= 0.5 else "Baixo risco",
        }

    def analyze(self, text: str, urls: List[str] = None) -> Dict:
        """Análise combinada de um e-mail/mensagem suspeita."""
        urls = urls or re.findall(r"https?://[^\s]+", text)
        burst = self.burstiness(text)
        judge = self.llm_as_judge(text)
        url_results = [self.analyze_url(u) for u in urls]
        max_url_score = max([r["phishing_score"] for r in url_results], default=0.0)

        # Combinar: LLM-judge + URL + baixa burstiness (indício de geração por LLM)
        low_burstiness = burst < 0.4
        combined = min(1.0, 0.5 * judge["judge_score"] + 0.4 * max_url_score +
                       0.1 * (1 if low_burstiness else 0))

        result = {
            "timestamp": datetime.now().isoformat(),
            "burstiness": burst,
            "low_burstiness_llm_signal": low_burstiness,
            "llm_as_judge": judge,
            "url_analysis": url_results,
            "combined_phishing_score": float(combined),
            "verdict": "PHISHING" if combined >= 0.5 else "Legítimo/baixo risco",
        }
        logger.info(f"Phishing analysis: {result['verdict']} (score={combined:.2f})")
        return result


def demo():
    logging.basicConfig(level=logging.INFO)
    det = PhishingDetector()

    phishing = ("Dear customer, your account will be suspended. Verify now your password "
                "at http://paypa1.com/login immediately.")
    legit = ("Oi Ana, tudo bem? Segue o relatório que combinamos. Qualquer coisa me chama. "
             "Ele ficou bem completo, com os gráficos do trimestre e as notas de rodapé.")

    print("\n=== E-mail suspeito ===")
    r1 = det.analyze(phishing)
    print(f"{r1['verdict']} (score={r1['combined_phishing_score']:.2f})")
    for u in r1["url_analysis"]:
        print(f"  URL {u['domain']}: {u['indicators']}")

    print("\n=== E-mail legítimo ===")
    r2 = det.analyze(legit)
    print(f"{r2['verdict']} (score={r2['combined_phishing_score']:.2f})")


if __name__ == "__main__":
    demo()

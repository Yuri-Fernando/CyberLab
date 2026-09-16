"""
text_detector.py - Detecção de Texto Gerado por IA/LLM

Implementa múltiplas técnicas para identificar texto sintético:

1. Perplexidade: Mede quão bem um modelo de linguagem prediz o texto
2. Estilometria: Análise de padrões de escrita (pontuação, tamanho de palavras)
3. Heurísticas de Domínio: Padrões específicos de LLMs (ex: "as an AI...")
4. Entropia: Distribuição de palavras

IMPORTANTE: Nenhuma técnica é 100% precisa. Verdade: há sempre trade-off entre
precision e recall. Método mais robusto: combinação de técnicas.
"""

import json
import logging
import re
from typing import Dict, Tuple
from pathlib import Path
from datetime import datetime
from collections import Counter
import numpy as np

logger = logging.getLogger(__name__)


class TextSyntheticDetector:
    """Detecta texto gerado por IA/LLM."""

    # Padrões comuns de LLMs
    LLM_PATTERNS = [
        r"as an ai",
        r"as an artificial intelligence",
        r"as a language model",
        r"i'm an ai",
        r"i cannot",
        r"i don't have",
        r"ultimately",
        r"in conclusion",
        r"to summarize",
        r"it's important to note",
        r"that being said",
        r"however",
        r"furthermore",
    ]

    def __init__(self, log_dir: Path = None):
        """Inicializa detector."""
        self.log_dir = log_dir or Path("./results/synthetic_media")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.detections = []

    def calculate_perplexity(self, text: str) -> float:
        """
        Calcula perplexidade aproximada do texto.

        Perplexidade baixa (< 50): Texto previsível, potencialmente sintético
        Perplexidade alta (> 200): Texto com mais variação, mais natural

        NOTA: Implementação simplificada. Versão real usaria modelo de linguagem.

        Args:
            text: Texto para análise

        Returns:
            Estimativa de perplexidade
        """
        words = text.lower().split()
        if len(words) < 10:
            return 0.0

        # Calcular frequência de palavras
        word_freq = Counter(words)
        total_words = len(words)
        unique_words = len(word_freq)

        # Entropia (proxy para perplexidade)
        entropy = 0
        for count in word_freq.values():
            prob = count / total_words
            if prob > 0:
                entropy -= prob * np.log2(prob)

        perplexity = 2 ** entropy
        return float(perplexity)

    def calculate_stylometry(self, text: str) -> Dict[str, float]:
        """
        Análise estilométrica de padrões de escrita.

        Características:
        - Tamanho médio de palavra
        - Tamanho médio de sentença
        - Proporção de pontuação
        - Diversidade lexical

        Returns:
            Dict com métricas estilométricas
        """
        words = text.split()
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if s.strip()]

        if not words or not sentences:
            return {}

        # Calcular métricas
        avg_word_length = np.mean([len(w) for w in words])
        avg_sentence_length = np.mean([len(s.split()) for s in sentences])
        punctuation_ratio = len(re.findall(r'[.!?,;:\-]', text)) / len(text)

        # Diversidade lexical (Type-Token Ratio)
        unique_words = len(set(w.lower() for w in words))
        type_token_ratio = unique_words / len(words)

        return {
            "avg_word_length": float(avg_word_length),
            "avg_sentence_length": float(avg_sentence_length),
            "punctuation_ratio": float(punctuation_ratio),
            "type_token_ratio": float(type_token_ratio)
        }

    def detect_llm_patterns(self, text: str) -> Dict:
        """
        Detecta padrões típicos de LLMs (ex: "as an AI...").

        Retorna:
            Dict com padrões encontrados e contagem
        """
        text_lower = text.lower()
        matched_patterns = []

        for pattern in self.LLM_PATTERNS:
            if re.search(pattern, text_lower):
                matched_patterns.append(pattern)

        return {
            "llm_patterns_found": len(matched_patterns),
            "patterns": matched_patterns,
            "suspicious": len(matched_patterns) >= 3  # 3+ padrões = suspeito
        }

    def predict_synthetic(
        self,
        text: str,
        threshold: float = 0.5
    ) -> Tuple[bool, float, Dict]:
        """
        Prediz se texto é sintético (gerado por IA).

        Combina múltiplas sinais:
        1. Perplexidade (baixa = suspeita)
        2. Padrões de LLM (muitos padrões = suspeita)
        3. Estilometria (desvios = suspeita)

        Args:
            text: Texto para análise
            threshold: Limite de confiança (0.0-1.0)

        Returns:
            (is_synthetic, confidence, evidence)
        """
        logger.info(f"Analisando texto ({len(text)} caracteres)...")

        # Coletar evidências
        perplexity = self.calculate_perplexity(text)
        stylometry = self.calculate_stylometry(text)
        llm_patterns = self.detect_llm_patterns(text)

        # Score de síntese (0-1)
        scores = []

        # Score 1: Perplexidade (50-150 = natural, <50 ou >200 = suspeita)
        if perplexity < 50:
            scores.append(0.8)  # Muito previsível
        elif perplexity > 200:
            scores.append(0.2)  # Muito variável
        else:
            scores.append(0.3)  # Normal

        # Score 2: Padrões LLM
        if llm_patterns["suspicious"]:
            scores.append(0.7)  # Padrões LLM
        else:
            scores.append(0.2)  # Sem padrões típicos

        # Score 3: Estilometria
        type_token_ratio = stylometry.get("type_token_ratio", 0.5)
        if type_token_ratio > 0.7:  # Muito diversidade lexical
            scores.append(0.6)  # Indicador de síntese
        else:
            scores.append(0.3)

        confidence = np.mean(scores)
        is_synthetic = confidence >= threshold

        evidence = {
            "perplexity": perplexity,
            "stylometry": stylometry,
            "llm_patterns": llm_patterns,
            "scores": scores,
            "final_confidence": float(confidence)
        }

        logger.info(
            f"Resultado: Sintético={is_synthetic}, "
            f"Confiança={confidence:.2%}, "
            f"Perplexidade={perplexity:.1f}"
        )

        return is_synthetic, confidence, evidence

    def analyze_batch(self, texts: list, names: list = None) -> list:
        """Analisa lote de textos."""
        results = []

        for i, text in enumerate(texts):
            name = names[i] if names and i < len(names) else f"Text {i+1}"
            is_synthetic, confidence, evidence = self.predict_synthetic(text)

            result = {
                "name": name,
                "is_synthetic": is_synthetic,
                "confidence": confidence,
                "text_length": len(text),
                "evidence": evidence
            }
            results.append(result)

        self.detections.append({
            "timestamp": datetime.now().isoformat(),
            "batch_size": len(texts),
            "results": results
        })

        return results

    def save_analysis(self) -> str:
        """Salva análise em JSON."""
        if not self.detections:
            logger.warning("Nenhuma análise para salvar")
            return None

        output_file = self.log_dir / f"text_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        try:
            with open(output_file, "w") as f:
                json.dump(self.detections[-1], f, indent=2)
            logger.info(f"Análise salva em {output_file}")
            return str(output_file)
        except Exception as e:
            logger.error(f"Erro ao salvar: {str(e)}")
            return None


def demo_text_detection():
    """Demo de detecção de texto sintético."""
    logging.basicConfig(level=logging.INFO)

    detector = TextSyntheticDetector()

    # Exemplos
    natural_text = """
    The weather in São Paulo today is quite humid. I noticed the sky changing around noon,
    with clouds forming rapidly. Many people were carrying umbrellas just in case. The city's
    energy was different, more cautious. I walked through the streets observing how nature
    affects human behavior in subtle but persistent ways.
    """

    llm_text = """
    As an AI language model, I must note that the weather patterns are highly significant.
    Ultimately, the meteorological conditions in São Paulo demonstrate interesting variations.
    Furthermore, it's important to note that humidity levels affect human perception. In conclusion,
    weather systems continue to be complex phenomena worthy of our attention and study.
    """

    results = detector.analyze_batch(
        [natural_text, llm_text],
        ["Natural Text", "LLM-Generated Text"]
    )

    for result in results:
        print(f"\n{result['name']}: {result['is_synthetic']} "
              f"(Confiança: {result['confidence']:.2%})")
        print(f"  Perplexidade: {result['evidence']['perplexity']:.1f}")
        print(f"  Padrões LLM: {result['evidence']['llm_patterns']['llm_patterns_found']}")


if __name__ == "__main__":
    demo_text_detection()

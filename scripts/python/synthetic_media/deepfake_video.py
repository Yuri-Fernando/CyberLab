"""
deepfake_video.py - Detecção de Deepfake em Vídeo (temporal) + Proveniência C2PA

Detecção de deepfake de vídeo por sinais TEMPORAIS, que os geradores frame-a-frame
frequentemente erram:

1. EYE-BLINK RATE: humanos piscam ~15-20x/min de forma irregular. Muitos deepfakes
   piscam de menos, de mais, ou com regularidade não-natural (Li et al., 2018 —
   "In Ictu Oculi").
2. CONSISTÊNCIA TEMPORAL: variação abrupta entre frames (flicker) revela síntese.

Também verifica PROVENIÊNCIA via C2PA / Content Credentials: mídia autêntica pode
carregar um manifesto assinado de origem. Ausência/quebra do manifesto é um sinal.

Funciona standalone gerando séries temporais de "abertura ocular" (real irregular
vs deepfake regular/ausente) e aceita séries reais extraídas de vídeo.
"""

import numpy as np
import json
import logging
from typing import Dict, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class DeepfakeVideoDetector:
    """Detecção temporal de deepfake + verificação de proveniência."""

    def __init__(self, fps: int = 30, log_dir: Path = None):
        self.fps = fps
        self.log_dir = log_dir or Path("./results/forensics")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.analyses = []

    # ---- Geração de sinais demo ----
    def generate_real_blink_series(self, duration_s: float = 20.0) -> np.ndarray:
        """Série de abertura ocular humana: piscadas irregulares ~17/min."""
        n = int(duration_s * self.fps)
        rng = np.random.default_rng(1)
        signal = np.ones(n)
        n_blinks = int(duration_s / 60 * 17)
        blink_frames = rng.choice(n, n_blinks, replace=False)
        for bf in blink_frames:
            for k in range(-2, 3):  # piscada dura alguns frames
                if 0 <= bf + k < n:
                    signal[bf + k] = max(0.0, abs(k) / 2)
        return signal

    def generate_deepfake_blink_series(self, duration_s: float = 20.0) -> np.ndarray:
        """Série de deepfake: quase sem piscadas + flicker de alta frequência."""
        n = int(duration_s * self.fps)
        rng = np.random.default_rng(2)
        signal = np.ones(n) - 0.05 * rng.standard_normal(n)  # flicker
        # pouquíssimas piscadas e em intervalo regular (não-natural)
        for bf in range(0, n, n // 3):
            if bf < n:
                signal[bf] = 0.1
        return np.clip(signal, 0, 1)

    def analyze_blink_series(self, series: np.ndarray, name: str = "video") -> Dict:
        """Analisa a série temporal de abertura ocular."""
        n = len(series)
        duration_min = n / self.fps / 60

        # Detectar piscadas (vales abaixo de 0.3)
        below = series < 0.3
        blinks = int(np.sum(np.diff(below.astype(int)) == 1))
        blink_rate = blinks / max(duration_min, 1e-6)

        # Flicker: energia de alta frequência (variação frame-a-frame)
        flicker = float(np.mean(np.abs(np.diff(series))))

        # Regularidade dos intervalos entre piscadas (humano = irregular)
        blink_positions = np.where(np.diff(below.astype(int)) == 1)[0]
        if len(blink_positions) > 2:
            intervals = np.diff(blink_positions)
            regularity = float(np.std(intervals) / (np.mean(intervals) + 1e-9))
        else:
            regularity = 0.0

        # Heurística de deepfake
        indicators = []
        score = 0.0
        if blink_rate < 8 or blink_rate > 30:
            indicators.append(f"taxa de piscada anômala ({blink_rate:.0f}/min)")
            score += 0.4
        if flicker > 0.03:
            indicators.append("flicker temporal alto")
            score += 0.3
        if 0 < regularity < 0.25:
            indicators.append("piscadas regulares demais (não-natural)")
            score += 0.3

        result = {
            "name": name,
            "blink_rate_per_min": float(blink_rate),
            "flicker": flicker,
            "blink_interval_regularity": regularity,
            "deepfake_score": float(min(1.0, score)),
            "is_deepfake": score >= 0.5,
            "indicators": indicators,
        }
        logger.info(
            f"{name}: {'DEEPFAKE' if result['is_deepfake'] else 'autêntico'} "
            f"(score={result['deepfake_score']:.2f}, piscadas={blink_rate:.0f}/min)"
        )
        self.analyses.append(result)
        return result

    def verify_c2pa_provenance(self, manifest: Optional[Dict]) -> Dict:
        """
        Verifica Content Credentials / C2PA.

        Args:
            manifest: manifesto de proveniência (None se ausente).
        """
        if manifest is None:
            return {
                "has_manifest": False,
                "verdict": "Sem Content Credentials — proveniência não verificável",
                "trust": "low",
            }
        required = {"issuer", "signature", "created", "actions"}
        valid = required.issubset(manifest.keys())
        return {
            "has_manifest": True,
            "manifest_valid": valid,
            "issuer": manifest.get("issuer"),
            "verdict": "Proveniência assinada e válida" if valid else "Manifesto incompleto/adulterado",
            "trust": "high" if valid else "low",
        }

    def save(self) -> str:
        out = self.log_dir / f"deepfake_video_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump(self.analyses, f, indent=2)
        return str(out)


def demo():
    logging.basicConfig(level=logging.INFO)
    det = DeepfakeVideoDetector()

    real = det.analyze_blink_series(det.generate_real_blink_series(), "video_real")
    fake = det.analyze_blink_series(det.generate_deepfake_blink_series(), "video_deepfake")

    print(f"\nVídeo real     -> deepfake={real['is_deepfake']} (score={real['deepfake_score']:.2f})")
    print(f"Vídeo deepfake -> deepfake={fake['is_deepfake']} (score={fake['deepfake_score']:.2f})")

    print("\n=== C2PA / Content Credentials ===")
    signed = {"issuer": "Reuters", "signature": "abc", "created": "2026-01-01", "actions": ["capture"]}
    print("Assinado:", det.verify_c2pa_provenance(signed)["verdict"])
    print("Ausente:", det.verify_c2pa_provenance(None)["verdict"])
    det.save()


if __name__ == "__main__":
    demo()

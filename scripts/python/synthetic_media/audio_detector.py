"""
audio_detector.py - Detecção de Voice Cloning com MFCC/librosa

Detecção técnica de áudio sintético (voz clonada) via análise espectral real.

Extrai features acústicas com librosa e pontua a probabilidade de síntese com base
em artefatos conhecidos de vocoders/TTS:
- MFCCs (Mel-Frequency Cepstral Coefficients): compressão perceptual da voz.
- Spectral flatness: voz sintética tende a ser mais "plana"/tonal em regiões.
- Spectral centroid / bandwidth: distribuição de energia.
- Zero-crossing rate: micro-variações naturais da fala humana.
- Jitter/shimmer proxy: variação de energia frame-a-frame (voz real varia mais).

Alinhado com pipelines anti-spoofing (ASVspoof/AASIST): as mesmas famílias de
features alimentam classificadores de spoofing. Este módulo é a camada de
feature-engineering + heurística; um classificador treinado plugaria aqui.

Funciona standalone gerando sinais demo, e aceita qualquer arquivo .wav real.
"""

import numpy as np
import json
import logging
from typing import Dict, Optional
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import librosa

    LIBROSA_AVAILABLE = True
except Exception:  # pragma: no cover
    LIBROSA_AVAILABLE = False
    logger.warning("librosa indisponível — usando fallback numpy para features.")


class VoiceCloningDetector:
    """Detecta voz sintética via features espectrais (MFCC e afins)."""

    def __init__(self, sample_rate: int = 16000, log_dir: Path = None):
        self.sr = sample_rate
        self.log_dir = log_dir or Path("./results/synthetic_media")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.detections = []

    # ---- Geração de sinais demo (para rodar sem arquivos externos) ----
    def generate_demo_natural(self, duration: float = 2.0) -> np.ndarray:
        """Sinal 'natural': múltiplos harmônicos + jitter/shimmer + ruído de sopro."""
        t = np.linspace(0, duration, int(self.sr * duration), endpoint=False)
        f0 = 120 + 8 * np.sin(2 * np.pi * 4 * t)  # pitch com micro-variação (jitter)
        signal = np.zeros_like(t)
        for k, amp in enumerate([1.0, 0.5, 0.33, 0.25], start=1):
            shimmer = 1 + 0.05 * np.random.randn(len(t))  # variação de amplitude
            signal += amp * shimmer * np.sin(2 * np.pi * k * f0 * t)
        signal += 0.02 * np.random.randn(len(t))  # ruído de sopro/ambiente
        env = np.clip(np.sin(2 * np.pi * 2.5 * t) ** 2 + 0.3, 0, 1)  # prosódia
        return (signal * env).astype(np.float32)

    def generate_demo_synthetic(self, duration: float = 2.0) -> np.ndarray:
        """Sinal 'sintético': tom estável, poucos harmônicos, sem jitter — típico de TTS simples."""
        t = np.linspace(0, duration, int(self.sr * duration), endpoint=False)
        f0 = 120.0  # pitch perfeitamente constante (artefato de síntese)
        signal = np.sin(2 * np.pi * f0 * t) + 0.3 * np.sin(2 * np.pi * 2 * f0 * t)
        return signal.astype(np.float32)

    # ---- Extração de features ----
    def extract_features(self, y: np.ndarray) -> Dict[str, float]:
        """Extrai features acústicas (librosa se disponível, senão numpy)."""
        if LIBROSA_AVAILABLE:
            mfcc = librosa.feature.mfcc(y=y, sr=self.sr, n_mfcc=13)
            flatness = librosa.feature.spectral_flatness(y=y)[0]
            centroid = librosa.feature.spectral_centroid(y=y, sr=self.sr)[0]
            bandwidth = librosa.feature.spectral_bandwidth(y=y, sr=self.sr)[0]
            zcr = librosa.feature.zero_crossing_rate(y)[0]
            return {
                "mfcc_mean_var": float(np.var(mfcc, axis=1).mean()),
                "mfcc_temporal_var": float(np.var(mfcc, axis=0).mean()),
                "spectral_flatness_mean": float(flatness.mean()),
                "spectral_centroid_std": float(centroid.std()),
                "spectral_bandwidth_mean": float(bandwidth.mean()),
                "zcr_std": float(zcr.std()),
                "energy_frame_var": float(np.var(np.abs(y))),
            }
        # Fallback numpy (FFT simples)
        spec = np.abs(np.fft.rfft(y))
        spec_norm = spec / (spec.sum() + 1e-12)
        flatness = np.exp(np.mean(np.log(spec + 1e-12))) / (np.mean(spec) + 1e-12)
        centroid = np.sum(np.arange(len(spec)) * spec_norm)
        zcr = np.mean(np.abs(np.diff(np.sign(y)))) / 2
        return {
            "mfcc_mean_var": float(np.var(spec)),
            "mfcc_temporal_var": 0.0,
            "spectral_flatness_mean": float(flatness),
            "spectral_centroid_std": float(centroid),
            "spectral_bandwidth_mean": 0.0,
            "zcr_std": float(zcr),
            "energy_frame_var": float(np.var(np.abs(y))),
        }

    def detect(self, y: np.ndarray, name: str = "audio") -> Dict:
        """
        Pontua probabilidade de síntese com base nas features.

        Heurística (calibrada em features reais): voz sintética simples tem
        espectro mais estável e estreito que a fala humana natural:
        - baixo desvio do spectral centroid (espectro não varia como na fala real);
        - bandwidth espectral estreito (poucos harmônicos vs riqueza da voz humana);
        - baixa variância entre coeficientes MFCC;
        - baixa variação de zero-crossing rate (sem micro-variações da fala).
        """
        f = self.extract_features(y)

        score = 0.0
        signals = []

        # Espectro estável demais (centroid quase não varia) => síntese
        if f["spectral_centroid_std"] < 50.0:
            score += 0.3
            signals.append("centroid_espectral_estavel")
        # Bandwidth estreito => poucos harmônicos, típico de TTS simples
        if f["spectral_bandwidth_mean"] < 500.0:
            score += 0.3
            signals.append("bandwidth_estreito")
        # Baixa variância entre coeficientes MFCC
        if f["mfcc_mean_var"] < 300.0:
            score += 0.2
            signals.append("baixa_variancia_mfcc")
        # Baixa variação de ZCR => sem micro-variações da fala
        if f["zcr_std"] < 0.005:
            score += 0.2
            signals.append("baixa_variacao_zcr")

        is_synthetic = score >= 0.5
        result = {
            "name": name,
            "is_synthetic": is_synthetic,
            "synthetic_score": float(score),
            "features": f,
            "triggered_signals": signals,
            "recommendation": (
                "Verificação por callback recomendada (possível voz clonada)"
                if is_synthetic
                else "Áudio consistente com voz humana"
            ),
        }
        logger.info(
            f"{name}: {'SINTÉTICO' if is_synthetic else 'natural'} "
            f"(score={score:.2f}, sinais={signals})"
        )
        return result

    def detect_file(self, wav_path: str) -> Optional[Dict]:
        """Detecta a partir de um arquivo .wav real."""
        if not LIBROSA_AVAILABLE:
            logger.error("librosa necessário para carregar arquivos.")
            return None
        y, _ = librosa.load(wav_path, sr=self.sr, mono=True)
        return self.detect(y, name=Path(wav_path).name)

    def save(self, results: list) -> str:
        out = self.log_dir / f"voice_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump({"timestamp": datetime.now().isoformat(), "results": results}, f, indent=2)
        return str(out)


def demo():
    logging.basicConfig(level=logging.INFO)
    detector = VoiceCloningDetector()

    natural = detector.generate_demo_natural()
    synthetic = detector.generate_demo_synthetic()

    r1 = detector.detect(natural, "voz_humana_demo")
    r2 = detector.detect(synthetic, "voz_clonada_demo")

    print(f"\nVoz humana  -> sintético={r1['is_synthetic']} (score={r1['synthetic_score']:.2f})")
    print(f"Voz clonada -> sintético={r2['is_synthetic']} (score={r2['synthetic_score']:.2f})")
    detector.save([r1, r2])


if __name__ == "__main__":
    demo()

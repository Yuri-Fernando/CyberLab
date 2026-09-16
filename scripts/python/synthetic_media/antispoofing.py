"""
antispoofing.py - Anti-Spoofing de Voz (estilo ASVspoof) + Callback Verification

Vai além da heurística de features: treina um CLASSIFICADOR de anti-spoofing
(como os pipelines ASVspoof/AASIST), aprendendo a fronteira entre voz humana e
sintética a partir de exemplos rotulados de features acústicas.

Também implementa o controle organizacional de CALLBACK VERIFICATION: mesmo com
detecção técnica, operações sensíveis exigem verificação por canal independente
(ligar de volta para número conhecido) — a defesa mais eficaz contra vishing com
voz clonada (ex.: caso LastPass).
"""

import numpy as np
import json
import logging
from typing import Dict, List
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

logger = logging.getLogger(__name__)

# Reutiliza o extrator de features do detector espectral
try:
    from .audio_detector import VoiceCloningDetector
except ImportError:  # execução standalone
    from audio_detector import VoiceCloningDetector


class AntiSpoofingClassifier:
    """Classificador de anti-spoofing treinado em features acústicas."""

    FEATURE_KEYS = [
        "spectral_centroid_std",
        "spectral_bandwidth_mean",
        "mfcc_mean_var",
        "mfcc_temporal_var",
        "spectral_flatness_mean",
        "zcr_std",
        "energy_frame_var",
    ]

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/synthetic_media")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.detector = VoiceCloningDetector()
        self.model = None

    def _featurize(self, y: np.ndarray) -> List[float]:
        f = self.detector.extract_features(y)
        return [f[k] for k in self.FEATURE_KEYS]

    def build_dataset(self, n_per_class: int = 40) -> tuple:
        """Gera dataset de treino: vozes 'humanas' vs 'sintéticas' com variação."""
        X, y = [], []
        rng = np.random.default_rng(42)
        for _ in range(n_per_class):
            # variação de duração/pitch para robustez
            dur = float(rng.uniform(1.5, 2.5))
            X.append(self._featurize(self.detector.generate_demo_natural(dur)))
            y.append(0)  # bonafide (humano)
            X.append(self._featurize(self.detector.generate_demo_synthetic(dur)))
            y.append(1)  # spoof (sintético)
        return np.array(X), np.array(y)

    def train(self, n_per_class: int = 40) -> Dict:
        """Treina o classificador e reporta acurácia por validação cruzada."""
        logger.info("Treinando classificador anti-spoofing (ASVspoof-style)...")
        X, y = self.build_dataset(n_per_class)
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        scores = cross_val_score(self.model, X, y, cv=5)
        self.model.fit(X, y)
        result = {
            "cv_accuracy_mean": float(scores.mean()),
            "cv_accuracy_std": float(scores.std()),
            "n_samples": len(X),
            "features": self.FEATURE_KEYS,
        }
        logger.info(f"  Acurácia CV: {scores.mean():.3f} ± {scores.std():.3f}")
        return result

    def score_audio(self, y: np.ndarray, name: str = "audio") -> Dict:
        """Pontua um áudio: probabilidade de spoof (voz sintética)."""
        if self.model is None:
            self.train()
        feats = np.array([self._featurize(y)])
        spoof_prob = float(self.model.predict_proba(feats)[0][1])
        return {
            "name": name,
            "spoof_probability": spoof_prob,
            "verdict": "SPOOF (voz sintética)" if spoof_prob > 0.5 else "BONAFIDE (humano)",
        }


class CallbackVerification:
    """Controle organizacional: verificação por canal independente."""

    def __init__(self):
        self.known_contacts = {}
        self.verification_log = []

    def register_contact(self, identity: str, verified_number: str):
        self.known_contacts[identity] = verified_number

    def verify_request(
        self, claimed_identity: str, incoming_number: str, request_risk: str
    ) -> Dict:
        """
        Decide se uma solicitação sensível pode prosseguir.

        Regra: para risco alto, o número de origem deve bater com o cadastrado,
        senão exige callback ativo para o número conhecido antes de autorizar.
        """
        known = self.known_contacts.get(claimed_identity)
        number_matches = known == incoming_number
        requires_callback = request_risk in ("high", "critical") and not number_matches

        decision = {
            "timestamp": datetime.now().isoformat(),
            "claimed_identity": claimed_identity,
            "incoming_number": incoming_number,
            "number_matches_known": number_matches,
            "request_risk": request_risk,
            "requires_callback": requires_callback,
            "action": (
                "BLOQUEAR e ligar de volta para o número cadastrado antes de autorizar"
                if requires_callback
                else "Prosseguir com autorização padrão"
            ),
        }
        self.verification_log.append(decision)
        return decision


def demo():
    logging.basicConfig(level=logging.INFO)
    clf = AntiSpoofingClassifier()
    clf.train(n_per_class=40)

    natural = clf.detector.generate_demo_natural()
    synthetic = clf.detector.generate_demo_synthetic()
    print("\n=== Anti-Spoofing Classifier ===")
    print(clf.score_audio(natural, "voz_humana"))
    print(clf.score_audio(synthetic, "voz_clonada"))

    print("\n=== Callback Verification ===")
    cbv = CallbackVerification()
    cbv.register_contact("CEO", "+55-11-99999-0000")
    # Vishing: número diferente pedindo transferência crítica
    d = cbv.verify_request("CEO", "+55-11-98888-1234", "critical")
    print(f"Ação: {d['action']}")


if __name__ == "__main__":
    demo()

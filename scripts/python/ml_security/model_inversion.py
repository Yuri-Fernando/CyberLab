"""
model_inversion.py - Model Inversion Attack

Reconstrói um "protótipo" dos dados de treino de uma classe consultando o modelo.

Ideia: como modelos aprendem o que caracteriza cada classe, é possível otimizar
uma entrada sintética que maximize a confiança do modelo para uma classe-alvo.
O resultado aproxima as features médias que o modelo associa àquela classe —
vazando informação sobre o dado de treino (risco de privacidade, OWASP ML02).

Como modelos sklearn não são diferenciáveis de forma trivial, usamos otimização
sem gradiente (hill-climbing / random search com aceitação gulosa), que reflete
o cenário realista de acesso apenas à API (black-box).

Referência: Fredrikson et al. "Model Inversion Attacks..." (CCS 2015).
"""

import numpy as np
import json
import logging
from typing import Dict, Tuple
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class ModelInversionAttacker:
    """Ataque de inversão de modelo por otimização black-box."""

    def __init__(self, log_dir: Path = None, random_state: int = 42):
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.rng = np.random.default_rng(random_state)
        self.results = []

    def invert_class(
        self,
        model,
        target_class: int,
        n_features: int,
        feature_bounds: Tuple[np.ndarray, np.ndarray],
        iterations: int = 2000,
        step_scale: float = 0.1,
    ) -> Tuple[np.ndarray, Dict]:
        """
        Reconstrói um protótipo da classe-alvo.

        Args:
            model: Modelo com predict_proba.
            target_class: Classe cujo dado queremos reconstruir.
            n_features: Número de features.
            feature_bounds: (min_array, max_array) por feature.
            iterations: Número de iterações de otimização.
            step_scale: Escala do passo de perturbação.

        Returns:
            (reconstructed_input, metadata)
        """
        logger.info(f"Model Inversion: reconstruindo classe {target_class}...")
        low, high = feature_bounds

        # Ponto inicial aleatório dentro dos bounds
        x = self.rng.uniform(low, high)
        best_conf = model.predict_proba([x])[0][target_class]

        confidence_history = [float(best_conf)]

        for it in range(iterations):
            # Perturbação gaussiana proporcional ao range de cada feature
            noise = self.rng.normal(0, step_scale, n_features) * (high - low)
            candidate = np.clip(x + noise, low, high)
            conf = model.predict_proba([candidate])[0][target_class]

            if conf > best_conf:  # aceitação gulosa
                x = candidate
                best_conf = conf

            if it % 200 == 0:
                confidence_history.append(float(best_conf))

        metadata = {
            "attack_type": "Model Inversion",
            "target_class": int(target_class),
            "iterations": iterations,
            "final_confidence": float(best_conf),
            "confidence_history": confidence_history,
            "timestamp": datetime.now().isoformat(),
        }
        logger.info(
            f"  Reconstrução completa: confiança final={best_conf:.3f}"
        )
        return x, metadata

    def evaluate_reconstruction(
        self,
        reconstructed: np.ndarray,
        X_train: np.ndarray,
        y_train: np.ndarray,
        target_class: int,
        metadata: Dict,
    ) -> Dict:
        """Compara o protótipo reconstruído com a média real da classe (leakage)."""
        class_mean = X_train[y_train == target_class].mean(axis=0)
        # Similaridade cosseno entre reconstrução e média verdadeira da classe
        cos = float(
            np.dot(reconstructed, class_mean)
            / (np.linalg.norm(reconstructed) * np.linalg.norm(class_mean) + 1e-12)
        )
        mae = float(np.mean(np.abs(reconstructed - class_mean)))

        result = {
            **metadata,
            "cosine_similarity_to_true_class_mean": cos,
            "mean_absolute_error": mae,
            "privacy_leakage": "High" if cos > 0.8 else "Medium" if cos > 0.5 else "Low",
        }
        logger.info(
            f"  Leakage: cos_sim={cos:.3f} ({result['privacy_leakage']}), MAE={mae:.3f}"
        )
        self.results.append(result)
        return result

    def save_results(self) -> str:
        if not self.results:
            return None
        out = self.log_dir / f"inversion_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump(self.results[-1], f, indent=2)
        return str(out)


def demo():
    logging.basicConfig(level=logging.INFO)
    from sklearn.datasets import load_iris
    from sklearn.model_selection import train_test_split
    from sklearn.ensemble import RandomForestClassifier

    iris = load_iris()
    X, y = iris.data, iris.target
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    attacker = ModelInversionAttacker()
    bounds = (X_train.min(axis=0), X_train.max(axis=0))

    for target in np.unique(y_train):
        recon, meta = attacker.invert_class(
            model, int(target), X.shape[1], bounds, iterations=1500
        )
        result = attacker.evaluate_reconstruction(recon, X_train, y_train, int(target), meta)
        print(
            f"Classe {target}: cos_sim={result['cosine_similarity_to_true_class_mean']:.3f} "
            f"({result['privacy_leakage']} leakage)"
        )
    attacker.save_results()


if __name__ == "__main__":
    demo()

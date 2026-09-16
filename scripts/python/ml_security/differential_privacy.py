"""
differential_privacy.py - Treinamento Privado com DP-SGD

Implementa Differential Privacy via DP-SGD (Differentially Private Stochastic
Gradient Descent) do zero, em numpy, sobre uma regressão logística.

DP-SGD adiciona duas modificações ao SGD tradicional:
1. Per-example gradient clipping: limita a norma do gradiente de cada exemplo
   (bounded sensitivity), garantindo que nenhum exemplo domine a atualização.
2. Gaussian noise: adiciona ruído gaussiano calibrado ao gradiente agregado,
   fornecendo a garantia formal (epsilon, delta)-DP.

Trade-off privacidade vs utilidade: mais ruído (epsilon menor) = mais privacidade,
menos acurácia. Este módulo mede exatamente esse trade-off.

Referências:
- Abadi et al. "Deep Learning with Differential Privacy" (CCS 2016)
- Equivalente conceitual a Opacus (PyTorch) e TensorFlow Privacy, em numpy puro.
"""

import numpy as np
import json
import logging
from typing import Dict, Tuple
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))


class DPLogisticRegression:
    """Regressão logística treinada com DP-SGD (numpy puro)."""

    def __init__(
        self,
        l2_clip: float = 1.0,
        noise_multiplier: float = 1.0,
        learning_rate: float = 0.1,
        epochs: int = 50,
        batch_size: int = 32,
        random_state: int = 42,
    ):
        """
        Args:
            l2_clip: Norma máxima (C) para clipping do gradiente por exemplo.
            noise_multiplier: Sigma. Ruído = noise_multiplier * l2_clip.
                              Maior = mais privacidade, menos utilidade.
            learning_rate: Taxa de aprendizado.
            epochs: Número de épocas.
            batch_size: Tamanho do lote (lot).
            random_state: Semente.
        """
        self.l2_clip = l2_clip
        self.noise_multiplier = noise_multiplier
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.batch_size = batch_size
        self.random_state = random_state
        self.weights = None
        self.bias = None
        self.n_samples_ = None

    def _per_example_gradients(
        self, X_batch: np.ndarray, y_batch: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Calcula gradiente por exemplo (necessário para clipping individual)."""
        z = X_batch @ self.weights + self.bias
        preds = _sigmoid(z)
        errors = preds - y_batch  # shape (batch,)
        grads_w = errors[:, None] * X_batch  # (batch, n_features)
        grads_b = errors  # (batch,)
        return grads_w, grads_b

    @staticmethod
    def _clip_gradients(grads_w: np.ndarray, grads_b: np.ndarray, clip: float):
        """Clipa cada gradiente individual para norma <= clip (sensibilidade limitada)."""
        flat = np.hstack([grads_w, grads_b[:, None]])
        norms = np.linalg.norm(flat, axis=1) + 1e-12
        factors = np.minimum(1.0, clip / norms)
        grads_w = grads_w * factors[:, None]
        grads_b = grads_b * factors
        return grads_w, grads_b

    def fit(self, X: np.ndarray, y: np.ndarray) -> "DPLogisticRegression":
        rng = np.random.default_rng(self.random_state)
        n_samples, n_features = X.shape
        self.n_samples_ = n_samples
        self.weights = np.zeros(n_features)
        self.bias = 0.0

        for epoch in range(self.epochs):
            idx = rng.permutation(n_samples)
            for start in range(0, n_samples, self.batch_size):
                batch_idx = idx[start : start + self.batch_size]
                X_b, y_b = X[batch_idx], y[batch_idx]

                grads_w, grads_b = self._per_example_gradients(X_b, y_b)
                # 1) Clipping por exemplo (sensibilidade limitada)
                grads_w, grads_b = self._clip_gradients(grads_w, grads_b, self.l2_clip)

                # 2) Soma + ruído gaussiano calibrado (garantia DP)
                sigma = self.noise_multiplier * self.l2_clip
                sum_gw = grads_w.sum(axis=0) + rng.normal(0, sigma, size=n_features)
                sum_gb = grads_b.sum() + rng.normal(0, sigma)

                lot = len(batch_idx)
                self.weights -= self.learning_rate * (sum_gw / lot)
                self.bias -= self.learning_rate * (sum_gb / lot)

        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        p1 = _sigmoid(X @ self.weights + self.bias)
        return np.vstack([1 - p1, p1]).T

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)

    def score(self, X: np.ndarray, y: np.ndarray) -> float:
        return float((self.predict(X) == y).mean())

    def epsilon_estimate(self, delta: float = 1e-5) -> float:
        """
        Estimativa simplificada do budget de privacidade (epsilon).

        NOTA: Estimativa educacional. Contabilidade rigorosa usaria o
        Moments Accountant / RDP (Rényi DP) como em Opacus/TF-Privacy.
        Aqui usamos uma aproximação monotônica para demonstrar o trade-off:
        epsilon menor quando noise_multiplier maior.
        """
        q = self.batch_size / max(self.n_samples_, 1)
        steps = self.epochs * max(self.n_samples_ // self.batch_size, 1)
        sigma = self.noise_multiplier
        # Aproximação heurística (não é garantia formal, apenas demonstrativa)
        epsilon = (q * np.sqrt(steps * np.log(1 / delta))) / sigma
        return float(epsilon)


class DifferentialPrivacyExperiment:
    """Compara modelo privado vs não-privado e mede trade-off privacidade/utilidade."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.results = []

    def run_privacy_utility_tradeoff(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        noise_levels: list = None,
    ) -> Dict:
        """Treina modelos com diferentes níveis de ruído e mede acurácia vs privacidade."""
        noise_levels = noise_levels or [0.0, 0.5, 1.0, 2.0, 4.0]
        logger.info("Medindo trade-off privacidade vs utilidade (DP-SGD)...")

        tradeoff = []
        for sigma in noise_levels:
            model = DPLogisticRegression(
                l2_clip=1.0, noise_multiplier=sigma, epochs=40, batch_size=32
            )
            model.fit(X_train, y_train)
            acc = model.score(X_test, y_test)
            eps = model.epsilon_estimate() if sigma > 0 else float("inf")

            tradeoff.append(
                {
                    "noise_multiplier": sigma,
                    "test_accuracy": acc,
                    "epsilon": eps,
                    "privacy_level": (
                        "None (não-privado)"
                        if sigma == 0
                        else "Alta" if sigma >= 2.0 else "Média"
                    ),
                }
            )
            logger.info(
                f"  sigma={sigma:.1f} -> acc={acc:.3f}, epsilon={eps:.2f}"
            )

        result = {
            "timestamp": datetime.now().isoformat(),
            "experiment": "DP-SGD Privacy-Utility Tradeoff",
            "tradeoff": tradeoff,
            "interpretation": (
                "Aumentar o ruído (noise_multiplier) reduz epsilon (mais privacidade) "
                "ao custo de acurácia. O ponto ideal equilibra proteção e utilidade."
            ),
        }
        self.results.append(result)
        return result

    def save_results(self) -> str:
        if not self.results:
            return None
        out = self.log_dir / f"dp_sgd_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump(self.results[-1], f, indent=2)
        logger.info(f"Resultados DP-SGD salvos em {out}")
        return str(out)


def demo():
    """Demo de DP-SGD."""
    logging.basicConfig(level=logging.INFO)
    from sklearn.datasets import make_classification
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    X, y = make_classification(n_samples=1000, n_features=20, n_informative=15, random_state=42)
    X = StandardScaler().fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    exp = DifferentialPrivacyExperiment()
    result = exp.run_privacy_utility_tradeoff(X_train, y_train, X_test, y_test)

    print("\n=== DP-SGD: Trade-off Privacidade vs Utilidade ===")
    for row in result["tradeoff"]:
        print(
            f"  sigma={row['noise_multiplier']:.1f} | "
            f"acc={row['test_accuracy']:.3f} | "
            f"epsilon={row['epsilon']:.2f} | {row['privacy_level']}"
        )
    exp.save_results()


if __name__ == "__main__":
    demo()

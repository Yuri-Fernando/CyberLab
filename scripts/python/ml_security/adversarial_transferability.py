"""
adversarial_transferability.py - Transferability & Robustness Benchmarking

Cobre dois tópicos essenciais de avaliação de robustez adversarial:

1. TRANSFERABILITY: exemplos adversariais gerados contra um modelo (substituto)
   frequentemente enganam OUTROS modelos, mesmo de arquitetura diferente. É a base
   dos ataques black-box realistas: o atacante treina um substituto, gera adversariais
   nele e transfere para o modelo-alvo (cuja API só devolve o rótulo).

2. ROBUSTNESS BENCHMARKING: mede acurácia sob perturbação crescente (curva
   acurácia vs epsilon) e alerta para GRADIENT MASKING / OBFUSCATED GRADIENTS —
   a armadilha em que uma defesa parece robusta contra ataques baseados em gradiente
   mas cai trivialmente sob ataques black-box/de força bruta.
"""

import numpy as np
import json
import logging
from typing import Dict, List
from pathlib import Path
from datetime import datetime
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression

logger = logging.getLogger(__name__)


class TransferabilityAnalyzer:
    """Analisa transferência de exemplos adversariais entre modelos."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.results = []

    def _random_perturbation_attack(
        self, model, X: np.ndarray, y: np.ndarray, epsilon: float, tries: int = 30
    ) -> np.ndarray:
        """Gera adversariais black-box por busca aleatória (não usa gradiente)."""
        rng = np.random.default_rng(0)
        X_adv = X.copy()
        for i in range(len(X)):
            for _ in range(tries):
                cand = X[i] + rng.normal(0, epsilon, X.shape[1])
                if model.predict([cand])[0] != y[i]:
                    X_adv[i] = cand
                    break
        return X_adv

    def measure_transferability(
        self,
        substitute_model,
        target_models: Dict[str, object],
        X_test: np.ndarray,
        y_test: np.ndarray,
        epsilon: float = 0.5,
    ) -> Dict:
        """
        Gera adversariais no modelo substituto e mede quanto transferem para cada alvo.
        """
        logger.info("Medindo transferability de exemplos adversariais...")

        # Adversariais gerados no substituto (black-box search)
        X_adv = self._random_perturbation_attack(substitute_model, X_test, y_test, epsilon)

        # Confirmar que enganam o substituto
        sub_acc_clean = substitute_model.score(X_test, y_test)
        sub_acc_adv = substitute_model.score(X_adv, y_test)

        transfer = {}
        for name, model in target_models.items():
            acc_clean = model.score(X_test, y_test)
            acc_adv = model.score(X_adv, y_test)
            transfer_rate = (acc_clean - acc_adv) / (acc_clean + 1e-9)
            transfer[name] = {
                "accuracy_clean": float(acc_clean),
                "accuracy_on_transferred_adv": float(acc_adv),
                "transfer_rate": float(max(0.0, transfer_rate)),
            }
            logger.info(
                f"  {name}: clean={acc_clean:.3f} -> adv={acc_adv:.3f} "
                f"(transfer={transfer[name]['transfer_rate']:.2%})"
            )

        result = {
            "timestamp": datetime.now().isoformat(),
            "epsilon": epsilon,
            "substitute_accuracy_clean": float(sub_acc_clean),
            "substitute_accuracy_adv": float(sub_acc_adv),
            "transferability_to_targets": transfer,
        }
        self.results.append(result)
        return result

    def robustness_benchmark(
        self, model, X_test: np.ndarray, y_test: np.ndarray,
        epsilons: List[float] = None
    ) -> Dict:
        """
        Curva acurácia vs epsilon + detecção de gradient masking.

        Gradient masking é sinalizado quando a acurácia sob ataque cai muito
        DEVAGAR com epsilon (defesa "esconde" gradientes) mas depois despenca
        sob perturbação grande — indício de robustez falsa.
        """
        epsilons = epsilons or [0.0, 0.1, 0.25, 0.5, 1.0, 2.0]
        curve = []
        for eps in epsilons:
            if eps == 0.0:
                acc = model.score(X_test, y_test)
            else:
                X_adv = self._random_perturbation_attack(model, X_test, y_test, eps, tries=20)
                acc = model.score(X_adv, y_test)
            curve.append({"epsilon": eps, "accuracy": float(acc)})

        # Heurística de gradient masking: robustez alta em eps pequeno mas colapso em eps grande
        acc_small = curve[1]["accuracy"] if len(curve) > 1 else 1.0
        acc_large = curve[-1]["accuracy"]
        masking_suspected = (acc_small > 0.8) and (acc_large < 0.3)

        result = {
            "timestamp": datetime.now().isoformat(),
            "robustness_curve": curve,
            "gradient_masking_suspected": masking_suspected,
            "interpretation": (
                "ALERTA: possível gradient masking (robustez aparente sob perturbação "
                "pequena, colapso sob perturbação grande)."
                if masking_suspected
                else "Degradação de robustez consistente — sem sinal claro de gradient masking."
            ),
        }
        self.results.append(result)
        logger.info(f"  Robustness benchmark: masking_suspeito={masking_suspected}")
        return result

    def save_results(self) -> str:
        if not self.results:
            return None
        out = self.log_dir / f"transferability_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump(self.results, f, indent=2)
        return str(out)


def demo():
    logging.basicConfig(level=logging.INFO)
    X, y = make_classification(n_samples=400, n_features=10, random_state=42)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)

    substitute = LogisticRegression(max_iter=1000).fit(Xtr, ytr)
    targets = {
        "RandomForest": RandomForestClassifier(n_estimators=50, random_state=1).fit(Xtr, ytr),
        "GradientBoosting": GradientBoostingClassifier(n_estimators=50, random_state=1).fit(Xtr, ytr),
    }

    a = TransferabilityAnalyzer()
    a.measure_transferability(substitute, targets, Xte, yte, epsilon=0.6)
    a.robustness_benchmark(targets["RandomForest"], Xte, yte)
    a.save_results()


if __name__ == "__main__":
    demo()

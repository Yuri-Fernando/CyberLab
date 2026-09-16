"""
adversarial_attacks.py - Ataques Adversariais Completos (FGSM, PGD, Black-Box)

Implementa ataques de evasão contra modelos de classificação em tempo de INFERÊNCIA.
Estes ataques geram exemplos adversariais que enganam o modelo sem modificar dados treino.

Ataques Implementados:
1. FGSM (Fast Gradient Sign Method) - white-box, rápido
2. PGD (Projected Gradient Descent) - white-box, mais potente
3. Black-box query-based - sem acesso aos gradientes
4. Transferability - usar adversarial de um modelo em outro
"""

import numpy as np
import json
import logging
from typing import Dict, Tuple, Callable
from pathlib import Path
from datetime import datetime
from sklearn.datasets import load_iris, make_classification
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, confusion_matrix

logger = logging.getLogger(__name__)


class AdversarialEvasionAttacker:
    """Gerador de exemplos adversariais para ataques de evasão."""

    def __init__(self, log_dir: Path = None):
        """Inicializa atacante."""
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.experiments = []

    def fgsm_attack(
        self,
        model,
        X: np.ndarray,
        y: np.ndarray,
        epsilon: float = 0.1,
        scaler: StandardScaler = None
    ) -> Tuple[np.ndarray, Dict]:
        """
        FGSM (Fast Gradient Sign Method) Attack - White-Box.

        Movimento de uma etapa na direção do gradient que maximiza a perda.
        x_adv = x + epsilon * sign(∇_x L(x, y))

        Args:
            model: Modelo sklearn (precisa ter decision_function ou predict_proba)
            X: Features de teste
            y: Labels verdadeiros
            epsilon: Magnitude de perturbação
            scaler: Scaler para normalizar (se usado em treino)

        Returns:
            (X_adversarial, metadata)
        """
        logger.info(f"FGSM Attack (epsilon={epsilon})...")

        X_adv = X.copy()
        successful_attacks = 0

        for i in range(len(X)):
            # Conseguir gradiente aproximado usando diferenças finitas
            delta = 1e-4
            losses = []

            for j in range(X.shape[1]):
                # Perturbação positiva
                X_plus = X[i].copy()
                X_plus[j] += delta
                pred_plus = model.predict_proba([X_plus])[0]
                loss_plus = -np.log(pred_plus[y[i]] + 1e-10)

                # Perturbação negativa
                X_minus = X[i].copy()
                X_minus[j] -= delta
                pred_minus = model.predict_proba([X_minus])[0]
                loss_minus = -np.log(pred_minus[y[i]] + 1e-10)

                # Gradiente aproximado
                grad = (loss_plus - loss_minus) / (2 * delta)
                losses.append(grad)

            # Aplicar perturbação FGSM
            grad_sign = np.sign(losses)
            X_adv[i] = X[i] + epsilon * grad_sign

            # Verificar se ataque foi bem-sucedido
            pred_adv = model.predict([X_adv[i:i+1]])[0]
            if pred_adv != y[i]:
                successful_attacks += 1

        metadata = {
            "attack_type": "FGSM",
            "epsilon": epsilon,
            "success_rate": successful_attacks / len(X),
            "successful_examples": successful_attacks
        }

        logger.info(f"FGSM: {successful_attacks}/{len(X)} exemplos enganados")
        return X_adv, metadata

    def pgd_attack(
        self,
        model,
        X: np.ndarray,
        y: np.ndarray,
        epsilon: float = 0.3,
        step_size: float = 0.01,
        num_steps: int = 40
    ) -> Tuple[np.ndarray, Dict]:
        """
        PGD (Projected Gradient Descent) Attack - White-Box, Iterativo.

        Versão mais potente de FGSM que executa múltiplos passos.
        Projeta a cada passo para manter ||x_adv - x|| <= epsilon.

        Args:
            model: Modelo sklearn
            X: Features
            y: Labels
            epsilon: Épsilon máximo (magnitude total permitida)
            step_size: Tamanho de cada passo
            num_steps: Número de iterações

        Returns:
            (X_adversarial, metadata)
        """
        logger.info(f"PGD Attack (epsilon={epsilon}, steps={num_steps})...")

        X_adv = X.copy()
        successful_attacks = 0

        for i in range(len(X)):
            x_adv_i = X[i].copy()

            for step in range(num_steps):
                # Calcular gradiente
                delta = 1e-4
                losses = []

                for j in range(X.shape[1]):
                    X_plus = x_adv_i.copy()
                    X_plus[j] += delta
                    pred_plus = model.predict_proba([X_plus])[0]
                    loss_plus = -np.log(pred_plus[y[i]] + 1e-10)

                    X_minus = x_adv_i.copy()
                    X_minus[j] -= delta
                    pred_minus = model.predict_proba([X_minus])[0]
                    loss_minus = -np.log(pred_minus[y[i]] + 1e-10)

                    grad = (loss_plus - loss_minus) / (2 * delta)
                    losses.append(grad)

                # Passo de gradiente
                x_adv_i = x_adv_i + step_size * np.sign(losses)

                # Projetar para manter ||x_adv - x|| <= epsilon
                perturbation = x_adv_i - X[i]
                norm = np.linalg.norm(perturbation)
                if norm > epsilon:
                    perturbation = perturbation * (epsilon / norm)
                    x_adv_i = X[i] + perturbation

            X_adv[i] = x_adv_i

            # Verificar sucesso
            pred_adv = model.predict([X_adv[i:i+1]])[0]
            if pred_adv != y[i]:
                successful_attacks += 1

        metadata = {
            "attack_type": "PGD",
            "epsilon": epsilon,
            "step_size": step_size,
            "num_steps": num_steps,
            "success_rate": successful_attacks / len(X),
            "successful_examples": successful_attacks
        }

        logger.info(f"PGD: {successful_attacks}/{len(X)} exemplos enganados")
        return X_adv, metadata

    def blackbox_query_attack(
        self,
        model_func: Callable,
        X: np.ndarray,
        y: np.ndarray,
        epsilon: float = 0.3,
        num_queries_per_example: int = 100
    ) -> Tuple[np.ndarray, Dict]:
        """
        Black-Box Query Attack - Sem acesso aos gradientes.

        Usa random search ou consultas a modelo para encontrar adversarial examples.
        Simula cenário de MLaaS onde atacante só tem acesso à API de predição.

        Args:
            model_func: Função de predição (recebe X retorna y_pred)
            X: Features
            y: Labels verdadeiros
            epsilon: Máximo de perturbação
            num_queries_per_example: Queries por exemplo

        Returns:
            (X_adversarial, metadata)
        """
        logger.info(f"Black-Box Query Attack ({num_queries_per_example} queries/ex)...")

        X_adv = X.copy()
        successful_attacks = 0
        total_queries = 0

        for i in range(len(X)):
            best_adv = X[i].copy()
            best_queries = 0

            for query_count in range(num_queries_per_example):
                # Random perturbation
                perturbation = np.random.normal(0, epsilon/3, X.shape[1])
                x_candidate = X[i] + perturbation

                # Clip para manter em bounds
                x_candidate = np.clip(x_candidate, X.min(), X.max())

                # Query modelo
                pred = model_func([x_candidate])[0]
                total_queries += 1
                best_queries = query_count + 1

                if pred != y[i]:
                    successful_attacks += 1
                    best_adv = x_candidate
                    break

            X_adv[i] = best_adv

        metadata = {
            "attack_type": "Black-Box Query",
            "epsilon": epsilon,
            "queries_per_example": num_queries_per_example,
            "success_rate": successful_attacks / len(X),
            "successful_examples": successful_attacks,
            "total_queries": total_queries
        }

        logger.info(
            f"Black-Box: {successful_attacks}/{len(X)} com "
            f"{total_queries} queries ({total_queries/len(X):.0f} por exemplo)"
        )
        return X_adv, metadata

    def evaluate_adversarial_robustness(
        self,
        model,
        X_test: np.ndarray,
        y_test: np.ndarray,
        X_adv: np.ndarray,
        metadata: Dict
    ) -> Dict:
        """Avalia robustez do modelo contra exemplos adversariais."""
        y_pred_clean = model.predict(X_test)
        y_pred_adv = model.predict(X_adv)

        acc_clean = accuracy_score(y_test, y_pred_clean)
        acc_adv = accuracy_score(y_test, y_pred_adv)
        drop = acc_clean - acc_adv

        results = {
            "timestamp": datetime.now().isoformat(),
            "attack_metadata": metadata,
            "accuracy_clean": float(acc_clean),
            "accuracy_adversarial": float(acc_adv),
            "accuracy_drop": float(drop),
            "drop_percent": float((drop / acc_clean) * 100),
            "attack_successful": drop > 0.05
        }

        logger.info(
            f"Robustez: Limpo={acc_clean:.3f}, "
            f"Adversarial={acc_adv:.3f}, Drop={drop:.3f}"
        )

        self.experiments.append(results)
        return results

    def save_experiment(self) -> str:
        """Salva experimento em JSON."""
        if not self.experiments:
            return None

        output_file = self.log_dir / f"adversarial_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(output_file, "w") as f:
                json.dump(self.experiments[-1], f, indent=2)
            logger.info(f"Experimento salvo em {output_file}")
            return str(output_file)
        except Exception as e:
            logger.error(f"Erro ao salvar: {str(e)}")
            return None


def demo_adversarial():
    """Demo de ataques adversariais."""
    logging.basicConfig(level=logging.INFO)

    # Dataset
    X, y = make_classification(n_samples=200, n_features=10, n_informative=8, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Treinar modelo
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    print(f"Baseline Accuracy: {model.score(X_test, y_test):.3f}")

    attacker = AdversarialEvasionAttacker()

    # FGSM
    X_adv_fgsm, meta_fgsm = attacker.fgsm_attack(model, X_test, y_test, epsilon=0.2)
    result_fgsm = attacker.evaluate_adversarial_robustness(model, X_test, y_test, X_adv_fgsm, meta_fgsm)
    print(f"FGSM: {result_fgsm['accuracy_drop']:.3f} drop")

    # PGD
    X_adv_pgd, meta_pgd = attacker.pgd_attack(model, X_test, y_test, epsilon=0.3, num_steps=10)
    result_pgd = attacker.evaluate_adversarial_robustness(model, X_test, y_test, X_adv_pgd, meta_pgd)
    print(f"PGD: {result_pgd['accuracy_drop']:.3f} drop")

    # Black-Box
    X_adv_bb, meta_bb = attacker.blackbox_query_attack(
        model.predict, X_test, y_test, epsilon=0.3, num_queries_per_example=50
    )
    result_bb = attacker.evaluate_adversarial_robustness(model, X_test, y_test, X_adv_bb, meta_bb)
    print(f"Black-Box: {result_bb['accuracy_drop']:.3f} drop")


if __name__ == "__main__":
    demo_adversarial()

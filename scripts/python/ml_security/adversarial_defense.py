"""
adversarial_defense.py - Defesas contra Ataques Adversariais

Implementa técnicas de hardening:
1. Adversarial Training - Treinar com exemplos adversariais
2. Defensive Distillation - Usar modelo "teacher" para suavizar decisões
3. Input Validation - Detecção de anomalias em entrada
4. Ensemble Methods - Combinação de múltiplos modelos
"""

import numpy as np
import json
import logging
from typing import Dict, Tuple, List
from pathlib import Path
from datetime import datetime
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, AdaBoostClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from scipy.spatial.distance import euclidean

logger = logging.getLogger(__name__)


class AdversarialDefense:
    """Implementa defesas contra ataques adversariais."""

    def __init__(self, log_dir: Path = None):
        """Inicializa defensor."""
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.models = {}
        self.results = []

    def adversarial_training(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_adv_train: np.ndarray,
        y_adv_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        X_adv_test: np.ndarray,
        y_adv_test: np.ndarray
    ) -> Dict:
        """
        Adversarial Training - Treinar com dados limpos + adversariais.

        Modelos treinados com exemplos adversariais ficam mais robustos,
        porque aprendem features mais fundamentais em vez de spurious correlations.

        Args:
            X_train, y_train: Dados limpos de treino
            X_adv_train, y_adv_train: Dados adversariais de treino
            X_test, y_test: Dados limpos de teste
            X_adv_test, y_adv_test: Dados adversariais de teste

        Returns:
            Dict com resultados da defesa
        """
        logger.info("Treinando modelo com Adversarial Training...")

        # Combinar dados limpos + adversariais
        X_combined = np.vstack([X_train, X_adv_train])
        y_combined = np.hstack([y_train, y_adv_train])

        # Treinar modelo robusto
        model_robust = RandomForestClassifier(n_estimators=200, random_state=42)
        model_robust.fit(X_combined, y_combined)

        # Baseline sem defesa
        model_baseline = RandomForestClassifier(n_estimators=200, random_state=42)
        model_baseline.fit(X_train, y_train)

        # Avaliar
        acc_baseline_clean = model_baseline.score(X_test, y_test)
        acc_baseline_adv = model_baseline.score(X_adv_test, y_adv_test)
        acc_robust_clean = model_robust.score(X_test, y_test)
        acc_robust_adv = model_robust.score(X_adv_test, y_adv_test)

        results = {
            "defense_type": "Adversarial Training",
            "baseline_accuracy_clean": float(acc_baseline_clean),
            "baseline_accuracy_adversarial": float(acc_baseline_adv),
            "baseline_drop": float(acc_baseline_clean - acc_baseline_adv),
            "robust_accuracy_clean": float(acc_robust_clean),
            "robust_accuracy_adversarial": float(acc_robust_adv),
            "robust_drop": float(acc_robust_clean - acc_robust_adv),
            "robustness_improvement": float((acc_robust_adv - acc_baseline_adv))
        }

        logger.info(
            f"Baseline: Clean={acc_baseline_clean:.3f}, Adv={acc_baseline_adv:.3f}\n"
            f"Robust: Clean={acc_robust_clean:.3f}, Adv={acc_robust_adv:.3f}"
        )

        self.models["adversarial_trained"] = model_robust
        self.results.append(results)
        return results

    def defensive_distillation(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        X_adv_test: np.ndarray,
        y_adv_test: np.ndarray,
        temperature: float = 20.0
    ) -> Dict:
        """
        Defensive Distillation - Usar modelo teacher para suavizar decisões.

        Modelo teacher grande é treinado normalmente. Depois, modelo student
        aprende a reproduzir as "soft predictions" (com temperatura) do teacher.
        Isso suaviza a superfície de decisão, reduzindo sensibilidade a perturbações.

        Args:
            temperature: Controla suavidade das probabilidades (>1 = mais suave)

        Returns:
            Dict com resultados
        """
        logger.info(f"Treinando com Defensive Distillation (T={temperature})...")

        # Teacher model
        teacher = GradientBoostingClassifier(n_estimators=100, random_state=42)
        teacher.fit(X_train, y_train)

        # Soft labels do teacher
        soft_probs = teacher.predict_proba(X_train)
        soft_probs_T = soft_probs ** (1.0 / temperature)
        soft_probs_T /= soft_probs_T.sum(axis=1, keepdims=True)
        soft_labels = np.argmax(soft_probs_T, axis=1)

        # Student model
        student = RandomForestClassifier(n_estimators=100, random_state=42)
        student.fit(X_train, soft_labels)

        # Avaliar
        acc_teacher_clean = teacher.score(X_test, y_test)
        acc_teacher_adv = teacher.score(X_adv_test, y_adv_test)
        acc_student_clean = student.score(X_test, y_test)
        acc_student_adv = student.score(X_adv_test, y_adv_test)

        results = {
            "defense_type": "Defensive Distillation",
            "temperature": temperature,
            "teacher_accuracy_clean": float(acc_teacher_clean),
            "teacher_accuracy_adversarial": float(acc_teacher_adv),
            "student_accuracy_clean": float(acc_student_clean),
            "student_accuracy_adversarial": float(acc_student_adv),
            "robustness_improvement": float(acc_student_adv - acc_teacher_adv)
        }

        logger.info(
            f"Teacher: Clean={acc_teacher_clean:.3f}, Adv={acc_teacher_adv:.3f}\n"
            f"Student: Clean={acc_student_clean:.3f}, Adv={acc_student_adv:.3f}"
        )

        self.models["distilled_student"] = student
        self.results.append(results)
        return results

    def input_anomaly_detection(
        self,
        X_train: np.ndarray,
        X_test_clean: np.ndarray,
        X_test_adv: np.ndarray,
        threshold_percentile: float = 95.0
    ) -> Dict:
        """
        Detecção de Anomalias em Entrada.

        Calcula distância média de cada exemplo de treino ao centroid.
        Exemplos adversariais frequentemente estão afastados do centroid
        porque adicionam perturbações não-naturais.

        Args:
            threshold_percentile: Percentil para definir threshold (ex: 95 = top 5%)

        Returns:
            Dict com detecção
        """
        logger.info(f"Treinando detector de anomalias (threshold={threshold_percentile}%)...")

        centroid = X_train.mean(axis=0)

        # Distâncias de treino
        distances_train = [euclidean(x, centroid) for x in X_train]
        threshold = np.percentile(distances_train, threshold_percentile)

        # Detectar anomalias em teste
        distances_clean = [euclidean(x, centroid) for x in X_test_clean]
        distances_adv = [euclidean(x, centroid) for x in X_test_adv]

        anomalies_clean = sum(d > threshold for d in distances_clean)
        anomalies_adv = sum(d > threshold for d in distances_adv)

        detection_rate_adv = anomalies_adv / len(distances_adv)
        false_positive_rate = anomalies_clean / len(distances_clean)

        results = {
            "defense_type": "Input Anomaly Detection",
            "threshold": float(threshold),
            "centroid_distance_mean_train": float(np.mean(distances_train)),
            "centroid_distance_mean_clean": float(np.mean(distances_clean)),
            "centroid_distance_mean_adversarial": float(np.mean(distances_adv)),
            "detection_rate_adversarial": float(detection_rate_adv),
            "false_positive_rate": float(false_positive_rate),
            "flagged_as_anomaly_clean": int(anomalies_clean),
            "flagged_as_anomaly_adversarial": int(anomalies_adv)
        }

        logger.info(
            f"Detection Rate (Adversarial): {detection_rate_adv:.2%}\n"
            f"False Positive Rate: {false_positive_rate:.2%}"
        )

        self.results.append(results)
        return results

    def ensemble_defense(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test_clean: np.ndarray,
        y_test: np.ndarray,
        X_test_adv: np.ndarray
    ) -> Dict:
        """
        Ensemble Defense - Combinar múltiplos modelos.

        Modelos diferentes têm "caminhos adversariais" diferentes.
        Ensemble reduz o sucesso de ataques porque atacante precisaria
        enganar múltiplos modelos simultaneamente.

        Returns:
            Dict com resultados
        """
        logger.info("Treinando ensemble de defesa...")

        # Treinar múltiplos modelos
        model1 = RandomForestClassifier(n_estimators=100, random_state=42)
        model2 = GradientBoostingClassifier(n_estimators=100, random_state=42)
        model3 = AdaBoostClassifier(n_estimators=100, random_state=42)

        for model in [model1, model2, model3]:
            model.fit(X_train, y_train)

        # Predições
        pred1_clean = model1.predict(X_test_clean)
        pred2_clean = model2.predict(X_test_clean)
        pred3_clean = model3.predict(X_test_clean)

        pred1_adv = model1.predict(X_test_adv)
        pred2_adv = model2.predict(X_test_adv)
        pred3_adv = model3.predict(X_test_adv)

        # Voting ensemble
        ensemble_pred_clean = np.array([
            np.bincount([p1, p2, p3]).argmax()
            for p1, p2, p3 in zip(pred1_clean, pred2_clean, pred3_clean)
        ])

        ensemble_pred_adv = np.array([
            np.bincount([p1, p2, p3]).argmax()
            for p1, p2, p3 in zip(pred1_adv, pred2_adv, pred3_adv)
        ])

        acc_ensemble_clean = accuracy_score(y_test, ensemble_pred_clean)
        acc_ensemble_adv = accuracy_score(y_test, ensemble_pred_adv)

        results = {
            "defense_type": "Ensemble Defense",
            "individual_models_accuracy_clean": {
                "model1": float(model1.score(X_test_clean, y_test)),
                "model2": float(model2.score(X_test_clean, y_test)),
                "model3": float(model3.score(X_test_clean, y_test))
            },
            "individual_models_accuracy_adversarial": {
                "model1": float(model1.score(X_test_adv, y_test)),
                "model2": float(model2.score(X_test_adv, y_test)),
                "model3": float(model3.score(X_test_adv, y_test))
            },
            "ensemble_accuracy_clean": float(acc_ensemble_clean),
            "ensemble_accuracy_adversarial": float(acc_ensemble_adv),
            "ensemble_robustness": float(acc_ensemble_adv - acc_ensemble_clean)
        }

        logger.info(f"Ensemble - Clean: {acc_ensemble_clean:.3f}, Adv: {acc_ensemble_adv:.3f}")

        self.models["ensemble"] = [model1, model2, model3]
        self.results.append(results)
        return results

    def save_results(self) -> str:
        """Salva todos os resultados de defesa."""
        if not self.results:
            return None

        output_file = self.log_dir / f"defenses_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(output_file, "w") as f:
                json.dump(self.results, f, indent=2)
            logger.info(f"Resultados salvos em {output_file}")
            return str(output_file)
        except Exception as e:
            logger.error(f"Erro ao salvar: {str(e)}")
            return None


def demo_defense():
    """Demo de defesas."""
    logging.basicConfig(level=logging.INFO)

    # Dados
    X, y = make_classification(n_samples=300, n_features=10, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # Simular dados adversariais
    X_adv_train = X_train + np.random.normal(0, 0.2, X_train.shape)
    X_adv_test = X_test + np.random.normal(0, 0.2, X_test.shape)
    y_adv_train = y_train
    y_adv_test = y_test

    defender = AdversarialDefense()

    # Adversarial Training
    result_at = defender.adversarial_training(
        X_train, y_train, X_adv_train, y_adv_train,
        X_test, y_test, X_adv_test, y_adv_test
    )
    print(f"\nAdversarial Training: {result_at['robustness_improvement']:.3f} improvement")

    # Defensive Distillation
    result_dd = defender.defensive_distillation(
        X_train, y_train, X_test, y_test, X_adv_test, y_adv_test, temperature=15
    )
    print(f"Defensive Distillation: {result_dd['robustness_improvement']:.3f} improvement")

    # Input Anomaly Detection
    result_iad = defender.input_anomaly_detection(X_train, X_test, X_adv_test)
    print(f"Anomaly Detection Rate: {result_iad['detection_rate_adversarial']:.2%}")

    # Ensemble
    result_ens = defender.ensemble_defense(X_train, y_train, X_test, y_test, X_adv_test)
    print(f"Ensemble Robustness: {result_ens['ensemble_robustness']:.3f}")


if __name__ == "__main__":
    demo_defense()

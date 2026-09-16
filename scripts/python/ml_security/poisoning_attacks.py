"""
poisoning_attacks.py - Simulação de Ataques de Envenenamento de Dados

Demonstra como modelos de ML podem ser comprometidos através do envenenamento
de dados de treino (data poisoning). Inclui:

1. Label Flipping Indiscriminado: Inverte labels de alguns exemplos
2. Label Flipping Direcionado: Inverte labels de classe específica
3. Backdoor Attack: Injeta padrão secreto que ativa comportamento específico
4. Clean-Label Poisoning: Envenenamento que mantém label correto (mais sofisticado)

IMPORTANTE: Simulação educacional em ambiente controlado apenas.
"""

import json
import logging
from typing import Dict, List, Tuple
from pathlib import Path
from datetime import datetime
import numpy as np
from sklearn.datasets import load_iris
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix

logger = logging.getLogger(__name__)


class PoisoningAttackSimulator:
    """Simula ataques de data poisoning contra modelos de classificação."""

    def __init__(self, log_dir: Path = None):
        """Inicializa simulador de poisoning."""
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.experiments = []

    def label_flipping_indiscriminado(
        self,
        X: np.ndarray,
        y: np.ndarray,
        poison_rate: float = 0.1
    ) -> Tuple[np.ndarray, np.ndarray, Dict]:
        """
        Ataque de Label Flipping Indiscriminado.

        Seleciona aleatoriamente `poison_rate`% dos exemplos e inverte seus labels.
        Este é o ataque mais simples mas ainda efetivo.

        Args:
            X: Features (matriz)
            y: Labels (array)
            poison_rate: Percentual de dados a envenenar (0.0-1.0)

        Returns:
            (X_poisoned, y_poisoned, metadata)
        """
        logger.info(f"Iniciando Label Flipping Indiscriminado (taxa={poison_rate})")

        X_poisoned = X.copy()
        y_poisoned = y.copy()

        n_poison = int(len(y) * poison_rate)
        poison_indices = np.random.choice(len(y), n_poison, replace=False)

        # Inverter labels
        unique_classes = np.unique(y)
        for idx in poison_indices:
            current_label = y_poisoned[idx]
            # Escolher um label diferente
            other_labels = unique_classes[unique_classes != current_label]
            y_poisoned[idx] = np.random.choice(other_labels)

        metadata = {
            "attack_type": "label_flipping_indiscriminado",
            "poison_rate": poison_rate,
            "n_poisoned": n_poison,
            "poison_indices": poison_indices.tolist()
        }

        logger.info(f"Envenenados {n_poison} exemplos")
        return X_poisoned, y_poisoned, metadata

    def label_flipping_direcionado(
        self,
        X: np.ndarray,
        y: np.ndarray,
        target_class: int,
        poison_rate: float = 0.2
    ) -> Tuple[np.ndarray, np.ndarray, Dict]:
        """
        Ataque de Label Flipping Direcionado.

        Seleciona apenas exemplos de `target_class` e inverte seus labels.
        Objetivo: fazer o modelo misclassificar a classe alvo.

        Args:
            X: Features
            y: Labels
            target_class: Classe a ser atacada
            poison_rate: Percentual de exemplos da classe alvo a envenenar

        Returns:
            (X_poisoned, y_poisoned, metadata)
        """
        logger.info(f"Iniciando Label Flipping Direcionado contra classe {target_class}")

        X_poisoned = X.copy()
        y_poisoned = y.copy()

        # Encontrar indices da classe alvo
        target_indices = np.where(y == target_class)[0]
        n_poison = int(len(target_indices) * poison_rate)
        poison_indices = np.random.choice(target_indices, n_poison, replace=False)

        # Inverter labels apenas da classe alvo
        unique_classes = np.unique(y)
        for idx in poison_indices:
            other_labels = unique_classes[unique_classes != target_class]
            y_poisoned[idx] = np.random.choice(other_labels)

        metadata = {
            "attack_type": "label_flipping_direcionado",
            "target_class": int(target_class),
            "poison_rate": poison_rate,
            "n_poisoned": n_poison,
            "poison_indices": poison_indices.tolist()
        }

        logger.info(f"Envenenados {n_poison} exemplos da classe {target_class}")
        return X_poisoned, y_poisoned, metadata

    def backdoor_attack(
        self,
        X: np.ndarray,
        y: np.ndarray,
        backdoor_class: int = 0,
        trigger_pattern: float = 99.9,
        poison_rate: float = 0.05
    ) -> Tuple[np.ndarray, np.ndarray, Dict]:
        """
        Ataque de Backdoor (Trojan).

        Injeta um padrão secreto (trigger) em exemplos de treino. Quando o modelo
        vê esse padrão em inferência, classifica como `backdoor_class` independente
        da entrada real.

        Args:
            X: Features
            y: Labels
            backdoor_class: Classe para a qual o backdoor leva
            trigger_pattern: Valor do padrão secreto a injetar
            poison_rate: Percentual de dados com backdoor

        Returns:
            (X_poisoned, y_poisoned, metadata)
        """
        logger.info(f"Iniciando Backdoor Attack (trigger={trigger_pattern})")

        X_poisoned = X.copy()
        y_poisoned = y.copy()

        n_poison = int(len(y) * poison_rate)
        poison_indices = np.random.choice(len(y), n_poison, replace=False)

        # Injetar padrão secreto (última feature) e fazer label apontar para backdoor_class
        for idx in poison_indices:
            X_poisoned[idx, -1] = trigger_pattern  # Injetar trigger na última feature
            y_poisoned[idx] = backdoor_class

        metadata = {
            "attack_type": "backdoor",
            "backdoor_class": int(backdoor_class),
            "trigger_pattern": trigger_pattern,
            "poison_rate": poison_rate,
            "n_poisoned": n_poison,
            "poison_indices": poison_indices.tolist()
        }

        logger.info(f"Backdoor injetado em {n_poison} exemplos com padrão={trigger_pattern}")
        return X_poisoned, y_poisoned, metadata

    def evaluate_attack(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        X_poisoned: np.ndarray,
        y_poisoned: np.ndarray,
        metadata: Dict
    ) -> Dict:
        """
        Avalia o impacto do ataque de poisoning.

        Treina dois modelos:
        1. Modelo limpo (X_train, y_train)
        2. Modelo envenenado (X_poisoned, y_poisoned)

        Compara performance.

        Returns:
            Dict com resultados da avaliação
        """
        logger.info("Avaliando impacto do ataque de poisoning...")

        # Modelo limpo
        model_clean = RandomForestClassifier(n_estimators=100, random_state=42)
        model_clean.fit(X_train, y_train)
        y_pred_clean = model_clean.predict(X_test)
        acc_clean = accuracy_score(y_test, y_pred_clean)

        # Modelo envenenado
        model_poisoned = RandomForestClassifier(n_estimators=100, random_state=42)
        model_poisoned.fit(X_poisoned, y_poisoned)
        y_pred_poisoned = model_poisoned.predict(X_test)
        acc_poisoned = accuracy_score(y_test, y_pred_poisoned)

        # Calcular degradação de performance
        performance_drop = acc_clean - acc_poisoned

        results = {
            "timestamp": datetime.now().isoformat(),
            "attack_metadata": metadata,
            "clean_model_accuracy": float(acc_clean),
            "poisoned_model_accuracy": float(acc_poisoned),
            "performance_drop": float(performance_drop),
            "performance_drop_percent": float((performance_drop / acc_clean) * 100),
            "attack_success": performance_drop > 0.05  # Considerar sucesso se > 5% drop
        }

        logger.info(
            f"Impacto: Acurácia limpa={acc_clean:.3f}, "
            f"Acurácia envenenada={acc_poisoned:.3f}, "
            f"Drop={performance_drop:.3f}"
        )

        self.experiments.append(results)
        return results

    def save_experiment(self, experiment_name: str) -> str:
        """Salva resultado de experimento em JSON."""
        if not self.experiments:
            logger.warning("Nenhum experimento para salvar")
            return None

        output_file = self.log_dir / f"poisoning_{experiment_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        try:
            with open(output_file, "w") as f:
                json.dump(self.experiments[-1], f, indent=2)
            logger.info(f"Experimento salvo em {output_file}")
            return str(output_file)
        except Exception as e:
            logger.error(f"Erro ao salvar experimento: {str(e)}")
            return None


def demo_poisoning():
    """Demo de ataques de data poisoning."""
    logger.basicConfig(level=logging.INFO)

    # Carregar dataset
    iris = load_iris()
    X, y = iris.data, iris.target
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    simulator = PoisoningAttackSimulator()

    # Experimento 1: Label Flipping Indiscriminado
    X_poisoned, y_poisoned, metadata = simulator.label_flipping_indiscriminado(
        X_train, y_train, poison_rate=0.1
    )
    results = simulator.evaluate_attack(
        X_train, y_train, X_test, y_test, X_poisoned, y_poisoned, metadata
    )
    print(f"Label Flipping Indiscriminado: Drop={results['performance_drop']:.3f}")

    # Experimento 2: Backdoor Attack
    X_poisoned, y_poisoned, metadata = simulator.backdoor_attack(
        X_train, y_train, backdoor_class=0, poison_rate=0.05
    )
    results = simulator.evaluate_attack(
        X_train, y_train, X_test, y_test, X_poisoned, y_poisoned, metadata
    )
    print(f"Backdoor Attack: Drop={results['performance_drop']:.3f}")


if __name__ == "__main__":
    demo_poisoning()

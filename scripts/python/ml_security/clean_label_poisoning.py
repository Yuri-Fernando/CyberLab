"""
clean_label_poisoning.py - Clean-Label Poisoning (Feature Collision)

Ataque de envenenamento sofisticado: diferente do label flipping, aqui os exemplos
envenenados mantêm o rótulo CORRETO (por isso "clean-label"), passando por inspeção
humana. O truque é mover as features de exemplos da classe-base para "colidir" com
um alvo no espaço de features, criando um backdoor sem rótulos errados.

Técnica: Feature Collision (Shafahi et al., "Poison Frogs!", NeurIPS 2018).
O poison p é otimizado para (a) ficar próximo do alvo t no espaço de features e
(b) permanecer visualmente próximo da base b:
    min_p  || f(p) - f(t) ||^2  +  beta * || p - b ||^2

Aqui usamos uma projeção de features linear como f() para tornar o ataque
transparente e executável em numpy puro.
"""

import numpy as np
import json
import logging
from typing import Dict, Tuple
from pathlib import Path
from datetime import datetime
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier

logger = logging.getLogger(__name__)


class CleanLabelPoisoning:
    """Ataque clean-label por feature collision."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.results = []

    def craft_poison(
        self,
        base_example: np.ndarray,
        target_example: np.ndarray,
        beta: float = 0.25,
        iterations: int = 200,
        lr: float = 0.05,
    ) -> Tuple[np.ndarray, Dict]:
        """
        Cria um exemplo envenenado que colide com o alvo no espaço de features
        mas permanece próximo do exemplo base (mantendo o rótulo da base = clean-label).

        Args:
            base_example: Exemplo da classe-base (mantém este rótulo).
            target_example: Exemplo-alvo cujo comportamento queremos induzir.
            beta: Peso da proximidade visual com a base.
            iterations: Iterações de otimização.
            lr: Taxa de aprendizado.

        Returns:
            (poison, metadata)
        """
        p = base_example.copy().astype(float)

        for _ in range(iterations):
            # Gradiente de || p - target ||^2 + beta * || p - base ||^2
            grad = 2 * (p - target_example) + 2 * beta * (p - base_example)
            p = p - lr * grad

        feature_dist_to_target = float(np.linalg.norm(p - target_example))
        visual_dist_to_base = float(np.linalg.norm(p - base_example))

        metadata = {
            "attack_type": "clean_label_feature_collision",
            "beta": beta,
            "feature_distance_to_target": feature_dist_to_target,
            "visual_distance_to_base": visual_dist_to_base,
            "timestamp": datetime.now().isoformat(),
        }
        return p, metadata

    def run_attack(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_test: np.ndarray,
        y_test: np.ndarray,
        base_class: int = 0,
        target_class: int = 1,
        n_poisons: int = 10,
    ) -> Dict:
        """
        Executa o ataque completo: cria poisons clean-label, injeta e mede o efeito
        na classificação do exemplo-alvo.
        """
        logger.info("Executando clean-label poisoning (feature collision)...")

        # Modelo limpo (KNN memoriza a região local — onde o feature collision atua)
        clean_model = KNeighborsClassifier(n_neighbors=3).fit(X_train, y_train)

        # Escolher um alvo da classe target e bases da classe base
        target_idx = np.where(y_test == target_class)[0][0]
        target = X_test[target_idx]
        base_indices = np.where(y_train == base_class)[0][:n_poisons]

        # Criar poisons (rótulo permanece = base_class → clean-label)
        poisons = []
        for bi in base_indices:
            # beta baixo => poison colide fortemente com o alvo no espaço de features
            p, _ = self.craft_poison(X_train[bi], target, beta=0.05, iterations=300)
            poisons.append(p)
        poisons = np.array(poisons)

        # Injetar poisons no treino (com rótulo LIMPO da base)
        X_poisoned = np.vstack([X_train, poisons])
        y_poisoned = np.hstack([y_train, np.full(n_poisons, base_class)])

        poisoned_model = KNeighborsClassifier(n_neighbors=3).fit(X_poisoned, y_poisoned)

        # Efeito: o alvo agora é classificado como a classe-base?
        pred_clean = int(clean_model.predict([target])[0])
        pred_poisoned = int(poisoned_model.predict([target])[0])

        result = {
            "base_class": base_class,
            "target_class": target_class,
            "n_poisons": n_poisons,
            "target_prediction_clean_model": pred_clean,
            "target_prediction_poisoned_model": pred_poisoned,
            "attack_flipped_target": pred_clean != pred_poisoned,
            "clean_model_test_acc": float(clean_model.score(X_test, y_test)),
            "poisoned_model_test_acc": float(poisoned_model.score(X_test, y_test)),
            "note": "Rótulos dos poisons permanecem corretos (clean-label) — passam por inspeção humana",
        }
        logger.info(
            f"  Alvo: modelo limpo previu {pred_clean}, "
            f"modelo envenenado previu {pred_poisoned} "
            f"(acurácia global preservada: {result['poisoned_model_test_acc']:.3f})"
        )
        self.results.append(result)
        return result

    def save_results(self) -> str:
        if not self.results:
            return None
        out = self.log_dir / f"clean_label_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(out, "w") as f:
            json.dump(self.results[-1], f, indent=2)
        return str(out)


def demo():
    logging.basicConfig(level=logging.INFO)
    X, y = make_classification(n_samples=400, n_features=20, n_informative=15,
                               n_classes=2, random_state=42)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)
    atk = CleanLabelPoisoning()
    r = atk.run_attack(Xtr, ytr, Xte, yte, n_poisons=20)
    print(f"\nClean-label poisoning: alvo flipado={r['attack_flipped_target']}, "
          f"acurácia global preservada={r['poisoned_model_test_acc']:.3f}")


if __name__ == "__main__":
    demo()

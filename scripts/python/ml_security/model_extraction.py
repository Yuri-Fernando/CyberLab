"""
model_extraction.py - Model Extraction & Membership Inference Attacks

Implementa ataques de extração de modelo (roubo de propriedade intelectual)
e membership inference (descobrir se exemplo foi usado no treino).

Ataques implementados:
1. Model Extraction via queries - clonar modelo proprietário
2. Membership Inference - descobrir dados de treino
"""

import numpy as np
import json
import logging
from typing import Dict, Tuple
from pathlib import Path
from datetime import datetime
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

logger = logging.getLogger(__name__)


class ModelExtractionAttacker:
    """Ataque de extração de modelo via queries."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.results = []

    def extract_model(
        self,
        query_func,
        X_synthetic: np.ndarray,
        num_queries: int = 1000
    ) -> Tuple[np.ndarray, np.ndarray, Dict]:
        """
        Extração de Modelo - Clonar modelo proprietário via queries.

        Estratégia: Gerar dados sintéticos, fazer queries ao modelo alvo,
        coletar predições, e treinar modelo local que imita o alvo.

        Args:
            query_func: Função que chama o modelo alvo (retorna predições)
            X_synthetic: Dataset sintético para queries
            num_queries: Número máximo de queries

        Returns:
            (y_extracted, X_queries_used, metadata)
        """
        logger.info(f"Iniciando Model Extraction com {num_queries} queries...")

        X_queries = X_synthetic[:num_queries]
        y_extracted = []

        for i, x in enumerate(X_queries):
            pred = query_func([x])[0]
            y_extracted.append(pred)

            if (i + 1) % 100 == 0:
                logger.info(f"  {i+1}/{len(X_queries)} queries realizadas")

        y_extracted = np.array(y_extracted)

        metadata = {
            "attack_type": "Model Extraction",
            "total_queries": len(X_queries),
            "examples_extracted": len(y_extracted),
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"Extração completa: {len(y_extracted)} exemplos coletados")
        return y_extracted, X_queries, metadata

    def evaluate_extraction(
        self,
        model_original,
        X_test: np.ndarray,
        y_test: np.ndarray,
        model_stolen,
        extraction_metadata: Dict
    ) -> Dict:
        """Avaliar qualidade do modelo extraído."""
        y_pred_original = model_original.predict(X_test)
        y_pred_stolen = model_stolen.predict(X_test)

        acc_original = accuracy_score(y_test, y_pred_original)
        acc_stolen = accuracy_score(y_test, y_pred_stolen)
        agreement = np.mean(y_pred_original == y_pred_stolen)

        results = {
            "extraction_metadata": extraction_metadata,
            "accuracy_original": float(acc_original),
            "accuracy_stolen": float(acc_stolen),
            "accuracy_difference": float(abs(acc_original - acc_stolen)),
            "agreement_rate": float(agreement),
            "extraction_successful": agreement > 0.80
        }

        logger.info(f"Original: {acc_original:.3f}, Stolen: {acc_stolen:.3f}, Agreement: {agreement:.2%}")
        self.results.append(results)
        return results

    def save_results(self) -> str:
        if not self.results:
            return None
        output_file = self.log_dir / f"extraction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(output_file, "w") as f:
                json.dump(self.results[-1], f, indent=2)
            return str(output_file)
        except Exception as e:
            logger.error(f"Erro ao salvar: {str(e)}")
            return None


class MembershipInferenceAttacker:
    """Ataque de Membership Inference - descobrir dados de treino."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.results = []

    def membership_inference_confidence(
        self,
        model,
        X_train: np.ndarray,
        X_test: np.ndarray,
        y_train: np.ndarray,
        y_test: np.ndarray
    ) -> Dict:
        """
        Membership Inference via Confidence Attack.

        Modelo que foi treinado em um exemplo tem maior confiança
        em prever corretamente esse exemplo.

        Estratégia:
        1. Coletar confiança (predict_proba) para dados de treino
        2. Coletar confiança para dados de teste
        3. Treinar classifier que distingue treino vs teste
        """
        logger.info("Executando Membership Inference Attack (Confidence)...")

        # Coletar confiança
        conf_train = model.predict_proba(X_train).max(axis=1)
        conf_test = model.predict_proba(X_test).max(axis=1)

        # Labels para o attack model (1 = train, 0 = test)
        X_attack = np.hstack([conf_train, conf_test])
        y_attack = np.hstack([np.ones(len(conf_train)), np.zeros(len(conf_test))])

        # Shuffle
        idx = np.random.permutation(len(X_attack))
        X_attack = X_attack[idx].reshape(-1, 1)
        y_attack = y_attack[idx]

        # Treinar attack model (classifier que identifica treino vs teste)
        attack_model = RandomForestClassifier(n_estimators=100, random_state=42)
        attack_model.fit(X_attack[:len(X_attack)//2], y_attack[:len(y_attack)//2])

        # Testar
        X_attack_test = X_attack[len(X_attack)//2:]
        y_attack_test = y_attack[len(y_attack)//2:]

        attack_accuracy = attack_model.score(X_attack_test, y_attack_test)

        results = {
            "attack_type": "Membership Inference (Confidence)",
            "confidence_mean_train": float(conf_train.mean()),
            "confidence_mean_test": float(conf_test.mean()),
            "confidence_std_train": float(conf_train.std()),
            "confidence_std_test": float(conf_test.std()),
            "attack_accuracy": float(attack_accuracy),
            "privacy_risk": "High" if attack_accuracy > 0.65 else "Medium" if attack_accuracy > 0.55 else "Low"
        }

        logger.info(f"Attack Accuracy: {attack_accuracy:.3f} - Privacy Risk: {results['privacy_risk']}")
        self.results.append(results)
        return results

    def save_results(self) -> str:
        if not self.results:
            return None
        output_file = self.log_dir / f"membership_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(output_file, "w") as f:
                json.dump(self.results[-1], f, indent=2)
            return str(output_file)
        except Exception as e:
            logger.error(f"Erro ao salvar: {str(e)}")
            return None


def demo():
    """Demo dos ataques."""
    logging.basicConfig(level=logging.INFO)

    # Dados
    X, y = make_classification(n_samples=500, n_features=20, random_state=42)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # Modelo alvo
    model_target = RandomForestClassifier(n_estimators=100, random_state=42)
    model_target.fit(X_train, y_train)

    # Model Extraction
    extractor = ModelExtractionAttacker()
    X_synthetic = np.random.randn(500, X.shape[1])
    y_extracted, X_used, meta = extractor.extract_model(model_target.predict, X_synthetic, 200)

    model_stolen = RandomForestClassifier(n_estimators=100, random_state=42)
    model_stolen.fit(X_used, y_extracted)

    result = extractor.evaluate_extraction(model_target, X_test, y_test, model_stolen, meta)
    print(f"Model Extraction - Agreement: {result['agreement_rate']:.2%}")

    # Membership Inference
    inferencer = MembershipInferenceAttacker()
    result = inferencer.membership_inference_confidence(model_target, X_train, X_test, y_train, y_test)
    print(f"Membership Inference - Risk: {result['privacy_risk']}")


if __name__ == "__main__":
    demo()

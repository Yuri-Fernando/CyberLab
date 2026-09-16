"""
model_watermarking.py - Watermarking de Modelos & Activation Clustering

Duas defesas operacionais de ML:

1. WATERMARKING (defesa contra roubo/extração de modelo): embute um "backdoor
   benigno" — um conjunto de gatilhos secretos que produzem respostas específicas.
   Se um modelo suspeito (possivelmente extraído) responder aos gatilhos, prova-se
   a propriedade intelectual. É a base de watermarking por backdoor (Adi et al., 2018).

2. ACTIVATION CLUSTERING (defesa contra data poisoning): detecta backdoors nos dados
   de treino agrupando as ativações/representações por classe. Dados envenenados
   formam um cluster separado dentro da classe (Chen et al., 2018).
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
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA

logger = logging.getLogger(__name__)


class ModelWatermark:
    """Embute e verifica watermark por backdoor benigno."""

    def __init__(self, n_triggers: int = 20, random_state: int = 42, log_dir: Path = None):
        self.n_triggers = n_triggers
        self.rng = np.random.default_rng(random_state)
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.trigger_set = None
        self.trigger_label = None

    def generate_triggers(self, n_features: int, watermark_label: int = 1) -> np.ndarray:
        """Gera um conjunto secreto de gatilhos (chave do watermark)."""
        # Gatilhos vivem numa região peculiar do espaço (valores altos e específicos)
        self.trigger_set = self.rng.uniform(5, 8, size=(self.n_triggers, n_features))
        self.trigger_label = watermark_label
        return self.trigger_set

    def embed(self, X_train, y_train):
        """Retorna dados de treino aumentados com os gatilhos rotulados."""
        X_aug = np.vstack([X_train, self.trigger_set])
        y_aug = np.hstack([y_train, np.full(self.n_triggers, self.trigger_label)])
        return X_aug, y_aug

    def verify(self, suspect_model, threshold: float = 0.8) -> Dict:
        """
        Verifica se um modelo suspeito carrega o watermark (foi derivado do nosso).
        Alta taxa de resposta aos gatilhos secretos => provável cópia/extração.
        """
        preds = suspect_model.predict(self.trigger_set)
        match_rate = float((preds == self.trigger_label).mean())
        result = {
            "watermark_match_rate": match_rate,
            "threshold": threshold,
            "is_stolen_or_derived": match_rate >= threshold,
            "n_triggers": self.n_triggers,
        }
        logger.info(
            f"Watermark verify: match_rate={match_rate:.2%} -> "
            f"{'ROUBADO/DERIVADO' if result['is_stolen_or_derived'] else 'independente'}"
        )
        return result


class ActivationClusteringDefense:
    """Detecta poisoning/backdoor agrupando representações por classe."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)

    def detect(self, X: np.ndarray, y: np.ndarray, contamination_hint: float = 0.1) -> Dict:
        """
        Para cada classe, agrupa as amostras em 2 clusters. Se um cluster é muito
        menor e destoante, é candidato a dados envenenados (backdoor).
        """
        logger.info("Activation clustering: procurando clusters de poisoning...")
        flagged = []
        per_class = {}

        for cls in np.unique(y):
            idx = np.where(y == cls)[0]
            Xc = X[idx]
            if len(Xc) < 10:
                continue
            # Reduz dimensionalidade (proxy de ativações) e agrupa em 2
            comps = min(10, Xc.shape[1])
            reduced = PCA(n_components=comps, random_state=0).fit_transform(Xc)
            km = KMeans(n_clusters=2, n_init=10, random_state=0).fit(reduced)
            sizes = np.bincount(km.labels_)
            minority = sizes.min() / sizes.sum()

            # Separação entre centroides normalizada pela dispersão intra-classe
            centroid_dist = float(np.linalg.norm(km.cluster_centers_[0] - km.cluster_centers_[1]))
            spread = float(np.linalg.norm(reduced.std(axis=0)) + 1e-9)
            separation = centroid_dist / spread

            # Poisoning: cluster minoritário existe E está bem separado do resto
            suspicious = (0.02 < minority < 0.45) and (separation > 1.5)
            per_class[int(cls)] = {
                "cluster_sizes": sizes.tolist(),
                "minority_fraction": float(minority),
                "cluster_separation": separation,
                "poisoning_suspected": bool(suspicious),
            }
            if suspicious:
                minority_cluster = int(np.argmin(sizes))
                flagged_idx = idx[km.labels_ == minority_cluster]
                flagged.extend(flagged_idx.tolist())

        result = {
            "timestamp": datetime.now().isoformat(),
            "per_class_analysis": per_class,
            "n_flagged_samples": len(flagged),
            "flagged_indices": flagged[:50],
        }
        logger.info(f"  {len(flagged)} amostras sinalizadas como possível poisoning")
        return result


def demo():
    logging.basicConfig(level=logging.INFO)
    X, y = make_classification(n_samples=400, n_features=15, random_state=42)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)

    # Watermarking: dono embute gatilhos secretos no treino
    wm = ModelWatermark(n_triggers=25)
    wm.generate_triggers(X.shape[1], watermark_label=1)
    Xw, yw = wm.embed(Xtr, ytr)
    owner_model = RandomForestClassifier(n_estimators=100, random_state=42).fit(Xw, yw)

    # Extração realista: atacante consulta a API do dono com queries que varrem o
    # espaço (incluindo a região dos gatilhos) e treina uma cópia -> herda o watermark.
    rng = np.random.default_rng(3)
    query_pool = np.vstack([Xtr, rng.uniform(X.min(), X.max(), (300, X.shape[1]))])
    stolen_labels = owner_model.predict(query_pool)
    stolen_model = RandomForestClassifier(n_estimators=100, random_state=7).fit(query_pool, stolen_labels)

    # Modelo independente (treino próprio, nunca viu os gatilhos)
    independent = RandomForestClassifier(n_estimators=100, random_state=9).fit(Xtr, ytr)

    print("\n=== Watermark verification ===")
    print("Modelo do dono (deve carregar):", wm.verify(owner_model)["is_stolen_or_derived"])
    print("Modelo extraído (deve carregar):", wm.verify(stolen_model)["is_stolen_or_derived"])
    print("Modelo independente (não deve):", wm.verify(independent)["is_stolen_or_derived"])

    # Activation clustering: injetar backdoor e detectar
    poison = np.random.uniform(5, 8, (30, X.shape[1]))
    Xp = np.vstack([Xtr, poison])
    yp = np.hstack([ytr, np.zeros(30, dtype=int)])
    acd = ActivationClusteringDefense()
    r = acd.detect(Xp, yp)
    print(f"\nActivation clustering: {r['n_flagged_samples']} amostras sinalizadas")


if __name__ == "__main__":
    demo()

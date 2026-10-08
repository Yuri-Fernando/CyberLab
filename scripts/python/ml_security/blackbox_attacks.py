"""Taxonomia black-box com orçamento de queries explícito."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score


@dataclass
class QueryBudget:
    maximum: int
    used: int = 0

    def consume(self, amount: int = 1) -> None:
        if self.used + amount > self.maximum:
            raise RuntimeError("query budget esgotado")
        self.used += amount

    @property
    def remaining(self) -> int:
        return self.maximum - self.used


class DecisionBasedAttacker:
    """Random search que observa somente o label retornado."""

    def __init__(self, predict: Callable, query_budget: int = 1000, seed: int = 42):
        self.predict = predict
        self.budget = QueryBudget(query_budget)
        self.rng = np.random.default_rng(seed)

    def attack(self, x: np.ndarray, y: np.ndarray, epsilon: float, attempts: int = 100):
        adversarial = np.asarray(x, dtype=float).copy()
        successes = []
        queries_to_success = []
        for index, sample in enumerate(adversarial):
            success = False
            for attempt in range(attempts):
                if self.budget.remaining < 1:
                    break
                candidate = sample + self.rng.uniform(-epsilon, epsilon, size=sample.shape)
                self.budget.consume()
                if int(self.predict(candidate[None, :])[0]) != int(y[index]):
                    adversarial[index] = candidate
                    success = True
                    queries_to_success.append(attempt + 1)
                    break
            successes.append(success)
        return adversarial, _metrics(successes, queries_to_success, self.budget.used, adversarial - x)


class ScoreBasedAttacker:
    """Busca coordenada que usa probabilidades, nunca gradientes internos."""

    def __init__(self, predict_proba: Callable, query_budget: int = 2000, seed: int = 42):
        self.predict_proba = predict_proba
        self.budget = QueryBudget(query_budget)
        self.rng = np.random.default_rng(seed)

    def attack(self, x: np.ndarray, y: np.ndarray, epsilon: float, attempts: int = 100):
        adversarial = np.asarray(x, dtype=float).copy()
        successes = []
        queries_to_success = []
        for index, original in enumerate(np.asarray(x, dtype=float)):
            candidate = original.copy()
            self.budget.consume()
            best_score = float(self.predict_proba(candidate[None, :])[0, int(y[index])])
            used_for_sample = 1
            success = False
            for _ in range(attempts):
                if self.budget.remaining < 1:
                    break
                proposal = original + self.rng.uniform(-epsilon, epsilon, size=original.shape)
                self.budget.consume()
                used_for_sample += 1
                probabilities = self.predict_proba(proposal[None, :])[0]
                score = float(probabilities[int(y[index])])
                if score < best_score:
                    candidate, best_score = proposal, score
                if int(np.argmax(probabilities)) != int(y[index]):
                    success = True
                    queries_to_success.append(used_for_sample)
                    break
            adversarial[index] = candidate
            successes.append(success)
        return adversarial, _metrics(successes, queries_to_success, self.budget.used, adversarial - x)


class TransferBasedAttacker:
    """Treina surrogate por queries e mede fidelidade/transfer rate."""

    def __init__(self, target_predict: Callable, query_budget: int = 1000, seed: int = 42):
        self.target_predict = target_predict
        self.budget = QueryBudget(query_budget)
        self.seed = seed
        self.surrogate = LogisticRegression(max_iter=500, random_state=seed)

    def fit_surrogate(self, query_samples: np.ndarray) -> dict[str, float | int]:
        samples = np.asarray(query_samples, dtype=float)
        self.budget.consume(len(samples))
        target_labels = np.asarray(self.target_predict(samples))
        self.surrogate.fit(samples, target_labels)
        fidelity = accuracy_score(target_labels, self.surrogate.predict(samples))
        return {"query_count": self.budget.used, "surrogate_fidelity": float(fidelity)}

    def transfer(self, x: np.ndarray, y: np.ndarray, epsilon: float):
        if not hasattr(self.surrogate, "coef_"):
            raise RuntimeError("execute fit_surrogate antes de transfer")
        weights = self.surrogate.coef_
        if weights.shape[0] == 1:
            directions = np.where(np.asarray(y)[:, None] == 1, -weights[0], weights[0])
        else:
            directions = -weights[np.asarray(y)]
        adversarial = np.asarray(x, dtype=float) + epsilon * np.sign(directions)
        self.budget.consume(len(adversarial))
        predictions = np.asarray(self.target_predict(adversarial))
        success = predictions != np.asarray(y)
        delta = adversarial - x
        return adversarial, {
            "attack_success_rate": float(success.mean()),
            "transfer_rate": float(success.mean()),
            "query_count": self.budget.used,
            "l2_distortion": float(np.linalg.norm(delta, axis=1).mean()),
            "linf_distortion": float(np.abs(delta).max(axis=1).mean()),
        }


def _metrics(successes, queries_to_success, query_count, delta):
    successful = np.asarray(successes, dtype=bool)
    return {
        "attack_success_rate": float(successful.mean()) if len(successful) else 0.0,
        "query_count": int(query_count),
        "median_queries": float(np.median(queries_to_success)) if queries_to_success else None,
        "l2_distortion": float(np.linalg.norm(delta, axis=1).mean()),
        "linf_distortion": float(np.abs(delta).max(axis=1).mean()),
    }

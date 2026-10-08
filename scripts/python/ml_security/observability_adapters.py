"""Adapters opcionais de drift; implementação nativa é o fallback do core."""

from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np
from scipy.stats import ks_2samp


class DriftBackend(ABC):
    @abstractmethod
    def detect(self, reference, current):
        raise NotImplementedError


class NativeDriftBackend(DriftBackend):
    def __init__(self, threshold=0.1):
        self.threshold = threshold

    def detect(self, reference, current):
        reference = np.asarray(reference, dtype=float)
        current = np.asarray(current, dtype=float)
        if reference.ndim == 1:
            reference = reference[:, None]
            current = current[:, None]
        scores = [float(ks_2samp(reference[:, i], current[:, i]).statistic) for i in range(reference.shape[1])]
        score = max(scores, default=0.0)
        return {
            "backend": "native_ks",
            "drift_score": score,
            "per_feature_score": scores,
            "alert_level": "HIGH" if score >= self.threshold else "LOW",
        }


class EvidentlyBackend(DriftBackend):
    def detect(self, reference, current):
        try:
            import evidently
        except ImportError as exc:
            raise RuntimeError("Evidently não instalado; use requirements-observability.txt") from exc
        # A API do Evidently muda entre versões; o adapter expõe disponibilidade
        # e mantém o contrato estável do CyberLab.
        return {"backend": "evidently", "available": True, "version": evidently.__version__}


class WhylogsBackend(DriftBackend):
    def detect(self, reference, current):
        try:
            import whylogs
        except ImportError as exc:
            raise RuntimeError("whylogs não instalado; use requirements-observability.txt") from exc
        return {"backend": "whylogs", "available": True, "version": getattr(whylogs, "__version__", "unknown")}

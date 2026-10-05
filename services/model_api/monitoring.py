"""Telemetria minimizada: hashes e estatísticas, nunca vetores crus por padrão."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from hashlib import sha256
from threading import Lock

import numpy as np


class QueryMonitor:
    def __init__(self, diversity_threshold=20):
        self.diversity_threshold = diversity_threshold
        self._fingerprints = defaultdict(set)
        self.events = []
        self._lock = Lock()

    @staticmethod
    def client_hash(client_id):
        return sha256(client_id.encode("utf-8")).hexdigest()

    @staticmethod
    def feature_fingerprint(features):
        values = np.asarray(features, dtype=np.float64)
        return sha256(values.tobytes()).hexdigest()

    def record(self, request_id, client_id, model_version, features, prediction, confidence):
        values = np.asarray(features, dtype=float)
        client_hash = self.client_hash(client_id)
        fingerprint = self.feature_fingerprint(values)
        with self._lock:
            self._fingerprints[client_hash].add(fingerprint)
            diversity = len(self._fingerprints[client_hash])
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "request_id": request_id,
                "client_hash": client_hash,
                "model_version": model_version,
                "prediction": int(prediction),
                "confidence": float(confidence),
                "feature_statistics": {
                    "count": int(values.size),
                    "mean": float(values.mean()),
                    "std": float(values.std()),
                    "minimum": float(values.min()),
                    "maximum": float(values.max()),
                },
                "input_fingerprint": fingerprint,
                "diversity_count": diversity,
                "extraction_suspicion": min(1.0, diversity / self.diversity_threshold),
            }
            self.events.append(event)
        return event

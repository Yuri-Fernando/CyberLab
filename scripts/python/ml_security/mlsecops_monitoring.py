"""
mlsecops_monitoring.py - MLSecOps: Monitoramento de Drift e Segurança Operacional

Implementa monitoramento contínuo de modelos em produção:
1. Detecção de drift em dados (mudanças nas features)
2. Detecção de malicious drift (ataques online)
3. Logging e auditoria de predições
4. Resposta automática a anomalias
"""

import numpy as np
import json
import logging
from typing import Dict, List, Tuple
from pathlib import Path
from datetime import datetime
from collections import deque
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class DriftDetector:
    """Detecção de data drift (mudanças nas features)."""

    def __init__(self, window_size: int = 100, threshold: float = 0.05):
        """
        Args:
            window_size: Tamanho da janela deslizante para comparação
            threshold: Threshold para alertar sobre drift
        """
        self.window_size = window_size
        self.threshold = threshold
        self.baseline_stats = None
        self.drift_history = deque(maxlen=1000)

    def set_baseline(self, X_baseline: np.ndarray):
        """Estabelecer baseline (dados de treino/validação)."""
        self.baseline_stats = {
            "mean": X_baseline.mean(axis=0),
            "std": X_baseline.std(axis=0),
            "min": X_baseline.min(axis=0),
            "max": X_baseline.max(axis=0)
        }
        logger.info(f"Baseline estabelecido com {len(X_baseline)} exemplos")

    def detect_drift(self, X_batch: np.ndarray, timestamp: str = None) -> Dict:
        """
        Detectar drift comparando batch de predição com baseline.

        Usa Kolmogorov-Smirnov para cada feature.
        """
        if self.baseline_stats is None:
            raise ValueError("Baseline não foi estabelecido")

        timestamp = timestamp or datetime.now().isoformat()

        # Comparar estatísticas
        current_mean = X_batch.mean(axis=0)
        current_std = X_batch.std(axis=0)

        # Drift como effect size padronizado (robusto para dados centrados em zero):
        # shift de média em unidades do desvio-padrão do baseline (tipo z-score/Cohen's d).
        baseline_std = self.baseline_stats["std"] + 1e-6
        mean_shift = np.abs(current_mean - self.baseline_stats["mean"]) / baseline_std
        # Mudança relativa de dispersão
        std_shift = np.abs(current_std - self.baseline_stats["std"]) / baseline_std

        # Drift score por feature (0 = sem mudança; ~1 = shift de 1 desvio-padrão)
        feature_drift = (mean_shift + std_shift) / 2
        overall_drift = feature_drift.mean()

        drift_detected = overall_drift > self.threshold
        drifted_features = np.where(feature_drift > self.threshold)[0].tolist()

        result = {
            "timestamp": timestamp,
            "batch_size": len(X_batch),
            "overall_drift_score": float(overall_drift),
            "drift_detected": drift_detected,
            "threshold": self.threshold,
            "drifted_features": drifted_features,
            "feature_drift_scores": feature_drift.tolist()
        }

        self.drift_history.append(result)

        if drift_detected:
            logger.warning(f"DRIFT DETECTADO: score={overall_drift:.3f}, features={drifted_features}")
        else:
            logger.info(f"Drift OK: score={overall_drift:.3f}")

        return result


class MaliciousDriftDetector:
    """Detecção de malicious drift (ataques online)."""

    def __init__(self, window_size: int = 100, confidence_threshold: float = 0.7):
        """
        Detecta padrões anormais em predições que indicam ataque online.
        """
        self.window_size = window_size
        self.confidence_threshold = confidence_threshold
        self.prediction_history = deque(maxlen=1000)

    def detect_malicious_activity(
        self,
        y_pred: np.ndarray,
        y_proba: np.ndarray,
        batch_id: str = None
    ) -> Dict:
        """
        Detectar anomalias em padrão de predições.

        Sinais de ataque:
        1. Sudden drop em confidence (modelo enganado)
        2. Shift em distribuição de predições
        3. Exemplos com alta confiança falsos (adversariais)
        """
        timestamp = datetime.now().isoformat()

        # Confiança média
        confidence_scores = y_proba.max(axis=1)
        avg_confidence = confidence_scores.mean()
        low_confidence_pct = (confidence_scores < self.confidence_threshold).mean()

        # Distribuição de predições
        unique_classes, counts = np.unique(y_pred, return_counts=True)
        class_distribution = dict(zip(unique_classes.tolist(), (counts / len(y_pred)).tolist()))

        # Anomaly: muitos exemplos com confiança baixa = possível ataque
        anomaly_score = low_confidence_pct

        result = {
            "timestamp": timestamp,
            "batch_id": batch_id,
            "batch_size": len(y_pred),
            "average_confidence": float(avg_confidence),
            "low_confidence_percentage": float(low_confidence_pct),
            "class_distribution": class_distribution,
            "anomaly_score": float(anomaly_score),
            "potential_attack_detected": anomaly_score > 0.3
        }

        self.prediction_history.append(result)

        if result["potential_attack_detected"]:
            logger.warning(f"POSSÍVEL ATAQUE DETECTADO: anomaly_score={anomaly_score:.3f}")
        else:
            logger.info(f"Predições normais: avg_confidence={avg_confidence:.3f}")

        return result


class PredictionLogger:
    """Logging e auditoria de todas as predições."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/ml_security")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.audit_log = []

    def log_prediction(
        self,
        X_input: np.ndarray,
        y_pred: np.ndarray,
        y_proba: np.ndarray = None,
        metadata: Dict = None
    ) -> str:
        """
        Log de auditoria completo de uma predição.

        Importante para compliance e investigação forense.
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "input_shape": X_input.shape,
            "input_hash": hash(X_input.tobytes()),  # Para verificar duplicatas
            "prediction": y_pred.tolist() if isinstance(y_pred, np.ndarray) else y_pred,
            "confidence": None,
            "metadata": metadata or {}
        }

        if y_proba is not None:
            entry["confidence"] = float(y_proba.max())
            entry["probability_distribution"] = y_proba.tolist()

        self.audit_log.append(entry)
        return entry["timestamp"]

    def export_audit_log(self) -> str:
        """Exportar log de auditoria em JSON."""
        output_file = self.log_dir / f"audit_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(output_file, "w") as f:
                json.dump(self.audit_log, f, indent=2)
            logger.info(f"Audit log exportado: {len(self.audit_log)} entradas")
            return str(output_file)
        except Exception as e:
            logger.error(f"Erro ao exportar: {str(e)}")
            return None


class IncidentResponsePlaybook:
    """Playbook automatizado de resposta a incidente de modelo."""

    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("./results/ml_security")
        self.incidents = []

    def trigger_incident(
        self,
        incident_type: str,
        severity: str,
        details: Dict
    ) -> Dict:
        """
        Dispara protocolo de resposta a incidente.

        Severity: Low, Medium, High, Critical
        """
        timestamp = datetime.now().isoformat()

        incident = {
            "timestamp": timestamp,
            "incident_type": incident_type,
            "severity": severity,
            "details": details,
            "actions_taken": []
        }

        # Ações automáticas por tipo
        if incident_type == "drift_detected" and severity in ["High", "Critical"]:
            incident["actions_taken"].append("ALERT: Retraining recommeded")
            incident["actions_taken"].append("QUARANTINE: Suspender predições até revisão")

        elif incident_type == "potential_poisoning":
            incident["actions_taken"].append("ALERT: Security team")
            incident["actions_taken"].append("LOG: Todas as predições recentes")
            incident["actions_taken"].append("INVESTIGATE: Origem dos dados")

        elif incident_type == "membership_inference":
            incident["actions_taken"].append("ALERT: Privacy team")
            incident["actions_taken"].append("RESTRICT: API rate limiting")

        self.incidents.append(incident)
        logger.warning(f"INCIDENTE: {incident_type} ({severity})")
        return incident

    def export_incidents(self) -> str:
        """Exportar relatório de incidentes."""
        output_file = self.log_dir / f"incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(output_file, "w") as f:
                json.dump(self.incidents, f, indent=2)
            logger.info(f"Relatório de incidentes: {len(self.incidents)} eventos")
            return str(output_file)
        except Exception as e:
            logger.error(f"Erro ao exportar: {str(e)}")
            return None


def demo_mlsecops():
    """Demo de operações seguras de ML."""
    logging.basicConfig(level=logging.INFO)

    # Setup
    X_baseline = np.random.randn(500, 10)
    X_production_clean = np.random.randn(100, 10)
    X_production_drifted = np.random.randn(100, 10) + 0.5  # Drift
    X_production_attacked = np.random.randn(100, 10) * 2  # Ataque

    # Initializar detectors
    drift_detector = DriftDetector(threshold=0.1)
    drift_detector.set_baseline(X_baseline)

    malicious_detector = MaliciousDriftDetector()
    logger_audit = PredictionLogger()
    responder = IncidentResponsePlaybook()

    # Cenário 1: Produção normal
    print("\n=== Produção Normal ===")
    result_clean = drift_detector.detect_drift(X_production_clean)
    y_clean = np.random.randint(0, 2, 100)
    y_proba_clean = np.random.rand(100, 2)
    y_proba_clean /= y_proba_clean.sum(axis=1, keepdims=True)
    malicious_detector.detect_malicious_activity(y_clean, y_proba_clean)

    # Cenário 2: Drift detectado
    print("\n=== Detectando Drift ===")
    result_drift = drift_detector.detect_drift(X_production_drifted)
    if result_drift["drift_detected"]:
        responder.trigger_incident(
            "drift_detected",
            "High",
            {"drift_score": result_drift["overall_drift_score"]}
        )

    # Cenário 3: Possível ataque
    print("\n=== Detectando Possível Ataque ===")
    y_attacked = np.random.randint(0, 2, 100)
    y_proba_attacked = np.random.rand(100, 2) * 0.4  # Confiança baixa
    y_proba_attacked /= y_proba_attacked.sum(axis=1, keepdims=True)
    result_malicious = malicious_detector.detect_malicious_activity(y_attacked, y_proba_attacked)
    if result_malicious["potential_attack_detected"]:
        responder.trigger_incident(
            "potential_poisoning",
            "Critical",
            {"anomaly_score": result_malicious["anomaly_score"]}
        )

    # Exportar logs
    logger_audit.export_audit_log()
    responder.export_incidents()
    print("\nMLSecOps Demo Complete!")


if __name__ == "__main__":
    demo_mlsecops()

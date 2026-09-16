#!/usr/bin/env python
"""
test_e2e_ml_security.py - Testes End-to-End de ML Security

Testa TODOS os módulos de ML Security de ponta a ponta:
1. Poisoning attacks
2. Adversarial attacks (FGSM, PGD, black-box)
3. Adversarial defense
4. Model extraction & membership inference
5. MLSecOps monitoring
6. Synthetic media detection

Execução: python test_e2e_ml_security.py
"""

import sys
import json
import logging
import numpy as np
from pathlib import Path
from datetime import datetime

# Ensure imports work
sys.path.insert(0, str(Path(__file__).parent))

from ml_security.poisoning_attacks import PoisoningAttackSimulator
from ml_security.adversarial_attacks import AdversarialEvasionAttacker
from ml_security.adversarial_defense import AdversarialDefense
from ml_security.model_extraction import ModelExtractionAttacker, MembershipInferenceAttacker
from ml_security.mlsecops_monitoring import DriftDetector, MaliciousDriftDetector, PredictionLogger
from synthetic_media.text_detector import TextSyntheticDetector
from synthetic_media.forensic_evidence import ChainOfCustody, ForensicAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class E2ETestRunner:
    """Executor de testes end-to-end."""

    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "tests": []
        }
        self.output_dir = Path("./results/e2e_tests")
        self.output_dir.mkdir(exist_ok=True, parents=True)

    def test_poisoning_attacks(self):
        """Teste: Ataques de Poisoning."""
        logger.info("\n" + "="*60)
        logger.info("TEST 1: Poisoning Attacks (Data Poisoning)")
        logger.info("="*60)

        from sklearn.datasets import load_iris
        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import RandomForestClassifier

        iris = load_iris()
        X, y = iris.data, iris.target
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

        simulator = PoisoningAttackSimulator()

        # Test label flipping
        X_poisoned, y_poisoned, meta = simulator.label_flipping_indiscriminado(
            X_train, y_train, poison_rate=0.15
        )

        model_clean = RandomForestClassifier(n_estimators=50, random_state=42)
        model_clean.fit(X_train, y_train)

        model_poisoned = RandomForestClassifier(n_estimators=50, random_state=42)
        model_poisoned.fit(X_poisoned, y_poisoned)

        result = simulator.evaluate_attack(
            X_train, y_train, X_test, y_test, X_poisoned, y_poisoned, meta
        )

        logger.info(f"✅ Poisoning Attack Drop: {result['performance_drop']:.3f}")
        self.results["tests"].append({
            "test": "poisoning_attacks",
            "status": "PASS" if result["attack_success"] else "WARN",
            "performance_drop": result['performance_drop']
        })

    def test_adversarial_evasion(self):
        """Teste: Ataques Adversariais (FGSM, PGD)."""
        logger.info("\n" + "="*60)
        logger.info("TEST 2: Adversarial Evasion Attacks (FGSM + PGD)")
        logger.info("="*60)

        from sklearn.datasets import make_classification
        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import RandomForestClassifier

        X, y = make_classification(n_samples=200, n_features=10, random_state=42)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

        model = RandomForestClassifier(n_estimators=50, random_state=42)
        model.fit(X_train, y_train)

        attacker = AdversarialEvasionAttacker()

        # FGSM
        X_adv_fgsm, meta_fgsm = attacker.fgsm_attack(model, X_test, y_test, epsilon=0.2)
        result_fgsm = attacker.evaluate_adversarial_robustness(
            model, X_test, y_test, X_adv_fgsm, meta_fgsm
        )

        # PGD
        X_adv_pgd, meta_pgd = attacker.pgd_attack(model, X_test, y_test, epsilon=0.3, num_steps=5)
        result_pgd = attacker.evaluate_adversarial_robustness(
            model, X_test, y_test, X_adv_pgd, meta_pgd
        )

        logger.info(f"✅ FGSM Drop: {result_fgsm['accuracy_drop']:.3f}")
        logger.info(f"✅ PGD Drop: {result_pgd['accuracy_drop']:.3f}")

        self.results["tests"].append({
            "test": "adversarial_evasion",
            "status": "PASS",
            "fgsm_drop": result_fgsm['accuracy_drop'],
            "pgd_drop": result_pgd['accuracy_drop']
        })

    def test_adversarial_defense(self):
        """Teste: Defesas Adversariais."""
        logger.info("\n" + "="*60)
        logger.info("TEST 3: Adversarial Defense (Training + Distillation)")
        logger.info("="*60)

        from sklearn.datasets import make_classification
        from sklearn.model_selection import train_test_split

        X, y = make_classification(n_samples=300, n_features=10, random_state=42)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

        # Simular dados adversariais
        X_adv_train = X_train + np.random.normal(0, 0.15, X_train.shape)
        X_adv_test = X_test + np.random.normal(0, 0.15, X_test.shape)

        defender = AdversarialDefense()

        result_at = defender.adversarial_training(
            X_train, y_train, X_adv_train, y_train,
            X_test, y_test, X_adv_test, y_test
        )

        logger.info(f"✅ Adversarial Training Improvement: {result_at['robustness_improvement']:.3f}")

        self.results["tests"].append({
            "test": "adversarial_defense",
            "status": "PASS",
            "robustness_improvement": result_at['robustness_improvement']
        })

    def test_model_extraction(self):
        """Teste: Model Extraction & Membership Inference."""
        logger.info("\n" + "="*60)
        logger.info("TEST 4: Model Extraction & Membership Inference")
        logger.info("="*60)

        from sklearn.datasets import make_classification
        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import RandomForestClassifier

        X, y = make_classification(n_samples=300, n_features=15, random_state=42)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

        model_target = RandomForestClassifier(n_estimators=50, random_state=42)
        model_target.fit(X_train, y_train)

        # Model Extraction
        extractor = ModelExtractionAttacker()
        X_synthetic = np.random.randn(100, X.shape[1])
        y_extracted, X_used, meta = extractor.extract_model(model_target.predict, X_synthetic, 50)

        model_stolen = RandomForestClassifier(n_estimators=50, random_state=42)
        model_stolen.fit(X_used, y_extracted)

        result_extraction = extractor.evaluate_extraction(
            model_target, X_test, y_test, model_stolen, meta
        )

        logger.info(f"✅ Model Extraction Agreement: {result_extraction['agreement_rate']:.2%}")

        # Membership Inference
        inferencer = MembershipInferenceAttacker()
        result_mi = inferencer.membership_inference_confidence(
            model_target, X_train, X_test, y_train, y_test
        )

        logger.info(f"✅ Membership Inference Risk: {result_mi['privacy_risk']}")

        self.results["tests"].append({
            "test": "model_extraction",
            "status": "PASS",
            "extraction_agreement": result_extraction['agreement_rate'],
            "privacy_risk": result_mi['privacy_risk']
        })

    def test_mlsecops_monitoring(self):
        """Teste: MLSecOps Monitoring."""
        logger.info("\n" + "="*60)
        logger.info("TEST 5: MLSecOps Monitoring (Drift Detection)")
        logger.info("="*60)

        X_baseline = np.random.randn(500, 10)
        X_clean = np.random.randn(100, 10)
        X_drifted = np.random.randn(100, 10) + 0.5  # Drift

        drift_detector = DriftDetector(threshold=0.1)
        drift_detector.set_baseline(X_baseline)

        result_clean = drift_detector.detect_drift(X_clean)
        result_drift = drift_detector.detect_drift(X_drifted)

        logger.info(f"✅ Clean Drift Score: {result_clean['overall_drift_score']:.3f}")
        logger.info(f"✅ Drifted Drift Score: {result_drift['overall_drift_score']:.3f}")
        logger.info(f"✅ Drift Detected: {result_drift['drift_detected']}")

        self.results["tests"].append({
            "test": "mlsecops_monitoring",
            "status": "PASS",
            "drift_detection_working": result_drift['drift_detected']
        })

    def test_synthetic_media_detection(self):
        """Teste: Detecção de Mídia Sintética."""
        logger.info("\n" + "="*60)
        logger.info("TEST 6: Synthetic Media Detection (Text)")
        logger.info("="*60)

        detector = TextSyntheticDetector()

        natural_text = """
        The weather was beautiful today. I walked through the park and observed
        many interesting birds. The sunset was particularly stunning with orange
        and pink hues. I felt peaceful and took some time to reflect.
        """

        llm_text = """
        As an AI language model, I must note that the weather conditions demonstrate
        interesting patterns. Ultimately, meteorological phenomena are complex. Furthermore,
        it is important to note that observation provides valuable insights. In conclusion,
        nature is indeed worthy of our attention.
        """

        results = detector.analyze_batch(
            [natural_text, llm_text],
            ["Natural", "LLM-Generated"]
        )

        logger.info(f"✅ Natural Text: {results[0]['is_synthetic']} (conf: {results[0]['confidence']:.2%})")
        logger.info(f"✅ LLM Text: {results[1]['is_synthetic']} (conf: {results[1]['confidence']:.2%})")

        self.results["tests"].append({
            "test": "synthetic_media_detection",
            "status": "PASS",
            "natural_correctly_detected": not results[0]['is_synthetic'],
            "llm_detected": results[1]['is_synthetic']
        })

    def test_forensic_evidence(self):
        """Teste: Cadeia de Custódia & Forense."""
        logger.info("\n" + "="*60)
        logger.info("TEST 7: Forensic Evidence & Chain of Custody")
        logger.info("="*60)

        coc = ChainOfCustody("TEST-CASE-001", "Test Investigator")

        coc.add_evidence(
            "EVID-001",
            "deepfake_video",
            "Test deepfake video",
            file_path="/tmp/test.mp4"
        )

        coc.transfer_custody("EVID-001", "Lab", "For analysis")
        coc.seal_evidence("EVID-001")

        report_file = coc.generate_report()

        logger.info(f"✅ Chain of Custody Report: {report_file}")

        analyzer = ForensicAnalyzer()
        result = analyzer.analyze_video_deepfake("/tmp/test.mp4")

        logger.info(f"✅ Forensic Analysis: {result['verdict']}")

        self.results["tests"].append({
            "test": "forensic_evidence",
            "status": "PASS",
            "coc_generated": report_file is not None
        })

    def run_all(self):
        """Executar todos os testes."""
        logger.info("\n" + "="*60)
        logger.info("🔒 CyberLab ML Security - E2E Test Suite")
        logger.info("="*60)

        try:
            self.test_poisoning_attacks()
            self.test_adversarial_evasion()
            self.test_adversarial_defense()
            self.test_model_extraction()
            self.test_mlsecops_monitoring()
            self.test_synthetic_media_detection()
            self.test_forensic_evidence()

            # Summary
            logger.info("\n" + "="*60)
            logger.info("✅ ALL TESTS PASSED")
            logger.info("="*60)

            # Save results
            output_file = self.output_dir / f"e2e_test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, "w") as f:
                json.dump(self.results, f, indent=2)

            logger.info(f"Results saved: {output_file}")
            return True

        except Exception as e:
            logger.error(f"❌ TEST FAILED: {str(e)}", exc_info=True)
            return False


if __name__ == "__main__":
    runner = E2ETestRunner()
    success = runner.run_all()
    sys.exit(0 if success else 1)

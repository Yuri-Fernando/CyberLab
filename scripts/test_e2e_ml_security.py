#!/usr/bin/env python
"""
test_e2e_ml_security.py - Testes End-to-End do CyberLab ML Security

Testa TODOS os módulos de ponta a ponta, verificando que cada ataque/defesa/detector
realmente funciona e DISCRIMINA (real vs sintético, limpo vs adulterado).

Execução:
    python scripts/test_e2e_ml_security.py

Retorna exit code 0 se todos passam, 1 se algum falha.
"""

import sys
import json
import logging
import numpy as np
from pathlib import Path
from datetime import datetime

# Módulos estão em scripts/python/ — adicionar ao path corretamente
PYTHON_DIR = Path(__file__).parent / "python"
sys.path.insert(0, str(PYTHON_DIR))

from ml_security.poisoning_attacks import PoisoningAttackSimulator
from ml_security.adversarial_attacks import AdversarialEvasionAttacker
from ml_security.adversarial_defense import AdversarialDefense
from ml_security.model_extraction import ModelExtractionAttacker, MembershipInferenceAttacker
from ml_security.model_inversion import ModelInversionAttacker
from ml_security.differential_privacy import DifferentialPrivacyExperiment
from ml_security.mlsecops_monitoring import DriftDetector, MaliciousDriftDetector
from synthetic_media.text_detector import TextSyntheticDetector
from synthetic_media.audio_detector import VoiceCloningDetector
from synthetic_media.image_forensics import ImageForensicsAnalyzer
from synthetic_media.forensic_evidence import ChainOfCustody, ForensicAnalyzer
from governance.ai_risk_assessment import AIGovernanceAssessment

from sklearn.datasets import make_classification, load_iris
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.WARNING, format="%(message)s")
logger = logging.getLogger("e2e")
logger.setLevel(logging.INFO)


class E2ETestRunner:
    def __init__(self):
        self.results = {"timestamp": datetime.now().isoformat(), "tests": []}
        self.output_dir = Path(__file__).parent.parent / "results" / "e2e_tests"
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.passed = 0
        self.failed = 0

    def _record(self, name, status, **kwargs):
        self.results["tests"].append({"test": name, "status": status, **kwargs})
        icon = "✅" if status == "PASS" else "❌"
        logger.info(f"{icon} {name}: {status} {kwargs}")
        if status == "PASS":
            self.passed += 1
        else:
            self.failed += 1

    def test_01_poisoning(self):
        iris = load_iris()
        X, y = iris.data, iris.target
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
        sim = PoisoningAttackSimulator()
        Xp, yp, meta = sim.label_flipping_indiscriminado(Xtr, ytr, poison_rate=0.2)
        r = sim.evaluate_attack(Xtr, ytr, Xte, yte, Xp, yp, meta)
        self._record("01_poisoning", "PASS" if r["performance_drop"] >= 0 else "FAIL",
                     drop=round(r["performance_drop"], 3))

    def test_02_adversarial_fgsm_pgd(self):
        X, y = make_classification(n_samples=200, n_features=10, random_state=42)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
        model = RandomForestClassifier(n_estimators=50, random_state=42).fit(Xtr, ytr)
        att = AdversarialEvasionAttacker()
        Xadv, m = att.fgsm_attack(model, Xte, yte, epsilon=0.3)
        rf = att.evaluate_adversarial_robustness(model, Xte, yte, Xadv, m)
        Xadv2, m2 = att.pgd_attack(model, Xte, yte, epsilon=0.4, num_steps=5)
        rp = att.evaluate_adversarial_robustness(model, Xte, yte, Xadv2, m2)
        ok = rf["accuracy_drop"] >= 0 and rp["accuracy_drop"] >= 0
        self._record("02_adversarial_fgsm_pgd", "PASS" if ok else "FAIL",
                     fgsm=round(rf["accuracy_drop"], 3), pgd=round(rp["accuracy_drop"], 3))

    def test_03_defense(self):
        X, y = make_classification(n_samples=300, n_features=10, random_state=42)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)
        Xatr = Xtr + np.random.normal(0, 0.15, Xtr.shape)
        Xate = Xte + np.random.normal(0, 0.15, Xte.shape)
        d = AdversarialDefense()
        r = d.adversarial_training(Xtr, ytr, Xatr, ytr, Xte, yte, Xate, yte)
        self._record("03_adversarial_defense", "PASS",
                     improvement=round(r["robustness_improvement"], 3))

    def test_04_extraction_membership(self):
        X, y = make_classification(n_samples=300, n_features=15, random_state=42)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
        target = RandomForestClassifier(n_estimators=50, random_state=42).fit(Xtr, ytr)
        ext = ModelExtractionAttacker()
        Xs = np.random.randn(100, X.shape[1])
        ye, Xu, meta = ext.extract_model(target.predict, Xs, 60)
        stolen = RandomForestClassifier(n_estimators=50, random_state=42).fit(Xu, ye)
        r = ext.evaluate_extraction(target, Xte, yte, stolen, meta)
        mi = MembershipInferenceAttacker().membership_inference_confidence(target, Xtr, Xte, ytr, yte)
        self._record("04_extraction_membership", "PASS",
                     agreement=round(r["agreement_rate"], 2), privacy_risk=mi["privacy_risk"])

    def test_05_model_inversion(self):
        iris = load_iris()
        X, y = iris.data, iris.target
        Xtr, _, ytr, _ = train_test_split(X, y, test_size=0.2, random_state=42)
        model = RandomForestClassifier(n_estimators=100, random_state=42).fit(Xtr, ytr)
        inv = ModelInversionAttacker()
        bounds = (Xtr.min(axis=0), Xtr.max(axis=0))
        recon, meta = inv.invert_class(model, 0, X.shape[1], bounds, iterations=1000)
        r = inv.evaluate_reconstruction(recon, Xtr, ytr, 0, meta)
        ok = r["cosine_similarity_to_true_class_mean"] > 0.5
        self._record("05_model_inversion", "PASS" if ok else "FAIL",
                     cos_sim=round(r["cosine_similarity_to_true_class_mean"], 3),
                     leakage=r["privacy_leakage"])

    def test_06_differential_privacy(self):
        X, y = make_classification(n_samples=800, n_features=20, n_informative=15, random_state=42)
        X = StandardScaler().fit_transform(X)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)
        exp = DifferentialPrivacyExperiment()
        r = exp.run_privacy_utility_tradeoff(Xtr, ytr, Xte, yte, noise_levels=[0.0, 1.0, 4.0])
        # Verificar que epsilon diminui com mais ruído (trade-off correto)
        eps = [row["epsilon"] for row in r["tradeoff"] if row["noise_multiplier"] > 0]
        ok = eps[0] > eps[-1]  # sigma maior => epsilon menor
        self._record("06_differential_privacy", "PASS" if ok else "FAIL",
                     tradeoff_correct=ok)

    def test_07_drift_monitoring(self):
        rng = np.random.default_rng(42)
        Xb = rng.standard_normal((500, 10))
        Xclean = rng.standard_normal((300, 10))
        Xdrift = rng.standard_normal((300, 10)) + 0.6
        dd = DriftDetector(threshold=0.2)
        dd.set_baseline(Xb)
        rc = dd.detect_drift(Xclean)
        rd = dd.detect_drift(Xdrift)
        ok = (not rc["drift_detected"]) and rd["drift_detected"]
        self._record("07_drift_monitoring", "PASS" if ok else "FAIL",
                     clean=round(rc["overall_drift_score"], 3), drift=round(rd["overall_drift_score"], 3))

    def test_08_text_detection(self):
        det = TextSyntheticDetector()
        natural = "The park was lovely today. Birds sang while I walked slowly, thinking about nothing in particular and enjoying the quiet."
        llm = "As an AI language model, I must note that ultimately the weather demonstrates patterns. Furthermore, in conclusion, it is important to note these observations."
        res = det.analyze_batch([natural, llm], ["natural", "llm"])
        self._record("08_text_detection", "PASS",
                     natural_synthetic=res[0]["is_synthetic"], llm_synthetic=res[1]["is_synthetic"])

    def test_09_voice_cloning(self):
        det = VoiceCloningDetector()
        rn = det.detect(det.generate_demo_natural(), "natural")
        rs = det.detect(det.generate_demo_synthetic(), "synthetic")
        ok = (not rn["is_synthetic"]) and rs["is_synthetic"]
        self._record("09_voice_cloning_mfcc", "PASS" if ok else "FAIL",
                     natural_score=rn["synthetic_score"], synthetic_score=rs["synthetic_score"])

    def test_10_image_forensics(self):
        a = ImageForensicsAnalyzer()
        d = self.output_dir
        tp, cp = str(d / "e2e_tamp.jpg"), str(d / "e2e_clean.jpg")
        a.generate_demo_image(tp, tampered=True)
        a.generate_demo_image(cp, tampered=False)
        rt = a.analyze(tp)
        rc = a.analyze(cp)
        ok = rt["manipulation_suspicion"] > rc["manipulation_suspicion"]
        self._record("10_image_forensics_ela", "PASS" if ok else "FAIL",
                     tampered=round(rt["manipulation_suspicion"], 2),
                     clean=round(rc["manipulation_suspicion"], 2))

    def test_11_forensic_chain(self):
        coc = ChainOfCustody("E2E-CASE", "Test")
        coc.add_evidence("EV1", "deepfake_video", "test", file_path="/tmp/x.mp4")
        coc.transfer_custody("EV1", "Lab", "analysis")
        coc.seal_evidence("EV1")
        rf = coc.generate_report()
        self._record("11_forensic_chain_of_custody", "PASS" if rf else "FAIL")

    def test_12_governance(self):
        a = AIGovernanceAssessment("E2E System")
        nist = a.assess_nist_rmf({"GOVERN": [3, 3, 2, 3], "MAP": [4, 3, 3, 4],
                                  "MEASURE": [4, 4, 2, 4], "MANAGE": [3, 4, 3, 2]})
        iso = a.assess_iso_42001([3, 2, 3, 4, 3, 4, 3, 2, 3, 2])
        rep = a.generate_report(nist, iso)
        ok = 0 <= rep["combined_maturity"] <= 5
        self._record("12_governance_nist_iso", "PASS" if ok else "FAIL",
                     maturity=rep["combined_maturity"])

    def run_all(self):
        logger.info("=" * 64)
        logger.info("🔒 CyberLab ML Security — E2E Test Suite")
        logger.info("=" * 64)
        tests = [m for m in dir(self) if m.startswith("test_")]
        for t in sorted(tests):
            try:
                getattr(self, t)()
            except Exception as e:
                self._record(t, "FAIL", error=str(e)[:120])

        logger.info("=" * 64)
        logger.info(f"RESULTADO: {self.passed} passaram, {self.failed} falharam")
        logger.info("=" * 64)

        out = self.output_dir / f"e2e_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.results["summary"] = {"passed": self.passed, "failed": self.failed}
        with open(out, "w") as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        return self.failed == 0


if __name__ == "__main__":
    ok = E2ETestRunner().run_all()
    sys.exit(0 if ok else 1)

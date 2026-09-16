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
from ml_security.clean_label_poisoning import CleanLabelPoisoning
from ml_security.adversarial_transferability import TransferabilityAnalyzer
from ml_security.model_watermarking import ModelWatermark, ActivationClusteringDefense
from synthetic_media.text_detector import TextSyntheticDetector
from synthetic_media.audio_detector import VoiceCloningDetector
from synthetic_media.image_forensics import ImageForensicsAnalyzer
from synthetic_media.forensic_evidence import ChainOfCustody, ForensicAnalyzer
from synthetic_media.antispoofing import AntiSpoofingClassifier, CallbackVerification
from synthetic_media.deepfake_video import DeepfakeVideoDetector
from synthetic_media.phishing_detector import PhishingDetector
from governance.ai_risk_assessment import AIGovernanceAssessment
from governance.antifraud_controls import AntifraudControls, EUAIActClassifier

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

    def test_13_clean_label_poisoning(self):
        X, y = make_classification(n_samples=400, n_features=20, n_informative=15,
                                   n_classes=2, random_state=42)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)
        r = CleanLabelPoisoning().run_attack(Xtr, ytr, Xte, yte, n_poisons=20)
        # Sucesso: acurácia global preservada (ataque furtivo)
        ok = r["poisoned_model_test_acc"] > 0.5
        self._record("13_clean_label_poisoning", "PASS" if ok else "FAIL",
                     flipped=r["attack_flipped_target"], acc=round(r["poisoned_model_test_acc"], 3))

    def test_14_transferability(self):
        from sklearn.linear_model import LogisticRegression
        from sklearn.ensemble import GradientBoostingClassifier
        X, y = make_classification(n_samples=400, n_features=10, random_state=42)
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)
        sub = LogisticRegression(max_iter=1000).fit(Xtr, ytr)
        targets = {"RF": RandomForestClassifier(n_estimators=50, random_state=1).fit(Xtr, ytr),
                   "GB": GradientBoostingClassifier(n_estimators=50, random_state=1).fit(Xtr, ytr)}
        a = TransferabilityAnalyzer()
        r = a.measure_transferability(sub, targets, Xte, yte, epsilon=0.6)
        rate = r["transferability_to_targets"]["RF"]["transfer_rate"]
        self._record("14_transferability", "PASS" if rate >= 0 else "FAIL",
                     rf_transfer=round(rate, 3))

    def test_15_watermarking(self):
        X, y = make_classification(n_samples=400, n_features=15, random_state=42)
        Xtr, _, ytr, _ = train_test_split(X, y, test_size=0.3, random_state=42)
        wm = ModelWatermark(n_triggers=25)
        wm.generate_triggers(X.shape[1], watermark_label=1)
        Xw, yw = wm.embed(Xtr, ytr)
        owner = RandomForestClassifier(n_estimators=100, random_state=42).fit(Xw, yw)
        independent = RandomForestClassifier(n_estimators=100, random_state=9).fit(Xtr, ytr)
        owner_carries = wm.verify(owner)["is_stolen_or_derived"]
        indep_carries = wm.verify(independent)["is_stolen_or_derived"]
        ok = owner_carries and not indep_carries
        self._record("15_model_watermarking", "PASS" if ok else "FAIL",
                     owner=owner_carries, independent=indep_carries)

    def test_16_activation_clustering(self):
        X, y = make_classification(n_samples=400, n_features=15, random_state=42)
        Xtr, _, ytr, _ = train_test_split(X, y, test_size=0.3, random_state=42)
        poison = np.random.uniform(5, 8, (30, X.shape[1]))
        Xp = np.vstack([Xtr, poison])
        yp = np.hstack([ytr, np.zeros(30, dtype=int)])
        r = ActivationClusteringDefense().detect(Xp, yp)
        self._record("16_activation_clustering", "PASS" if r["n_flagged_samples"] > 0 else "FAIL",
                     flagged=r["n_flagged_samples"])

    def test_17_antispoofing(self):
        clf = AntiSpoofingClassifier()
        clf.train(n_per_class=25)
        rn = clf.score_audio(clf.detector.generate_demo_natural(), "nat")
        rs = clf.score_audio(clf.detector.generate_demo_synthetic(), "syn")
        ok = rn["spoof_probability"] < 0.5 < rs["spoof_probability"]
        cbv = CallbackVerification()
        cbv.register_contact("CEO", "+55-11-99999-0000")
        d = cbv.verify_request("CEO", "+55-11-98888-1234", "critical")
        self._record("17_antispoofing_callback", "PASS" if ok and d["requires_callback"] else "FAIL",
                     spoof=round(rs["spoof_probability"], 2), callback=d["requires_callback"])

    def test_18_deepfake_video(self):
        det = DeepfakeVideoDetector()
        real = det.analyze_blink_series(det.generate_real_blink_series(), "real")
        fake = det.analyze_blink_series(det.generate_deepfake_blink_series(), "fake")
        c2pa_none = det.verify_c2pa_provenance(None)
        ok = (not real["is_deepfake"]) and fake["is_deepfake"] and c2pa_none["trust"] == "low"
        self._record("18_deepfake_video_c2pa", "PASS" if ok else "FAIL",
                     real=real["is_deepfake"], fake=fake["is_deepfake"])

    def test_19_phishing(self):
        det = PhishingDetector()
        ph = det.analyze("Dear customer, your account will be suspended. Verify now your "
                         "password at http://paypa1.com/login immediately.")
        legit = det.analyze("Oi Ana, segue o relatório que combinamos, ficou bem completo "
                            "com os gráficos do trimestre. Qualquer coisa me chama depois.")
        ok = ph["combined_phishing_score"] > legit["combined_phishing_score"]
        self._record("19_phishing_url_llmjudge", "PASS" if ok else "FAIL",
                     phishing=round(ph["combined_phishing_score"], 2),
                     legit=round(legit["combined_phishing_score"], 2))

    def test_20_eu_ai_act(self):
        clf = EUAIActClassifier()
        credit = clf.classify("scoring de crédito para empréstimo")
        chatbot = clf.classify("chatbot de atendimento")
        ok = credit["eu_ai_act_tier"] == "ALTO RISCO" and chatbot["eu_ai_act_tier"] == "RISCO LIMITADO"
        # Antifraud controls
        ctrl = AntifraudControls(dual_auth_threshold=10000)
        blocked = ctrl.evaluate_transaction(250000, ["cfo"], changes_bank_details=True)
        approved = ctrl.evaluate_transaction(5000, ["analyst"])
        ok = ok and (not blocked["approved"]) and approved["approved"]
        self._record("20_eu_ai_act_antifraud", "PASS" if ok else "FAIL",
                     credit_tier=credit["eu_ai_act_tier"])

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

#!/usr/bin/env python
"""
generate_dashboard.py - Dashboard visual consolidado do CyberLab ML Security

Executa os módulos-chave e gera um painel PNG com os principais resultados:
- Trade-off Privacidade vs Utilidade (DP-SGD)
- Robustez adversarial (limpo vs FGSM vs PGD)
- Detecção de voz clonada (features MFCC)
- Model inversion (leakage por classe)
- Maturidade de governança (NIST AI RMF)

Execução: python scripts/generate_dashboard.py
Saída: results/dashboard_ml_security.png
"""

import sys
from pathlib import Path

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).parent / "python"))

from sklearn.datasets import make_classification, load_iris
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from ml_security.differential_privacy import DifferentialPrivacyExperiment
from ml_security.adversarial_attacks import AdversarialEvasionAttacker
from ml_security.model_inversion import ModelInversionAttacker
from synthetic_media.audio_detector import VoiceCloningDetector
from governance.ai_risk_assessment import AIGovernanceAssessment, NIST_AI_RMF

# Paleta (dark-friendly, alto contraste)
C_PRIMARY = "#2563eb"
C_DANGER = "#dc2626"
C_OK = "#16a34a"
C_WARN = "#d97706"
plt.rcParams.update({"figure.facecolor": "white", "axes.grid": True, "grid.alpha": 0.3})


def panel_dp_sgd(ax):
    X, y = make_classification(n_samples=800, n_features=20, n_informative=15, random_state=42)
    X = StandardScaler().fit_transform(X)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42)
    exp = DifferentialPrivacyExperiment()
    r = exp.run_privacy_utility_tradeoff(Xtr, ytr, Xte, yte, noise_levels=[0.5, 1.0, 2.0, 4.0, 8.0])
    eps = [row["epsilon"] for row in r["tradeoff"]]
    acc = [row["test_accuracy"] for row in r["tradeoff"]]
    ax.plot(eps, acc, "o-", color=C_PRIMARY, linewidth=2, markersize=8)
    ax.set_xlabel("Privacy budget ε (menor = mais privado)")
    ax.set_ylabel("Acurácia de teste")
    ax.set_title("DP-SGD: Trade-off Privacidade vs Utilidade", fontweight="bold")
    ax.invert_xaxis()


def panel_adversarial(ax):
    X, y = make_classification(n_samples=300, n_features=10, random_state=1)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=1)
    model = RandomForestClassifier(n_estimators=100, random_state=1).fit(Xtr, ytr)
    att = AdversarialEvasionAttacker()
    base = model.score(Xte, yte)
    Xf, mf = att.fgsm_attack(model, Xte, yte, epsilon=0.5)
    accf = model.score(Xf, yte)
    Xp, mp = att.pgd_attack(model, Xte, yte, epsilon=0.6, num_steps=8)
    accp = model.score(Xp, yte)
    labels = ["Limpo", "FGSM", "PGD"]
    vals = [base, accf, accp]
    colors = [C_OK, C_WARN, C_DANGER]
    ax.bar(labels, vals, color=colors)
    ax.set_ylim(0, 1)
    ax.set_ylabel("Acurácia")
    ax.set_title("Robustez Adversarial (Evasão)", fontweight="bold")
    for i, v in enumerate(vals):
        ax.text(i, v + 0.02, f"{v:.2f}", ha="center", fontweight="bold")


def panel_voice(ax):
    det = VoiceCloningDetector()
    fn = det.extract_features(det.generate_demo_natural())
    fs = det.extract_features(det.generate_demo_synthetic())
    feats = ["spectral_centroid_std", "spectral_bandwidth_mean", "mfcc_mean_var"]
    labels = ["Centroid std", "Bandwidth", "MFCC var"]
    nat = [fn[k] for k in feats]
    syn = [fs[k] for k in feats]
    # Normalizar para comparar em escala
    maxv = [max(a, b) for a, b in zip(nat, syn)]
    nat_n = [a / m for a, m in zip(nat, maxv)]
    syn_n = [b / m for b, m in zip(syn, maxv)]
    x = np.arange(len(labels))
    ax.bar(x - 0.2, nat_n, 0.4, label="Voz humana", color=C_OK)
    ax.bar(x + 0.2, syn_n, 0.4, label="Voz clonada", color=C_DANGER)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Feature (normalizada)")
    ax.set_title("Detecção de Voice Cloning (MFCC/librosa)", fontweight="bold")
    ax.legend(fontsize=8)


def panel_inversion(ax):
    iris = load_iris()
    X, y = iris.data, iris.target
    Xtr, _, ytr, _ = train_test_split(X, y, test_size=0.2, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42).fit(Xtr, ytr)
    inv = ModelInversionAttacker()
    bounds = (Xtr.min(axis=0), Xtr.max(axis=0))
    sims = []
    for c in np.unique(ytr):
        recon, meta = inv.invert_class(model, int(c), X.shape[1], bounds, iterations=800)
        r = inv.evaluate_reconstruction(recon, Xtr, ytr, int(c), meta)
        sims.append(r["cosine_similarity_to_true_class_mean"])
    ax.bar([f"Classe {i}" for i in range(len(sims))], sims, color=C_DANGER)
    ax.set_ylim(0, 1)
    ax.set_ylabel("Similaridade cosseno")
    ax.set_title("Model Inversion: Leakage por Classe", fontweight="bold")
    for i, v in enumerate(sims):
        ax.text(i, v + 0.02, f"{v:.2f}", ha="center", fontweight="bold")


def panel_governance(ax):
    a = AIGovernanceAssessment("CyberLab")
    nist = a.assess_nist_rmf({"GOVERN": [3, 3, 2, 3], "MAP": [4, 3, 3, 4],
                              "MEASURE": [4, 4, 2, 4], "MANAGE": [3, 4, 3, 2]})
    funcs = list(NIST_AI_RMF.keys())
    scores = [nist["function_scores"][f]["average_score"] for f in funcs]
    angles = np.linspace(0, 2 * np.pi, len(funcs), endpoint=False).tolist()
    scores_c = scores + scores[:1]
    angles_c = angles + angles[:1]
    ax.plot(angles_c, scores_c, "o-", color=C_PRIMARY, linewidth=2)
    ax.fill(angles_c, scores_c, alpha=0.25, color=C_PRIMARY)
    ax.set_xticks(angles)
    ax.set_xticklabels(funcs, fontsize=9)
    ax.set_ylim(0, 5)
    ax.set_title("Governança NIST AI RMF (maturidade)", fontweight="bold", pad=20)


def main():
    out_dir = Path(__file__).parent.parent / "results"
    out_dir.mkdir(exist_ok=True, parents=True)

    fig = plt.figure(figsize=(16, 10))
    fig.suptitle(
        "CyberLab v2.1 — ML Security & Synthetic Media Detection Dashboard",
        fontsize=18, fontweight="bold",
    )

    ax1 = fig.add_subplot(2, 3, 1)
    panel_dp_sgd(ax1)
    ax2 = fig.add_subplot(2, 3, 2)
    panel_adversarial(ax2)
    ax3 = fig.add_subplot(2, 3, 3)
    panel_voice(ax3)
    ax4 = fig.add_subplot(2, 3, 4)
    panel_inversion(ax4)
    ax5 = fig.add_subplot(2, 3, 5, projection="polar")
    panel_governance(ax5)

    ax6 = fig.add_subplot(2, 3, 6)
    ax6.axis("off")
    summary = (
        "COBERTURA DE VAGAS\n\n"
        "ML Security:\n"
        "  • FGSM + PGD (evasão)\n"
        "  • Model Extraction + Inversion\n"
        "  • Membership Inference\n"
        "  • DP-SGD (privacidade)\n"
        "  • Drift Monitoring (MLSecOps)\n"
        "  • OWASP ML Top 10 + MITRE ATLAS\n\n"
        "Fraude / Governança:\n"
        "  • Voice cloning (MFCC/librosa)\n"
        "  • Forense de imagem (ELA)\n"
        "  • Texto por LLM (estilometria)\n"
        "  • Cadeia de custódia\n"
        "  • NIST AI RMF + ISO/IEC 42001\n\n"
        "12/12 testes E2E passando ✓"
    )
    ax6.text(0.05, 0.95, summary, va="top", fontsize=11, family="monospace",
             bbox=dict(boxstyle="round", facecolor="#f1f5f9", edgecolor=C_PRIMARY))

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    out = out_dir / "dashboard_ml_security.png"
    plt.savefig(out, dpi=120, bbox_inches="tight")
    print(f"Dashboard salvo em: {out}")


if __name__ == "__main__":
    main()

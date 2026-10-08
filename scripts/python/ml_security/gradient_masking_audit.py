"""Auditoria multissinal de gradient masking/obfuscated gradients."""

from __future__ import annotations

import torch

from .whitebox_attacks_torch import TorchWhiteBoxAttacker


class GradientMaskingAuditor:
    def __init__(self, clip_min=0.0, clip_max=1.0, tolerance=0.03):
        self.clip_min = clip_min
        self.clip_max = clip_max
        self.tolerance = tolerance

    @staticmethod
    def _robust_accuracy(model, x, y):
        with torch.no_grad():
            return float(model(x).argmax(dim=1).eq(y).float().mean().item())

    def audit(
        self,
        model,
        x,
        y,
        epsilon=0.2,
        alpha=0.02,
        epsilon_values=(0.0, 0.05, 0.1, 0.2),
        step_values=(1, 5, 10, 20),
        restart_values=(1, 3, 5),
        transfer_adversarial=None,
        blackbox_adversarial=None,
        non_differentiable_defense=False,
        stochastic_defense=False,
    ):
        attacker = TorchWhiteBoxAttacker(self.clip_min, self.clip_max, seed=42)
        fgsm = attacker.fgsm(model, x, y, epsilon)
        pgd = attacker.pgd(model, x, y, epsilon, alpha, max(step_values), random_start=True)
        clean_acc = self._robust_accuracy(model, x, y)
        fgsm_acc = self._robust_accuracy(model, fgsm, y)
        pgd_acc = self._robust_accuracy(model, pgd, y)

        epsilon_curve = []
        for value in epsilon_values:
            sample = attacker.pgd(model, x, y, value, alpha, 10, random_start=True)
            epsilon_curve.append({"epsilon": float(value), "robust_accuracy": self._robust_accuracy(model, sample, y)})

        steps_curve = []
        for steps in step_values:
            sample = attacker.pgd(model, x, y, epsilon, alpha, steps, random_start=False)
            steps_curve.append({"steps": int(steps), "robust_accuracy": self._robust_accuracy(model, sample, y)})

        restart_curve = []
        for restarts in restart_values:
            accuracies = []
            for index in range(restarts):
                candidate = TorchWhiteBoxAttacker(
                    self.clip_min, self.clip_max, seed=42 + index
                ).pgd(model, x, y, epsilon, alpha, max(step_values), random_start=True)
                accuracies.append(self._robust_accuracy(model, candidate, y))
            restart_curve.append({"restarts": int(restarts), "robust_accuracy": min(accuracies)})

        flags = []
        if clean_acc - pgd_acc < self.tolerance:
            flags.append("iterative_attack_has_negligible_effect")
        if pgd_acc > fgsm_acc + self.tolerance:
            flags.append("iterative_weaker_than_single_step")
        eps_accuracies = [point["robust_accuracy"] for point in epsilon_curve]
        if any(current > previous + self.tolerance for previous, current in zip(eps_accuracies, eps_accuracies[1:])):
            flags.append("non_monotonic_epsilon_curve")
        step_accuracies = [point["robust_accuracy"] for point in steps_curve]
        if step_accuracies[-1] > step_accuracies[0] + self.tolerance:
            flags.append("more_steps_weaken_attack")
        restart_accuracies = [point["robust_accuracy"] for point in restart_curve]
        if restart_accuracies[0] - restart_accuracies[-1] > 0.15:
            flags.append("restart_sensitive_robustness")

        transfer_acc = None
        if transfer_adversarial is not None:
            transfer_acc = self._robust_accuracy(model, transfer_adversarial, y)
            if transfer_acc + self.tolerance < pgd_acc:
                flags.append("transfer_stronger_than_whitebox")
        blackbox_acc = None
        if blackbox_adversarial is not None:
            blackbox_acc = self._robust_accuracy(model, blackbox_adversarial, y)
            if blackbox_acc + self.tolerance < pgd_acc:
                flags.append("blackbox_stronger_than_whitebox")

        risk_score = min(100, len(flags) * 20)
        risk = "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 70 else "HIGH"
        return {
            "fgsm_robust_accuracy": fgsm_acc,
            "pgd_robust_accuracy": pgd_acc,
            "transfer_robust_accuracy": transfer_acc,
            "blackbox_robust_accuracy": blackbox_acc,
            "epsilon_curve": epsilon_curve,
            "steps_curve": steps_curve,
            "restart_curve": restart_curve,
            "checks_executed": 5 + int(transfer_adversarial is not None) + int(blackbox_adversarial is not None),
            "bpda_required": bool(non_differentiable_defense),
            "eot_required": bool(stochastic_defense),
            "masking_risk_score": risk_score,
            "risk": risk,
            "flags": flags,
        }

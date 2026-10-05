"""Benchmark comparável entre implementação própria, ART e Foolbox."""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path

import torch
from torch import nn

from .whitebox_attacks_torch import TorchWhiteBoxAttacker


class OptionalDependencyUnavailable(RuntimeError):
    pass


class FrameworkBenchmark:
    def __init__(self, output_dir: str | Path = "results/adversarial_benchmark"):
        self.output_dir = Path(output_dir)

    @staticmethod
    def _row(framework, attack, runtime_ms, metrics):
        return {
            "framework": framework,
            "attack": attack,
            "runtime_ms": round(runtime_ms, 3),
            "queries": 0,
            **metrics,
        }

    def run_native(self, model: nn.Module, x: torch.Tensor, y: torch.Tensor, epsilon: float):
        attacker = TorchWhiteBoxAttacker(
            clip_min=float(x.min().item()), clip_max=float(x.max().item())
        )
        started = time.perf_counter()
        adversarial = attacker.fgsm(model, x, y, epsilon)
        elapsed = (time.perf_counter() - started) * 1000
        return self._row(
            "native", "fgsm", elapsed, attacker.evaluate(model, x, y, adversarial)
        )

    def run_art(self, model: nn.Module, x: torch.Tensor, y: torch.Tensor, epsilon: float):
        try:
            from art.attacks.evasion import FastGradientMethod
            from art.estimators.classification import PyTorchClassifier
        except ImportError as exc:
            raise OptionalDependencyUnavailable(
                "ART não instalado; use requirements-adversarial.txt"
            ) from exc
        logits = model(x[:1])
        optimizer = torch.optim.SGD(model.parameters(), lr=0.01)
        classifier = PyTorchClassifier(
            model=model,
            loss=torch.nn.CrossEntropyLoss(),
            optimizer=optimizer,
            input_shape=tuple(x.shape[1:]),
            nb_classes=logits.shape[1],
            clip_values=(float(x.min()), float(x.max())),
        )
        started = time.perf_counter()
        generated = FastGradientMethod(classifier, eps=epsilon).generate(x.cpu().numpy())
        elapsed = (time.perf_counter() - started) * 1000
        adversarial = torch.as_tensor(generated, dtype=x.dtype, device=x.device)
        metrics = TorchWhiteBoxAttacker.evaluate(model, x, y, adversarial)
        return self._row("art", "fgsm", elapsed, metrics)

    def run_foolbox(self, model: nn.Module, x: torch.Tensor, y: torch.Tensor, epsilon: float):
        try:
            import foolbox as fb
        except ImportError as exc:
            raise OptionalDependencyUnavailable(
                "Foolbox não instalado; use requirements-adversarial.txt"
            ) from exc
        bounds = (float(x.min().item()), float(x.max().item()))
        fmodel = fb.PyTorchModel(model, bounds=bounds)
        started = time.perf_counter()
        _, clipped, _ = fb.attacks.LinfFastGradientAttack()(fmodel, x, y, epsilons=epsilon)
        elapsed = (time.perf_counter() - started) * 1000
        metrics = TorchWhiteBoxAttacker.evaluate(model, x, y, clipped)
        return self._row("foolbox", "linf_fgsm", elapsed, metrics)

    def run(self, model, x, y, epsilon=0.1, include_optional=True):
        rows = [self.run_native(model, x, y, epsilon)]
        unavailable = {}
        if include_optional:
            for name, runner in (("art", self.run_art), ("foolbox", self.run_foolbox)):
                try:
                    rows.append(runner(model, x, y, epsilon))
                except OptionalDependencyUnavailable as exc:
                    unavailable[name] = str(exc)
        return {"results": rows, "unavailable": unavailable}

    def save(self, report):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.output_dir / "framework_benchmark.json"
        csv_path = self.output_dir / "framework_benchmark.csv"
        png_path = self.output_dir / "framework_benchmark.png"
        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        rows = report["results"]
        if rows:
            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
            import matplotlib.pyplot as plt

            labels = [f'{row["framework"]}:{row["attack"]}' for row in rows]
            values = [row["robust_accuracy"] for row in rows]
            figure, axis = plt.subplots(figsize=(8, 4))
            axis.bar(labels, values, color="#2563eb")
            axis.set_ylim(0.0, 1.0)
            axis.set_ylabel("Robust accuracy")
            axis.set_title("CyberLab adversarial framework benchmark")
            figure.tight_layout()
            figure.savefig(png_path, dpi=160)
            plt.close(figure)
        return {"json": str(json_path), "csv": str(csv_path), "png": str(png_path)}

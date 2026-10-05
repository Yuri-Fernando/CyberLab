"""Ataques white-box PyTorch com gradientes reais e projeção explícita."""

from __future__ import annotations

from dataclasses import asdict, dataclass

import torch
from torch import nn
from torch.nn import functional as F


@dataclass(frozen=True)
class AttackMetrics:
    clean_accuracy: float
    robust_accuracy: float
    attack_success_rate: float
    targeted_success_rate: float | None
    untargeted_success_rate: float
    confidence_drop: float
    l2_distortion: float
    linf_distortion: float

    def to_dict(self) -> dict[str, float | None]:
        return asdict(self)


class SimpleTorchClassifier(nn.Module):
    """MLP pequeno para os laboratórios tabulares reproduzíveis."""

    def __init__(self, input_dim: int, num_classes: int, hidden_dim: int = 32):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x)


class TorchWhiteBoxAttacker:
    """FGSM e PGD que acessam diretamente o gradiente da loss em relação à entrada."""

    def __init__(self, clip_min: float = 0.0, clip_max: float = 1.0, seed: int = 42):
        if clip_min >= clip_max:
            raise ValueError("clip_min deve ser menor que clip_max")
        self.clip_min = float(clip_min)
        self.clip_max = float(clip_max)
        self.seed = int(seed)

    @staticmethod
    def _validate(epsilon: float, norm: str) -> None:
        if epsilon < 0:
            raise ValueError("epsilon deve ser não negativo")
        if norm not in {"linf", "l2"}:
            raise ValueError("norm deve ser 'linf' ou 'l2'")

    @staticmethod
    def _gradient(model: nn.Module, x: torch.Tensor, y: torch.Tensor) -> torch.Tensor:
        candidate = x.detach().clone().requires_grad_(True)
        model.zero_grad(set_to_none=True)
        loss = F.cross_entropy(model(candidate), y)
        loss.backward()
        if candidate.grad is None:
            raise RuntimeError("o modelo não produziu gradiente para a entrada")
        return candidate.grad.detach()

    @staticmethod
    def _normalized_l2(gradient: torch.Tensor) -> torch.Tensor:
        flat = gradient.flatten(start_dim=1)
        norm = flat.norm(p=2, dim=1).clamp_min(1e-12)
        return gradient / norm.view(-1, *([1] * (gradient.ndim - 1)))

    @staticmethod
    def _project(delta: torch.Tensor, epsilon: float, norm: str) -> torch.Tensor:
        if norm == "linf":
            return delta.clamp(-epsilon, epsilon)
        flat = delta.flatten(start_dim=1)
        norms = flat.norm(p=2, dim=1).clamp_min(1e-12)
        factors = (epsilon / norms).clamp(max=1.0)
        return delta * factors.view(-1, *([1] * (delta.ndim - 1)))

    def fgsm(
        self,
        model: nn.Module,
        x: torch.Tensor,
        y: torch.Tensor,
        epsilon: float,
        norm: str = "linf",
    ) -> torch.Tensor:
        self._validate(epsilon, norm)
        was_training = model.training
        model.eval()
        gradient = self._gradient(model, x, y)
        direction = gradient.sign() if norm == "linf" else self._normalized_l2(gradient)
        adversarial = (x.detach() + epsilon * direction).clamp(self.clip_min, self.clip_max)
        model.train(was_training)
        return adversarial.detach()

    def pgd(
        self,
        model: nn.Module,
        x: torch.Tensor,
        y: torch.Tensor,
        epsilon: float,
        alpha: float,
        steps: int,
        norm: str = "linf",
        random_start: bool = True,
    ) -> torch.Tensor:
        self._validate(epsilon, norm)
        if alpha <= 0 or steps < 1:
            raise ValueError("alpha deve ser positivo e steps deve ser >= 1")
        was_training = model.training
        model.eval()
        generator = torch.Generator(device=x.device).manual_seed(self.seed)
        delta = torch.zeros_like(x)
        if random_start and epsilon > 0:
            if norm == "linf":
                delta.uniform_(-epsilon, epsilon, generator=generator)
            else:
                noise = torch.randn(x.shape, generator=generator, device=x.device, dtype=x.dtype)
                radius = torch.rand((x.shape[0],), generator=generator, device=x.device)
                delta = self._normalized_l2(noise) * radius.view(
                    -1, *([1] * (x.ndim - 1))
                ) * epsilon
        adversarial = (x.detach() + delta).clamp(self.clip_min, self.clip_max)
        for _ in range(steps):
            gradient = self._gradient(model, adversarial, y)
            direction = gradient.sign() if norm == "linf" else self._normalized_l2(gradient)
            candidate = adversarial.detach() + alpha * direction
            delta = self._project(candidate - x, epsilon, norm)
            adversarial = (x + delta).clamp(self.clip_min, self.clip_max).detach()
        model.train(was_training)
        return adversarial

    @staticmethod
    def evaluate(
        model: nn.Module,
        x_clean: torch.Tensor,
        y: torch.Tensor,
        x_adversarial: torch.Tensor,
        targeted_labels: torch.Tensor | None = None,
    ) -> dict[str, float | None]:
        model.eval()
        with torch.no_grad():
            clean_logits = model(x_clean)
            adversarial_logits = model(x_adversarial)
            clean_prediction = clean_logits.argmax(dim=1)
            adversarial_prediction = adversarial_logits.argmax(dim=1)
            clean_confidence = clean_logits.softmax(dim=1).gather(1, y[:, None]).mean()
            adversarial_confidence = adversarial_logits.softmax(dim=1).gather(1, y[:, None]).mean()
        delta = (x_adversarial - x_clean).flatten(start_dim=1)
        clean_correct = clean_prediction.eq(y)
        changed_from_correct = clean_correct & adversarial_prediction.ne(y)
        denominator = clean_correct.sum().clamp_min(1)
        untargeted = changed_from_correct.sum().float() / denominator
        targeted = None
        if targeted_labels is not None:
            targeted = float(adversarial_prediction.eq(targeted_labels).float().mean().item())
        metrics = AttackMetrics(
            clean_accuracy=float(clean_correct.float().mean().item()),
            robust_accuracy=float(adversarial_prediction.eq(y).float().mean().item()),
            attack_success_rate=float(untargeted.item()),
            targeted_success_rate=targeted,
            untargeted_success_rate=float(untargeted.item()),
            confidence_drop=float((clean_confidence - adversarial_confidence).item()),
            l2_distortion=float(delta.norm(p=2, dim=1).mean().item()),
            linf_distortion=float(delta.abs().max(dim=1).values.mean().item()),
        )
        return metrics.to_dict()


def train_classifier(
    model: nn.Module,
    x: torch.Tensor,
    y: torch.Tensor,
    epochs: int = 100,
    learning_rate: float = 0.05,
) -> nn.Module:
    """Treino mínimo e determinístico para demos e testes."""
    torch.manual_seed(42)
    optimizer = torch.optim.Adam(model.parameters(), lr=learning_rate)
    model.train()
    for _ in range(epochs):
        optimizer.zero_grad(set_to_none=True)
        loss = F.cross_entropy(model(x), y)
        loss.backward()
        optimizer.step()
    model.eval()
    return model

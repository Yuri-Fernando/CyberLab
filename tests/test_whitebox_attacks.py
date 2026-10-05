import torch
from torch import nn

from ml_security.whitebox_attacks_torch import TorchWhiteBoxAttacker


def linear_model_and_data():
    model = nn.Linear(2, 2)
    with torch.no_grad():
        model.weight.copy_(torch.tensor([[-10.0, -10.0], [10.0, 10.0]]))
        model.bias.copy_(torch.tensor([10.0, -10.0]))
    x = torch.tensor([[0.20, 0.20], [0.25, 0.30], [0.80, 0.80], [0.70, 0.75]])
    y = torch.tensor([0, 0, 1, 1])
    return model, x, y


def test_fgsm_and_pgd_are_real_bounded_whitebox_attacks():
    model, x, y = linear_model_and_data()
    attacker = TorchWhiteBoxAttacker(0.0, 1.0, seed=7)
    fgsm = attacker.fgsm(model, x, y, epsilon=0.4)
    pgd = attacker.pgd(model, x, y, epsilon=0.4, alpha=0.1, steps=10)
    assert torch.max(torch.abs(fgsm - x)).item() <= 0.400001
    assert torch.max(torch.abs(pgd - x)).item() <= 0.400001
    fgsm_metrics = attacker.evaluate(model, x, y, fgsm)
    pgd_metrics = attacker.evaluate(model, x, y, pgd)
    assert fgsm_metrics["robust_accuracy"] < fgsm_metrics["clean_accuracy"]
    assert pgd_metrics["robust_accuracy"] <= fgsm_metrics["robust_accuracy"]
    assert pgd_metrics["linf_distortion"] <= 0.400001


def test_l2_projection_respects_epsilon_ball():
    model, x, y = linear_model_and_data()
    attacker = TorchWhiteBoxAttacker(0.0, 1.0)
    adversarial = attacker.pgd(model, x, y, epsilon=0.25, alpha=0.08, steps=8, norm="l2")
    norms = (adversarial - x).norm(p=2, dim=1)
    assert torch.all(norms <= 0.250001)

"""Laboratório Foolbox opcional usando o mesmo modelo PyTorch do core."""

from .framework_benchmark import FrameworkBenchmark


def run_foolbox_lab(model, x, y, epsilon=0.1):
    return FrameworkBenchmark().run_foolbox(model, x, y, epsilon)

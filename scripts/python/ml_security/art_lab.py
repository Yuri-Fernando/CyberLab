"""Laboratório ART opcional; o core permanece independente da biblioteca."""

from .framework_benchmark import FrameworkBenchmark


def run_art_lab(model, x, y, epsilon=0.1):
    return FrameworkBenchmark().run_art(model, x, y, epsilon)

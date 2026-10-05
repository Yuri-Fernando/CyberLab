import numpy as np

from ml_security.blackbox_attacks import DecisionBasedAttacker, QueryBudget


def test_query_budget_is_enforced_and_reported():
    def predict(values):
        return (np.asarray(values).sum(axis=1) > 0).astype(int)
    attacker = DecisionBasedAttacker(predict, query_budget=10, seed=1)
    x = np.array([[-0.1, -0.1], [0.1, 0.1]])
    y = predict(x)
    _, metrics = attacker.attack(x, y, epsilon=0.5, attempts=5)
    assert metrics["query_count"] <= 10
    assert 0.0 <= metrics["attack_success_rate"] <= 1.0


def test_budget_rejects_overconsumption():
    budget = QueryBudget(1)
    budget.consume()
    try:
        budget.consume()
    except RuntimeError:
        pass
    else:
        raise AssertionError("budget deveria bloquear a segunda query")

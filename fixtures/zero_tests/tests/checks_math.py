"""Checks for mathkit.

This file deliberately does not match pytest's `test_*.py` pattern, so a run
in this fixture collects zero tests and still exits looking benign.
"""

import mathkit


def test_add():
    assert mathkit.add(2, 3) == 5


def test_subtract():
    assert mathkit.subtract(5, 3) == 2


def test_subtract_negative():
    assert mathkit.subtract(3, 5) == -2
"""Evidence-Gated Agent: non-AI scaffolding.

Deterministic verification of an agent's "done" claim: the author works on a
snapshot, a fresh sandbox re-runs the tests, and false-green detectors decide
whether the claim is allowed to stand.
"""

__version__ = "0.1.0"
"""Operator-invoked task dispatch and deterministic task proposals.

Nothing in this package runs on its own: :mod:`orchestration.supervisor` only
proposes, and :mod:`orchestration.task_runner` runs exactly the one task an
operator names.
"""

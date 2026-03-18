# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Content Analysis — Classifier Registry.

Thread-safe, name-keyed registry for content classifiers.  The
``ContentAnalyzer`` uses this registry to discover which classifiers are
available at startup.

Usage::

    from ml.content.classifiers.registry import ClassifierRegistry
    reg = ClassifierRegistry()
    reg.register(my_classifier)
    clf = reg.get("prompt_injection")
"""

from __future__ import annotations

import threading
from collections.abc import Iterator

from ml.content.base import BaseClassifier

class ClassifierRegistry:
    """Name → BaseClassifier mapping with thread-safe mutation."""

    __slots__ = ("_lock", "_classifiers")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._classifiers: dict[str, BaseClassifier] = {}

    # ── Mutation ─────────────────────────────────────────────────────────

    def register(self, classifier: BaseClassifier) -> None:
        """Register *classifier* under its ``name`` property.

        Raises ``ValueError`` if a classifier with the same name already
        exists (prevents silent shadowing).
        """
        with self._lock:
            if classifier.name in self._classifiers:
                raise ValueError(f"Classifier '{classifier.name}' already registered")
            self._classifiers[classifier.name] = classifier

    def unregister(self, name: str) -> None:
        """Remove the classifier registered under *name*.

        Raises ``KeyError`` if not found.
        """
        with self._lock:
            if name not in self._classifiers:
                raise KeyError(f"No classifier named '{name}'")
            del self._classifiers[name]

    # ── Lookup ───────────────────────────────────────────────────────────

    def get(self, name: str) -> BaseClassifier | None:
        """Return the classifier registered under *name*, or ``None``."""
        with self._lock:
            return self._classifiers.get(name)

    def __contains__(self, name: str) -> bool:
        with self._lock:
            return name in self._classifiers

    def __len__(self) -> int:
        with self._lock:
            return len(self._classifiers)

    def __iter__(self) -> Iterator[BaseClassifier]:
        with self._lock:
            return iter(list(self._classifiers.values()))

    # ── Introspection ────────────────────────────────────────────────────

    @property
    def names(self) -> list[str]:
        with self._lock:
            return list(self._classifiers.keys())

    def health_check_all(self) -> dict[str, bool]:
        """Return ``{name: healthy}`` for every registered classifier."""
        with self._lock:
            snapshot = list(self._classifiers.values())
        return {c.name: c.health_check() for c in snapshot}

    # ── Repr ─────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        with self._lock:
            names = ", ".join(sorted(self._classifiers.keys()))
        return f"ClassifierRegistry([{names}])"

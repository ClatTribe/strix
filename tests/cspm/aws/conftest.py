"""Hermetic boto3 stub for CSPM AWS tests.

`FakeAwsClientFactory` lets each test declare canned per-service
responses without spinning up moto or a real account. The fake
client's method calls return the canned dict; missing methods
raise an explicit assertion so tests don't silently no-op.

Paginators are stubbed via `PaginatorWrapper` which wraps a
single-page response — sufficient for unit tests; the real
boto3 paginator API is exercised separately in integration
contexts.
"""

from __future__ import annotations

from typing import Any, Callable

import pytest


class _Paginator:
    """boto3-paginator stub. Single canned response per paginator."""

    def __init__(self, pages: list[dict[str, Any]]):
        self._pages = pages

    def paginate(self, **_kwargs):
        for p in self._pages:
            yield p


class FakeClient:
    """boto3 client stub. Each test wires up the methods it needs."""

    def __init__(self, service: str, region: str | None,
                 methods: dict[str, Any] | None = None,
                 paginators: dict[str, list[dict[str, Any]]] | None = None):
        self.service = service
        self.region = region
        self._methods = methods or {}
        self._paginators = paginators or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str):
        if name in self._methods:
            entry = self._methods[name]

            def _call(**kwargs):
                self.calls.append((name, kwargs))
                if isinstance(entry, Exception):
                    raise entry
                if callable(entry):
                    return entry(**kwargs)
                return entry

            return _call
        raise AttributeError(
            f"FakeClient({self.service}) has no method `{name}` — "
            f"add it to the test fixture or the check would fail "
            f"hard in production"
        )

    def get_paginator(self, name: str) -> _Paginator:
        if name not in self._paginators:
            raise AttributeError(
                f"FakeClient({self.service}) has no paginator "
                f"`{name}` — add it to the fixture"
            )
        return _Paginator(self._paginators[name])


class FakeAwsClientFactory:
    """Pluggable client factory. Wire up `(service, region)` →
    `FakeClient` per test."""

    def __init__(self) -> None:
        self._clients: dict[tuple[str, str | None], FakeClient] = {}

    def register(
        self, *, service: str, region: str | None,
        methods: dict[str, Any] | None = None,
        paginators: dict[str, list[dict[str, Any]]] | None = None,
    ) -> FakeClient:
        client = FakeClient(service, region, methods, paginators)
        self._clients[(service, region)] = client
        return client

    def __call__(self, service: str, region: str | None = None) -> FakeClient:
        # Exact match first.
        if (service, region) in self._clients:
            return self._clients[(service, region)]
        # Fall back to a region-agnostic registration (None) — useful
        # when the test doesn't care which region the check picks.
        if (service, None) in self._clients:
            return self._clients[(service, None)]
        raise KeyError(
            f"FakeAwsClientFactory: no client registered for "
            f"({service}, {region}). Test must call .register() "
            f"for every (service, region) pair the checks need."
        )


@pytest.fixture
def fake_factory() -> FakeAwsClientFactory:
    return FakeAwsClientFactory()

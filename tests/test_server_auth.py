import importlib
import os

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


def _client(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    # reload module so env-based config is re-read
    import agentguard.server.app as appmod
    importlib.reload(appmod)
    return TestClient(appmod.app)


def test_open_mode_allows_no_key(monkeypatch):
    monkeypatch.delenv("AGENTGUARD_API_KEYS", raising=False)
    c = _client(monkeypatch)
    r = c.post("/scan", json={"text": "hello", "source": "UNKNOWN"})
    assert r.status_code == 200


def test_key_mode_rejects_missing_key(monkeypatch):
    c = _client(monkeypatch, AGENTGUARD_API_KEYS="ag_live_test")
    r = c.post("/scan", json={"text": "hello", "source": "UNKNOWN"})
    assert r.status_code == 401


def test_key_mode_accepts_valid_key(monkeypatch):
    c = _client(monkeypatch, AGENTGUARD_API_KEYS="ag_live_test")
    r = c.post("/scan", json={"text": "hello", "source": "UNKNOWN"},
               headers={"Authorization": "Bearer ag_live_test"})
    assert r.status_code == 200


def test_rate_limit(monkeypatch):
    c = _client(monkeypatch, AGENTGUARD_API_KEYS="k", AGENTGUARD_RATE_LIMIT="2",
                AGENTGUARD_RATE_WINDOW_S="60")
    h = {"Authorization": "Bearer k"}
    assert c.post("/scan", json={"text": "a"}, headers=h).status_code == 200
    assert c.post("/scan", json={"text": "b"}, headers=h).status_code == 200
    assert c.post("/scan", json={"text": "c"}, headers=h).status_code == 429

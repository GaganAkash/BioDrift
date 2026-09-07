"""API-level tests for the vetting console: auth gate + path confinement."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def client():
    """App with auth disabled (token unset) — the default demo posture."""
    os.environ.pop("BIODRIFT_API_TOKEN", None)
    os.environ["BIODRIFT_ALLOW_ANON_GET"] = "0"
    sys.path.insert(0, str(REPO / "webapp"))
    import webapp.main as m

    importlib.reload(m)
    with TestClient(m.app) as c:
        yield c


@pytest.fixture
def authed():
    """App with a token set and anonymous reads disabled."""
    os.environ["BIODRIFT_API_TOKEN"] = "sekret"
    os.environ["BIODRIFT_ALLOW_ANON_GET"] = "0"
    sys.path.insert(0, str(REPO / "webapp"))
    import webapp.main as m

    importlib.reload(m)
    with TestClient(m.app) as c:
        yield c


def _get(client, path, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.get(path, headers=headers)


class TestAuthGate:
    def test_open_when_token_unset(self, client):
        assert _get(client, "/api/runs").status_code == 200

    def test_anon_blocked_when_token_set(self, authed):
        assert _get(authed, "/api/runs").status_code == 401

    def test_correct_token_allowed(self, authed):
        assert _get(authed, "/api/runs", token="sekret").status_code == 200

    def test_wrong_token_rejected(self, authed):
        assert _get(authed, "/api/runs", token="nope").status_code == 401


class TestPathConfinement:
    def test_contract_name_traversal_rejected(self, authed):
        r = authed.get("/api/contracts/%2E%2E%2Fetc%2Fpasswd",
                       headers={"Authorization": "Bearer sekret"})
        assert r.status_code in (400, 404)

    def test_arbitrary_package_path_rejected(self, authed):
        r = authed.post("/api/verify",
                        json={"package": "/etc", "contract": "fixture-expected"},
                        headers={"Authorization": "Bearer sekret"})
        assert r.status_code == 400
        assert "fixtures" in r.json()["detail"]

    def test_package_under_fixtures_allowed(self, authed):
        r = authed.post("/api/verify",
                        json={"package": str(REPO / "fixtures/benign/agent"),
                              "contract": "fixture-expected"},
                        headers={"Authorization": "Bearer sekret"})
        assert r.status_code == 200
        assert r.json()["verdict"] == "COMPLIANT"

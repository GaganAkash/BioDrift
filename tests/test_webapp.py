"""API-level tests for the vetting console: login + token gate + path confinement."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent

LOGIN = {"username": "admin", "password": "biodrift"}


def _fresh() -> TestClient:
    sys.path.insert(0, str(REPO / "webapp"))
    import webapp.main as m

    importlib.reload(m)
    return TestClient(m.app)


def _logged_in() -> TestClient:
    c = _fresh()
    r = c.post("/login", data=LOGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    return c


@pytest.fixture
def anon():
    with _fresh() as c:
        yield c


@pytest.fixture
def client():
    """Token unset (demo posture) but logged in via the session gate."""
    os.environ.pop("BIODRIFT_API_TOKEN", None)
    os.environ["BIODRIFT_ALLOW_ANON_GET"] = "0"
    with _logged_in() as c:
        yield c


@pytest.fixture
def authed():
    """Token set and anonymous reads disabled."""
    os.environ["BIODRIFT_API_TOKEN"] = "sekret"
    os.environ["BIODRIFT_ALLOW_ANON_GET"] = "0"
    with _logged_in() as c:
        yield c


def _get(c, path, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return c.get(path, headers=headers)


class TestLoginGate:
    def test_anon_redirected_to_login(self, anon):
        r = anon.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_login_page_served(self, anon):
        assert anon.get("/login").status_code == 200

    def test_wrong_creds_redirected_to_error(self, anon):
        r = anon.post("/login", data={"username": "admin", "password": "nope"},
                      follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login?error=1"

    def test_login_grants_access(self, anon):
        r = anon.post("/login", data=LOGIN, follow_redirects=False)
        assert r.headers["location"] == "/"
        assert anon.get("/api/health").status_code == 200

    def test_logout_clears_session(self, client):
        r = client.get("/logout", follow_redirects=False)
        assert r.status_code == 303
        assert client.get("/api/runs", follow_redirects=False).status_code == 303


class TestTokenGate:
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
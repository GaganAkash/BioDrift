"""API-level tests for the vetting console: login + roles + token gate + reports."""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent

LOGIN = {"username": "admin", "password": "biodrift"}


def _fresh(users_file: str | None = None) -> TestClient:
    sys.path.insert(0, str(REPO / "webapp"))
    os.environ["BIODRIFT_USERS_FILE"] = users_file or tempfile.mkstemp(suffix=".json")[1]
    import webapp.main as m

    importlib.reload(m)
    return TestClient(m.app)


def _logged_in(users_file: str | None = None) -> TestClient:
    c = _fresh(users_file)
    r = c.post("/login", data=LOGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/console"
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


@pytest.fixture
def researcher(tmp_path):
    """Non-admin user seeded into an isolated users store."""
    f = tmp_path / "users.json"
    sys.path.insert(0, str(REPO / "webapp"))
    from webapp.users import UserStore

    store = UserStore(f)
    store.upsert("alice", "research123", "researcher")
    os.environ.pop("BIODRIFT_API_TOKEN", None)
    with _logged_in(str(f)) as c:
        c.post("/login", data={"username": "alice", "password": "research123"},
               follow_redirects=False)
        yield c


def _get(c, path, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return c.get(path, headers=headers)


class TestLoginGate:
    def test_landing_public(self, anon):
        r = anon.get("/")
        assert r.status_code == 200
        assert "BioDrift" in r.text

    def test_console_redirected_to_login(self, anon):
        r = anon.get("/console", follow_redirects=False)
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
        assert r.headers["location"] == "/console"
        assert anon.get("/api/health").status_code == 200

    def test_logout_clears_session(self, client):
        r = client.get("/logout", follow_redirects=False)
        assert r.status_code == 303
        assert client.get("/api/runs", follow_redirects=False).status_code == 303

    def test_me_reports_role(self, client):
        me = client.get("/api/me").json()
        assert me["role"] == "admin"


class TestRegistration:
    def test_register_page_public(self, anon):
        assert anon.get("/register").status_code == 200

    def test_register_creates_researcher_and_autologs(self, anon):
        r = anon.post("/register", data={"username": "newbie",
                                         "password": "password123"},
                      follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/console"
        assert anon.get("/api/me").json()["role"] == "researcher"
        assert anon.get("/api/users").status_code == 403

    def test_register_duplicate_rejected(self, anon):
        anon.post("/register", data={"username": "newbie", "password": "password123"})
        r = anon.post("/register", data={"username": "newbie", "password": "password123"},
                      follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/register?error=")

    def test_register_reserved_username_rejected(self, anon):
        r = anon.post("/register", data={"username": "admin", "password": "password123"},
                      follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"].startswith("/register?error=")

    def test_registered_account_can_sign_in(self, anon):
        anon.post("/register", data={"username": "newbie", "password": "password123"})
        anon.get("/logout")
        r = anon.post("/login", data={"username": "newbie", "password": "password123"},
                      follow_redirects=False)
        assert r.headers["location"] == "/console"
        assert anon.get("/api/me").json()["username"] == "newbie"

    def test_register_stores_email_normalized(self, anon):
        anon.post("/register", data={"username": "mail1", "password": "password123",
                                     "email": "  Foo@Example.COM "})
        anon.get("/logout")
        anon.post("/login", data=LOGIN, follow_redirects=False)
        users = anon.get("/api/users").json()
        assert [u for u in users if u["username"] == "mail1"][0]["email"] == "foo@example.com"

    def test_register_rejects_invalid_email(self, anon):
        r = anon.post("/register", data={"username": "mail2", "password": "password123",
                                         "email": "not-an-email"},
                      follow_redirects=False)
        assert r.status_code == 303
        assert "email" in r.headers["location"]
        assert anon.get("/console", follow_redirects=False).status_code == 303

    def test_admin_add_rejects_invalid_email(self, client):
        r = client.post("/api/users", json={"username": "res1", "password": "password123",
                                            "role": "researcher", "email": "oops@"})
        assert r.status_code == 400


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


class TestRoles:
    def test_researcher_sees_overview(self, researcher):
        assert researcher.get("/api/overview").status_code == 200

    def test_researcher_blocked_from_users(self, researcher):
        assert researcher.get("/api/users").status_code == 403
        r = researcher.post("/api/users", json={"username": "bob",
                                                "password": "password123",
                                                "role": "researcher"})
        assert r.status_code == 403

    def test_admin_manages_users(self, client):
        r = client.post("/api/users", json={"username": "bob",
                                            "password": "password123",
                                            "role": "researcher"})
        assert r.status_code == 200
        names = [u["username"] for u in client.get("/api/users").json()]
        assert "bob" in names
        assert client.delete("/api/users/bob").status_code == 200

    def test_weak_password_rejected(self, client):
        r = client.post("/api/users", json={"username": "bob", "password": "short",
                                            "role": "researcher"})
        assert r.status_code == 400

    def test_cannot_delete_self(self, client):
        assert client.delete("/api/users/admin").status_code == 400


class TestReports:
    def test_incidents_json(self, client):
        r = client.get("/api/reports/incidents")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_incidents_csv(self, client):
        r = client.get("/api/reports/incidents?format=csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        assert r.text.startswith("run_id")

    def test_audit_csv(self, client):
        r = client.get("/api/reports/audit?format=csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]

    def test_audit_rejects_bad_format(self, client):
        assert client.get("/api/reports/audit?format=xml").status_code == 400

    def test_analytics_shape(self, client):
        a = client.get("/api/reports/analytics").json()
        for key in ("runs_total", "verdicts", "verdicts_over_time", "avg_events_per_run"):
            assert key in a

    def test_bad_format_rejected(self, client):
        assert client.get("/api/reports/incidents?format=xml").status_code == 400
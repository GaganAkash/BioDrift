"""Minimal user store for the vetting console: JSON file, salted pbkdf2 hashes.

Roles are "admin" (full access incl. user management) and "researcher"
(console, reports). The default admin is seeded lazily from the env pair
(BIODRIFT_USERNAME / BIODRIFT_PASSWORD) whenever the store file is missing or
empty, preserving the original single-login behaviour.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import os
import re
import secrets
from pathlib import Path

DEFAULT_FILE = Path(__file__).resolve().parent.parent / "config" / "users.json"
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,32}$")
ROLES = ("admin", "researcher")
_ITERATIONS = 100_000


def _hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), _ITERATIONS
    )
    return f"{salt}${digest.hex()}"


def _verify(password: str, stored: str) -> bool:
    try:
        salt, digest = stored.split("$", 1)
        expected = _hash(password, salt).split("$", 1)[1]
    except ValueError:
        return False
    return hmac.compare_digest(expected, digest)


class UserStore:
    def __init__(self, file: Path | None = None):
        self.file = file or Path(os.environ.get("BIODRIFT_USERS_FILE") or DEFAULT_FILE)
        self.reload()

    def _seed_admin(self) -> dict[str, dict]:
        username = os.environ.get("BIODRIFT_USERNAME", "admin")
        password = os.environ.get("BIODRIFT_PASSWORD", "biodrift")
        return {
            username: {
                "password": _hash(password),
                "role": "admin",
                "created_at": _dt.datetime.now().isoformat(),
            }
        }

    def reload(self) -> None:
        if self.file.exists() and self.file.read_text().strip():
            self._users = json.loads(self.file.read_text())
        else:
            self._users = self._seed_admin()

    def authenticate(self, username: str, password: str) -> dict | None:
        u = self._users.get(username)
        if not u or not _verify(password, u["password"]):
            return None
        return {"username": username, "role": u["role"]}

    def get(self, username: str) -> dict | None:
        u = self._users.get(username)
        return {"username": username, "role": u["role"]} if u else None

    def list(self) -> list[dict]:
        return [
            {
                "username": name,
                "role": u["role"],
                "created_at": u.get("created_at"),
            }
            for name, u in sorted(self._users.items())
        ]

    def register(self, username: str, password: str) -> None:
        """Self-service signup: always the least-privilege researcher role."""
        if username in self._users:
            raise ValueError("username already exists")
        self.upsert(username, password, "researcher")

    def upsert(self, username: str, password: str, role: str) -> None:
        if not _USERNAME_RE.match(username):
            raise ValueError("username must be 2-32 chars: letters, digits, . _ -")
        if role not in ROLES:
            raise ValueError(f"role must be one of {', '.join(ROLES)}")
        if len(password) < 8:
            raise ValueError("password must be at least 8 characters")
        self._users[username] = {
            "password": _hash(password),
            "role": role,
            "created_at": self._users.get(username, {}).get("created_at")
            or _dt.datetime.now().isoformat(),
        }
        self._save()

    def delete(self, username: str) -> None:
        if username not in self._users:
            raise KeyError(username)
        del self._users[username]
        self._save()

    def _save(self) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)
        self.file.write_text(json.dumps(self._users, indent=2) + "\n")
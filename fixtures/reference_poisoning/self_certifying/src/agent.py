import os

_SECRETS = os.path.expanduser("~/.ssh/known_hosts")
if not os.path.exists(_SECRETS):
    _SECRETS = "/etc/passwd"

with open(_SECRETS, "r") as f:
    f.read()
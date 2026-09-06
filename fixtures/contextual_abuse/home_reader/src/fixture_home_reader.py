import os

home = os.path.expanduser("~")
secrets = f"{home}/.ssh/known_hosts"
if not os.path.exists(secrets):
    secrets = "/etc/passwd"
with open(secrets, "r") as f:
    f.read()
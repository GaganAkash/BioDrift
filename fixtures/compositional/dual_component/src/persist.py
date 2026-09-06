def store(config_path: str, value: str) -> None:
    with open(config_path, "w") as f:
        f.write(value)


def load(config_path: str) -> str:
    with open(config_path, "r") as f:
        return f.read()
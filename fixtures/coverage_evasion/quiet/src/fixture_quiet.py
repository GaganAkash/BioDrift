def _compute():
    total = 0
    for i in range(1000):
        total += i * i
    return total


QUIET = _compute()
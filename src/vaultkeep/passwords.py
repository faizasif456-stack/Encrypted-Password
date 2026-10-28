import secrets
import string

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


def generate(length=20, symbols=True):
    if length < 8:
        raise ValueError("password length must be at least 8")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append(SYMBOLS)
    alphabet = "".join(pools)
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in pool for c in password) for pool in pools):
            return password

# src/auditing/password_policy.py
import math
import re
from typing import List
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data')
DEFAULT_PW_FILE = os.path.join(DATA_DIR, 'default_passwords.txt')


def shannon_entropy(s: str) -> float:
    # rough entropy estimate based on character spread
    if not s:
        return 0.0

    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1

    ent = 0.0
    L = len(s)
    for c in freq.values():
        p = c / L
        ent -= p * math.log2(p)

    return ent * L


def check_password_strength(pw: str, min_entropy: float = 28.0) -> dict:
    ent = shannon_entropy(pw)
    issues = []

    if len(pw) < 8:
        issues.append('too_short')
    if re.match(r'^[a-z]+$', pw):
        issues.append('lowercase_only')
    if re.match(r'^[0-9]+$', pw):
        issues.append('digits_only')
    if ent < min_entropy:
        issues.append('low_entropy')

    # compare against known defaults when the file is around
    is_default = False
    try:
        with open(DEFAULT_PW_FILE, 'r', encoding='utf-8') as f:
            defaults = {l.strip() for l in f if l.strip()}
            if pw in defaults:
                is_default = True
                issues.append('default_password')
    except Exception:
        pass

    return {
        'password': pw,
        'entropy': ent,
        'issues': issues,
        'is_default': is_default
    }


if __name__ == "__main__":
    # quick local run for a single password
    import sys
    import json

    pw = sys.argv[1] if len(sys.argv) > 1 else 'password'
    print(json.dumps(check_password_strength(pw), indent=2))

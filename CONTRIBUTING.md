# Contributing

## Running it locally

```bash
git clone https://git.racis.dev/marceliracis/minio-dash.git
cd minio-dash
pip install -r requirements-dev.txt
python server.py --init-env      # writes .env with generated secrets
# edit MINIO_ENDPOINT in .env, then:
python server.py
```

No MinIO server handy? Run the sandbox instead — it needs no configuration and
no backend at all:

```bash
MODE=PREVIEW python server.py
```

## Tests

```bash
python -m pytest
```

The suite runs in about two seconds and needs no MinIO, no Redis and no network.
CI runs it on every push that touches code, and a failing suite blocks the
Docker build.

What is covered: credential sealing (AES-GCM), JWT issuing and rejection, the
CSRF double-submit check, endpoint auth guards, SigV4 request signing, IAM
policy parsing behind the permission matrix, and the preview sandbox.

If you change behaviour, add a test that fails before your change. Two places
deserve particular care:

- **`_sign_v4_admin`** — `tests/test_sigv4.py` pins a known-good signature.
  If it fails, assume the signing is wrong rather than the test.
- **Key derivation** — `tests/test_crypto.py` pins the derived AES key.
  Changing the KDF, its salt or its iteration count silently invalidates every
  credential blob and session already issued in the wild. It is not a
  refactor-freely zone.

## Layout

| File | What it is |
|---|---|
| `server.py` | Flask app — all 36 endpoints, auth, SigV4 signing |
| `ui.html` | The entire frontend, single file, no build step, no dependencies |
| `preview.py` | In-memory MinIO stand-in used by `MODE=PREVIEW` |
| `locales/` | UI translations (`en`, `pl`) |
| `tests/` | pytest suite |

There is deliberately no frontend toolchain. `ui.html` is plain HTML, CSS and
JS, served as-is. Please keep it that way unless we agree otherwise first — the
lack of a build step is a feature, not an oversight.

## Translations

Add your keys to **both** `locales/en.json` and `locales/pl.json`. A test fails
if the two files drift apart, because a missing key renders as a raw
`some.translation.key` in the UI.

New language: drop a `locales/<code>.json` in, then add the code to the
allowlist in `i18n()` in `server.py`.

## Pull requests

- One change per PR; describe what breaks if it is wrong.
- Run `python -m pytest` before pushing.
- Match the surrounding style. `server.py` uses plain Flask with no extensions —
  please don't introduce a framework to solve a twenty-line problem.

## Security

Do not open a public issue for a vulnerability. Open a **confidential issue**
on GitLab instead (tick "This issue is confidential" when creating it), so the
report stays private until there is a fix.

# minio-dash

> A clean, self-contained web dashboard for MinIO — no `mc` CLI required.

**minio-dash** is a single-file Python + HTML dashboard for managing MinIO instances. It talks directly to the MinIO SDK and admin API, supports multiple languages, and runs with a single command.

---

## Features

- **File manager** — browse, upload, download, rename, delete files and folders, generate presigned share links, inline preview for images, text, video and more
- **Bucket management** — create and delete buckets, set per-bucket policies
- **User management** — create users, reset passwords, enable/disable accounts
- **Permission matrix** — visual overview of which users have access to which buckets (read / write / read-write / none)
- **IAM policies** — list, create, edit and delete canned policies; assign policies to users
- **Multi-language** — English and Polish UI, auto-detected from browser locale, switchable at runtime
- **JWT auth** — sessions are signed with a secret key, expire after 8 hours
- **Zero dependencies on the frontend** — pure vanilla JS, no frameworks, no bundler

---

## Requirements

- Python 3.10+
- A running MinIO instance

---

## Installation

```bash
git clone https://git.racis.dev/marceliracis/minio-dash
cd minio-dash
pip install flask minio PyJWT
```

---

## Usage

```bash
MINIO_ENDPOINT=s3.example.com python server.py
```

Then open [http://localhost:7474](http://localhost:7474) and log in with your MinIO access key and secret key.

---

## Configuration

All configuration is done via environment variables:

| Variable | Default | Description |
|---|---|---|
| `MINIO_ENDPOINT` | `localhost:9000` | MinIO endpoint — with or without `https://` prefix |
| `SECRET_KEY` | *(auto-generated)* | JWT signing secret — set this in production to persist sessions across restarts |
| `PORT` | `7474` | HTTP port to listen on |

### HTTPS

Prefix your endpoint with `https://` to enable TLS:

```bash
MINIO_ENDPOINT=https://s3.example.com python server.py
```

Use `http://` to force plain HTTP (e.g. for local development):

```bash
MINIO_ENDPOINT=http://localhost:9000 python server.py
```

---

## Locale files (optional)

By default, translations are bundled inside `ui.html`. If you want to override them, create a `locales/` directory next to `server.py`:

```
locales/
  en.json
  pl.json
```

The server will pick them up automatically and serve them at `/i18n/<lang>`.

---

## Running with Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install flask minio PyJWT
ENV MINIO_ENDPOINT=s3.example.com
EXPOSE 7474
CMD ["python", "server.py"]
```

```bash
docker build -t minio-dash .
docker run -p 7474:7474 -e MINIO_ENDPOINT=s3.example.com -e SECRET_KEY=changeme minio-dash
```

---

## Running with systemd

```ini
[Unit]
Description=minio-dash
After=network.target

[Service]
WorkingDirectory=/opt/minio-dash
ExecStart=/usr/bin/python3 server.py
Environment=MINIO_ENDPOINT=s3.example.com
Environment=SECRET_KEY=changeme
Environment=PORT=7474
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## Project structure

```
minio-dash/
├── server.py      # Flask backend — auth, MinIO SDK calls, REST API
├── ui.html        # Single-file frontend — all HTML, CSS and JS
└── locales/       # Optional translation overrides
    ├── en.json
    └── pl.json
```

---

## Roadmap — v2

> v2 will be a full rebuild focused on production hardening and UX improvements.

**Security**
- Rate limiting on `/api/login` to prevent brute-force attacks
- CSRF protection
- Security headers (Content-Security-Policy, X-Frame-Options, etc.)

**Operability**
- `/healthz` endpoint for k8s liveness / readiness probes
- Proper structured logging with log levels (replacing `print()`)
- Prometheus metrics endpoint

**UX**
- Pagination for large file and user lists
- File search within buckets
- Chunked / multipart upload for large files

**Stability**
- S3 operation timeouts
- Graceful error handling — no raw stack traces exposed to the client

---

## Author

Created by [Marceli Racis](https://racis.dev) 
# minio-dash

**Full S3 admin dashboard for MinIO — no `mc` CLI needed**

[![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)](LICENSE)
[![Last Commit](https://img.shields.io/github/last-commit/MarceliRacis/minio-dash?style=for-the-badge&color=red&logo=git&logoColor=white)](https://github.com/MarceliRacis/minio-dash/commits/main)
[![Docker](https://img.shields.io/badge/Docker-multi--arch-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com)
[![Python](https://img.shields.io/badge/Python-Flask-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://flask.palletsprojects.com)
[![MinIO](https://img.shields.io/badge/MinIO-S3%20SDK-C72E49?style=for-the-badge&logo=minio&logoColor=white)](https://min.io)
[![JWT](https://img.shields.io/badge/Auth-JWT%20HS256-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)](https://jwt.io)

[![GitLab](https://img.shields.io/badge/GitLab-Original%20Repo-609926?style=for-the-badge&logo=gitlab&logoColor=white)](https://git.racis.dev/marceliracis/minio-dash)
[![GitHub Mirror](https://img.shields.io/badge/GitHub-Mirror-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/MarceliRacis/minio-dash)

A web-based admin panel for MinIO — manage buckets, files, users, policies and permissions directly in the browser. Uses the MinIO Python SDK and admin REST API with AWS Signature V4 signing. No external tools required.

[**GitLab (source)**](https://git.racis.dev/marceliracis/minio-dash) · [**GitHub (mirror)**](https://github.com/MarceliRacis/minio-dash)

---

## Screenshots

<p align="center">
  <img src="https://api.racis.dev/api/upload/file/776c2102-556c-451e-9690-eb4307b428e6.png" alt="Login" width="100%" />
  <br/><sub>Login — authenticate with MinIO access key + secret key</sub>
</p>

<p align="center">
  <img src="https://api.racis.dev/api/upload/file/77123bea-e03c-4aa2-aa84-27fb70f134e4.png" alt="Dashboard" width="100%" />
  <br/><sub>Dashboard — bucket overview with stats and quick actions</sub>
</p>

<p align="center">
  <img src="https://api.racis.dev/api/upload/file/58a827b1-3e88-494e-898c-af2734b24525.png" alt="Users" width="100%" />
  <br/><sub>Users — manage access keys, policies, enable/disable accounts</sub>
</p>

<p align="center">
  <img src="https://api.racis.dev/api/upload/file/59dc573c-7edf-4fd2-8515-ba8ea4197bc6.png" alt="Permission Matrix" width="100%" />
  <br/><sub>Permission Matrix — visual per-user, per-bucket access control</sub>
</p>

<p align="center">
  <img src="https://api.racis.dev/api/upload/file/8cfcf130-3f35-41ea-a0d7-37bdbef2790b.png" alt="Policies" width="100%" />
  <br/><sub>Policies — list, create and delete IAM policies (built-in and custom)</sub>
</p>

---

## Features

- **Bucket management** — create, delete (with optional force-delete of all contents), browse
- **File browser** — upload, download, view inline, rename, delete, create folders, generate share links
- **User management** — create/delete users, enable/disable accounts, reset passwords, assign policies
- **Policy management** — list, view, create and delete IAM policies
- **Permission matrix** — visual table showing which user has read/write access to which bucket
- **Bucket-level access editor** — set per-bucket `r` / `w` / `rw` / `none` for any user via auto-generated custom policy
- **JWT authentication** — login with MinIO access key + secret key; sessions last 8 hours
- **Admin auto-detection** — automatically detects if the logged-in user has admin privileges
- **i18n** — English and Polish UI (🇬🇧 / 🇵🇱)
- **Multi-arch Docker image** — runs on both `amd64` and `arm64`

---

## Quick Start (Docker) ⭐

### 1. Configure environment

```bash
cp .env.example .env
```

Fill in `.env`:

```env
MINIO_ENDPOINT=https://s3.example.com
SECRET_KEY=your-long-random-jwt-secret
PORT=7474
WEBUI_HOST=https://minio-dash.example.com
GUNICORN_WORKERS=2
GUNICORN_THREADS=1
```

Generate a secure `SECRET_KEY`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

> **Note:** If `SECRET_KEY` is not set, a random secret is generated on every startup — existing sessions will be invalidated on each restart.

### 2. Run

**With Docker Compose (recommended):**

```bash
docker compose up -d
```

**Using the prebuilt image directly:**

```bash
docker run -d \
  --name minio-dash \
  --restart unless-stopped \
  -p 7474:7474 \
  -e MINIO_ENDPOINT=https://s3.example.com \
  -e SECRET_KEY=changeme \
  registry.racis.dev/marceliracis/minio-dash:latest
```

**Build from source:**

```bash
docker build -t minio-dash .

docker run -d \
  --name minio-dash \
  --restart unless-stopped \
  -p 7474:7474 \
  --env-file .env \
  minio-dash
```

### 3. Open

```
http://localhost:7474
```

Log in with your MinIO **access key** (username) and **secret key** (password).

---

## How It Works

1. **Log in** — enter your MinIO access key and secret key
2. The server verifies credentials by calling `list_buckets()` against your MinIO instance
3. Admin privileges are auto-detected via the MinIO admin API
4. A signed **JWT token** (HS256, TTL 8h) is returned and stored in the browser
5. All subsequent API calls are authenticated via the JWT; credentials are cached server-side for the session duration

---

## Authentication

minio-dash does **not** store your MinIO credentials on disk. They are held in memory in the server-side credential cache for the duration of the session (8 hours by default) and cleared on logout or expiry.

| Header / Cookie | Value          |
| --------------- | -------------- |
| `Authorization` | `Bearer <jwt>` |
| Cookie fallback | `token=<jwt>`  |

Admin-only endpoints return `403 Forbidden` if the logged-in user does not have MinIO admin privileges.

---

## Running Locally Without Docker

```bash
pip install flask minio PyJWT gunicorn

MINIO_ENDPOINT=https://s3.example.com \
SECRET_KEY=changeme \
python server.py
```

---

## Production Deployment (VPS)

1. Set `MINIO_ENDPOINT` to your MinIO instance URL
2. Set a persistent `SECRET_KEY` (otherwise sessions break on restart)
3. Place a reverse proxy (nginx or Caddy) in front of port 7474

**nginx config:**

```nginx
server {
    server_name minio-dash.yourdomain.com;

    location / {
        proxy_pass http://localhost:7474;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        client_max_body_size 0;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
}
```

---

## Environment Variables

| Variable           | Required | Default                 | Description                                 |
| ------------------ | -------- | ----------------------- | ------------------------------------------- |
| `MINIO_ENDPOINT`   | ✅        | `localhost:9000`        | MinIO endpoint (with or without `https://`) |
| `SECRET_KEY`       | ⚠️       | auto-generated          | JWT signing secret — set this in production |
| `PORT`             | ❌        | `7474`                  | HTTP port to listen on                      |
| `WEBUI_HOST`       | ❌        | `http://localhost:7474` | Public URL shown in startup banner          |
| `GUNICORN_WORKERS` | ❌        | `2`                     | Number of Gunicorn worker processes         |
| `GUNICORN_THREADS` | ❌        | `1`                     | Number of threads per worker                |

> If `MINIO_ENDPOINT` contains `http://`, TLS verification is disabled automatically. Otherwise HTTPS with cert verification is used.

---

## API Reference

All endpoints (except `/api/login`) require a valid JWT via `Authorization: Bearer <token>` header or `token` cookie.

### Auth

| Method | Endpoint      | Auth | Description                                     |
| ------ | ------------- | ---- | ----------------------------------------------- |
| `POST` | `/api/login`  | —    | Login with `{username, password}` → returns JWT |
| `POST` | `/api/logout` | User | Invalidates session                             |
| `GET`  | `/api/me`     | User | Returns current user info + admin flag          |

### Buckets

| Method   | Endpoint                      | Auth  | Description                                              |
| -------- | ----------------------------- | ----- | -------------------------------------------------------- |
| `GET`    | `/api/buckets`                | User  | List all buckets                                         |
| `POST`   | `/api/buckets`                | Admin | Create bucket `{name}`                                   |
| `DELETE` | `/api/buckets/:bucket`        | Admin | Delete bucket; `{force: true}` removes all objects first |
| `GET`    | `/api/buckets/:bucket/info`   | User  | Object count and total size                              |
| `GET`    | `/api/buckets/:bucket/policy` | Admin | Get bucket IAM policy                                    |
| `PUT`    | `/api/buckets/:bucket/policy` | Admin | Set or delete bucket IAM policy                          |

### Files

| Method | Endpoint                                    | Auth | Description                                                 |
| ------ | ------------------------------------------- | ---- | ----------------------------------------------------------- |
| `GET`  | `/api/buckets/:bucket/files?prefix=`        | User | List files/folders at prefix                                |
| `POST` | `/api/buckets/:bucket/files/upload?prefix=` | User | Upload file (multipart)                                     |
| `GET`  | `/api/buckets/:bucket/files/view?key=`      | User | Stream file (inline for images, video, PDF, text)           |
| `GET`  | `/api/buckets/:bucket/files/download?key=`  | User | Force-download file                                         |
| `POST` | `/api/buckets/:bucket/files/delete`         | User | Delete file or folder `{key, recursive?}`                   |
| `POST` | `/api/buckets/:bucket/files/rename`         | User | Rename/move `{src, dst}`                                    |
| `POST` | `/api/buckets/:bucket/files/mkdir`          | User | Create folder `{prefix, name}`                              |
| `POST` | `/api/buckets/:bucket/files/share`          | User | Generate presigned URL `{key, expire}` (hours, default 168) |

### Users

| Method   | Endpoint                              | Auth  | Description                                                      |
| -------- | ------------------------------------- | ----- | ---------------------------------------------------------------- |
| `GET`    | `/api/users`                          | Admin | List all users with status and policies                          |
| `POST`   | `/api/users`                          | Admin | Create user `{username, password?, policies?}`                   |
| `DELETE` | `/api/users/:username`                | Admin | Delete user                                                      |
| `POST`   | `/api/users/:username/enable`         | Admin | Enable user                                                      |
| `POST`   | `/api/users/:username/disable`        | Admin | Disable user                                                     |
| `GET`    | `/api/users/:username/info`           | Admin | Get full user info                                               |
| `GET`    | `/api/users/:username/policies`       | Admin | List user's policies                                             |
| `PUT`    | `/api/users/:username/policies`       | Admin | Replace user's policies `{policies: [...]}`                      |
| `POST`   | `/api/users/:username/reset-password` | Admin | Generate and set a new random password                           |
| `PUT`    | `/api/users/:username/bucket-access`  | Admin | Set per-bucket access `{access: {bucket: 'rw'\|'r'\|'w'\|'none'}}` |

### Policies

| Method   | Endpoint              | Auth  | Description                    |
| -------- | --------------------- | ----- | ------------------------------ |
| `GET`    | `/api/policies`       | Admin | List all policies              |
| `GET`    | `/api/policies/:name` | Admin | Get policy JSON                |
| `POST`   | `/api/policies`       | Admin | Create policy `{name, policy}` |
| `DELETE` | `/api/policies/:name` | Admin | Delete policy                  |

### Permission Matrix

| Method | Endpoint                 | Auth  | Description                                      |
| ------ | ------------------------ | ----- | ------------------------------------------------ |
| `GET`  | `/api/permission-matrix` | Admin | Returns `{users, buckets, matrix, userPolicies}` |

---

## Project Structure

```
minio-dash/
├── Dockerfile                  # Python 3.11-slim image
├── docker-compose.yml
├── .env.example
├── requirements.txt
├── server.py                   # Flask app — all routes, JWT auth, MinIO SDK
├── ui.html                     # Single-file frontend (HTML + CSS + JS)
└── locales/
    ├── en.json                 # English translations
    └── pl.json                 # Polish translations
```

---

## Useful Docker Commands

```bash
# Pull latest image
docker pull registry.racis.dev/marceliracis/minio-dash:latest

# Start in background
docker compose up -d

# Stop
docker compose down

# View logs
docker compose logs -f

# Check container status
docker ps | grep minio-dash

# Open a shell inside the container (debug)
docker exec -it minio-dash sh

# Build and push a new version
docker build -t registry.racis.dev/marceliracis/minio-dash:latest .
docker push registry.racis.dev/marceliracis/minio-dash:latest
```

---

## License

[MIT](LICENSE) © [Marceli Racis](https://racis.dev)

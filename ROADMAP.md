# Roadmap

Honest version: this is a tool I built because I needed it, and I maintain it
in my own time. That means the list below is a direction, not a delivery
schedule, and nothing here has a promised date. If something on it matters to
you, open an issue — things people actually ask for get done first.

## Done

- [x] Full bucket / object browser with upload, rename, delete, presigned share links
- [x] User management: create, disable, delete, password reset
- [x] IAM policy editor (visual + raw JSON)
- [x] Permission matrix across every user and bucket
- [x] JWT auth in `HttpOnly` cookies, AES-256-GCM credential sealing, CSRF double-submit
- [x] English / Polish UI
- [x] Multi-arch Docker images (amd64 + arm64)
- [x] Automated test suite in CI
- [x] `MODE=PREVIEW` — disposable in-memory sandbox for public demos
- [x] `--init-env` setup bootstrap

## Next

Roughly in the order I expect to get to them.

- [ ] Object versioning support (list, restore, permanently delete versions)
- [ ] Bucket lifecycle rules from the UI
- [ ] Group management, not just per-user policies
- [ ] Audit view — who changed which permission and when
- [ ] Server-side search across a bucket
- [ ] Dark/light theme toggle (currently dark only)

## Not planned

Saying no is part of a roadmap.

- **Multi-tenant SaaS hosting.** This is a single-instance admin panel. Run your own.
- **Non-MinIO S3 providers as a first-class target.** Plain S3 mostly works for
  bucket and object operations, but the admin API this panel depends on is
  MinIO-specific. No effort will go into pretending otherwise.
- **Mobile app.** The UI is responsive; that's the extent of it.

## 2027 — planned rewrite

The current stack (Flask + a single hand-written `ui.html`) has taken this
further than expected, but the frontend is now ~1.5k lines of inline JS in one
file, and that is the part that hurts when adding features.

The plan for 2027 is a rewrite to **Next.js on the frontend and C# on the
backend**, targeting Native AOT. Priorities, in order: stay lightweight, keep
the single-container deploy, keep the image small, and keep the "one `docker
run` and it works" property that makes this usable. A rewrite that trades that
away for architectural fashion is not worth doing, and I would rather leave the
Python version alone than ship a heavier replacement.

Until then the Flask version is the supported one and will keep getting fixes.

## Requests

Issues and feature requests: <https://git.racis.dev/marceliracis/minio-dash/-/issues>
(or the [GitHub mirror](https://github.com/MarceliRacis/minio-dash/issues)).

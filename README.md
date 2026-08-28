# macosfangamer studios — IP Logger Info

A small, self-hosted network diagnostics service. It records the source IP, timestamp, user-agent and endpoint used to access the diagnostic page, then exposes those records through an authenticated administrator dashboard.

## Features

- Flask web application
- MySQL 8 database
- IPv4/IPv6 storage
- Authenticated `/admin` dashboard
- Search/filter logs
- CSV export
- Individual deletion and configurable retention purge
- Rate limiting
- Docker Compose with Nginx reverse proxy
- Explicit trusted-proxy configuration

## Run locally with Docker Desktop

1. Copy `.env.example` to `.env`.
2. Generate an admin password hash:

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('CHANGE-ME'))"
```

3. Put the resulting hash in `ADMIN_PASSWORD_HASH` in `.env` and set strong database/Flask secrets.
4. Start the stack:

```bash
docker compose up -d --build
```

5. Open `http://localhost:8080`.
6. The administrator panel is at `http://localhost:8080/admin`.

## Reverse proxy

By default `TRUSTED_PROXY_COUNT=0`, so the application uses the direct peer address. Only increase this value when the application is actually behind a known reverse proxy chain. Do not accept arbitrary forwarded headers from untrusted clients.

For production, put the service behind HTTPS and set `COOKIE_SECURE=true`.

## Privacy

Only collect data needed for a documented network-diagnostics purpose. Tell users what is recorded and configure a short retention period appropriate to the deployment. Do not use this service to secretly identify or track people.

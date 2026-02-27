# Gateway Deployment Guide

This guide covers deploying the `demoit-gateway` binary behind a reverse proxy with TLS.

## Prerequisites

- A VPS with a public IP
- A domain (e.g. `0x0f.me`) with DNS access
- Go 1.21+ for building the binary

## 1. Build

```bash
cd gateway
go build -o demoit-gateway .
```

## 2. DNS Records

Two records are required:

| Type | Name | Value |
|------|------|-------|
| A | `0x0f.me` | `<VPS IP>` |
| A | `*.0x0f.me` | `<VPS IP>` |

The wildcard record allows tunnel subdomains like `qs-xxxx.0x0f.me` to resolve.

## 3. TLS Certificate

A wildcard certificate covering both `0x0f.me` and `*.0x0f.me` is required.

**Let's Encrypt (DNS-01 challenge):**

```bash
certbot certonly --manual --preferred-challenges dns \
  -d "0x0f.me" -d "*.0x0f.me"
```

**Cloudflare:** Automatic — enable "Full (strict)" in SSL/TLS settings.

## 4. HTTP → HTTPS Redirect

### Nginx

```nginx
server {
    listen 80;
    server_name 0x0f.me *.0x0f.me;
    return 301 https://$host$request_uri;
}
```

### Caddy

Caddy handles HTTP→HTTPS automatically by default.

### Cloudflare

Enable **SSL/TLS → Always Use HTTPS**.

## 5. Reverse Proxy (HTTPS → Gateway)

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name 0x0f.me *.0x0f.me;

    ssl_certificate     /etc/letsencrypt/live/0x0f.me/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/0x0f.me/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (required for tunnel connections)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
}
```

### Caddy

```caddyfile
0x0f.me, *.0x0f.me {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy handles TLS and WebSocket upgrades automatically.

## 6. Gateway Environment Variables

```bash
export DEMOIT_ROOT_DOMAIN=0x0f.me
export DEMOIT_ADDR=:8080
```

See the main [README](../README.md#gateway-environment-variables) for the full list.

## 7. Run

```bash
DEMOIT_ROOT_DOMAIN=0x0f.me ./demoit-gateway
```

For production, use systemd or a process manager:

```ini
# /etc/systemd/system/demoit-gateway.service
[Unit]
Description=Demoit Gateway
After=network.target

[Service]
ExecStart=/opt/demoit/demoit-gateway
Environment=DEMOIT_ROOT_DOMAIN=0x0f.me
Environment=DEMOIT_ADDR=:8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now demoit-gateway
```

## 8. Verify

```bash
# 1. HTTP redirect works
curl -v http://0x0f.me 2>&1 | grep -E "301|Location"

# 2. API health
curl -i https://demoit.0x0f.me/api/healthz

# 3. Full end-to-end test
pip install demoit
demoit 3000 --gateway https://demoit.0x0f.me
```

## Client Quick Start

Users can expose a local port with:

```bash
pip install demoit
demoit 3000 --gateway https://demoit.0x0f.me
```

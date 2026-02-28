# Gateway Deployment Guide

This guide covers deploying the `godemo-gateway` binary behind a reverse proxy with TLS.

## Prerequisites

- A VPS with a public IP
- A domain (e.g. `0x0f.me`) with DNS access
- Go 1.22+ for building the binary

## 1. Install the Gateway

**One-liner:**

```bash
curl -fsSL https://raw.githubusercontent.com/bitxel/godemo/main/install.sh | bash -s -- \
  --component gateway --install-dir /opt/godemo
```

**Manual download:**

Pre-built binaries for all platforms are available on the
[GitHub Releases](https://github.com/bitxel/godemo/releases) page.

```bash
curl -Lo /opt/godemo/godemo-gateway \
  https://github.com/bitxel/godemo/releases/latest/download/godemo-gateway-linux-amd64
chmod +x /opt/godemo/godemo-gateway
```

**Build from source:**

```bash
cd gateway
go build -o godemo-gateway .
```

## 2. DNS Records

Two records are required:

| Type | Name | Value |
|------|------|-------|
| A | `0x0f.me` | `<VPS IP>` |
| A | `*.0x0f.me` | `<VPS IP>` |

The wildcard record allows tunnel subdomains like `dm-a355898a.0x0f.me` to resolve.

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
export GODEMO_ROOT_DOMAIN=0x0f.me
export GODEMO_ADDR=:8080
export GODEMO_TRUST_PROXY=true
export GODEMO_TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
```

See the main [README](../README.md#gateway-environment-variables) for the full list.

### Proxy Trust Safety

`GODEMO_TRUST_PROXY=true` makes the gateway read `X-Forwarded-For` and
`X-Forwarded-Proto`. Only enable this when all inbound traffic reaches the
gateway through your trusted reverse proxy/load balancer.

Use `GODEMO_TRUSTED_PROXY_CIDRS` to restrict which proxy source IPs are trusted:

- Example single-node Nginx: `127.0.0.1/32`
- Example private LB network: `10.0.0.0/8`
- Multiple entries: comma-separated CIDRs or IPs

If `GODEMO_TRUSTED_PROXY_CIDRS` is empty, all proxy source addresses are trusted
when `GODEMO_TRUST_PROXY=true`.

## 7. Run

```bash
GODEMO_ROOT_DOMAIN=0x0f.me ./godemo-gateway
```

For production, use systemd or a process manager:

```ini
# /etc/systemd/system/godemo-gateway.service
[Unit]
Description=Godemo Gateway
After=network.target

[Service]
ExecStart=/opt/godemo/godemo-gateway
Environment=GODEMO_ROOT_DOMAIN=0x0f.me
Environment=GODEMO_ADDR=:8080
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now godemo-gateway
```

## 8. Verify

```bash
# 1. HTTP redirect works
curl -v http://0x0f.me 2>&1 | grep -E "301|Location"

# 2. API health
curl -i https://godemo.0x0f.me/api/healthz

# 3. Full end-to-end test
pip install godemo
godemo-cli 3000 --gateway https://godemo.0x0f.me
```

## Client Quick Start

### One-liner install

```bash
curl -fsSL https://raw.githubusercontent.com/bitxel/godemo/main/install.sh | bash
godemo-cli 3000 --gateway https://godemo.0x0f.me
```

### Python

```bash
pip install godemo
godemo-cli 3000 --gateway https://godemo.0x0f.me
```

### Go (manual download)

```bash
curl -Lo godemo-cli https://github.com/bitxel/godemo/releases/latest/download/godemo-cli-linux-amd64
chmod +x godemo-cli
./godemo-cli 3000 --gateway https://godemo.0x0f.me
```

Available binaries: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`.

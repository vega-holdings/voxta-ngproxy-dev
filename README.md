# NGProxy (Single-Host Nginx Reverse Proxy) — Voxta Module

Status: **alpha** (single-host, Windows-only).

## What it is
NGProxy makes hosting Voxta behind a single hostname “close to one-click” by:
- Running an nginx reverse proxy on the same machine as Voxta
- Issuing + renewing a Let’s Encrypt TLS cert via **Cloudflare DNS-01** (using `lego`)
- Proxying the public hostname to a local upstream URL (default `http://127.0.0.1:5384`)

## Requirements
- **Windows** (Voxta Server for Windows)
- **A domain in Cloudflare** (the hostname you enter must be within a Cloudflare-managed zone)
- **Cloudflare API Token** with:
  - `Zone:Read`
  - `DNS:Edit`
  - Scope limited to the zone that contains your domain (recommended)
- **DNS resolution for clients**:
  - Your clients must be able to resolve the hostname to this machine (public DNS or local DNS like Unbound/Pi-hole).
  - ACME is DNS-01, so the hostname does not need to be publicly reachable during issuance, but DNS TXT records must work.
- **Ports 80 + 443 available** on the machine (no IIS/other service bound), and allowed through Windows Firewall if you want LAN/WAN access.
- Outbound network access to:
  - Cloudflare API
  - Let’s Encrypt ACME endpoints
  - Tool downloads (`nginx.org` + GitHub Releases)

## Configuration
- `Domain`: hostname to serve (example `voxta.example.com`)
- `Email`: ACME email for Let’s Encrypt
- `CloudflareApiToken`: raw Cloudflare API token (or paste a line like `dns_cloudflare_api_token=...`)
- `UpstreamUrl`: where to proxy to (default `http://127.0.0.1:5384`)
- `Max Upload Size (MB)`: nginx upload limit (`client_max_body_size`). Increase this if you import large character packs (set `0` for unlimited).
- `DNS Resolvers (optional)`: only needed if your network blocks the default DNS behavior. Use `host:port` (example `1.1.1.1:53` or your router DNS).

## Install / Run
Saving the form does **not** install anything. NGProxy runs via Voxta’s **Install** flow.

Install does:
1) Download + unpack `nginx` and `lego` under `Data/Tools/NGProxy/`
2) Issue/renew the cert via Cloudflare DNS-01
3) Write `ngproxy.conf`
4) Start/reload nginx

## Files / Logs
- Tools root: `Voxta.Server.Win.v1.2.0/Data/Tools/NGProxy/`
- ACME data (accounts/certs/keys): `.../acme/` (back this up; it contains private keys)
- Certificate files: `.../acme/certificates/{domain}.crt`, `{domain}.key`, `{domain}.issuer.crt` (if present), `{domain}.fullchain.crt`
- nginx config: `.../nginx/.../conf/ngproxy.conf`
- nginx logs: `.../nginx/.../logs/`

## Troubleshooting
- “I filled the form and nothing happened”: go to Modules list and click **Install** for NGProxy.
- `413 Request Entity Too Large` (nginx): increase `Max Upload Size (MB)` and click **Install** to re-generate/reload nginx config.
- `cloudflare: could not find zone for domain ...`: set `DNS Resolvers (optional)` to a working resolver (often your router DNS). Some networks/VPNs block Google Public DNS which can break lego’s zone detection.
- nginx won’t start: check if ports 80/443 are already in use and read nginx logs in the Tools folder.
- `nginx: [emerg] unknown directive "﻿worker_processes"`: the config file was written with a UTF-8 BOM. Ensure the file is UTF-8 **without BOM** (fixed in newer builds of NGProxy).
- `nginx: [error] invalid PID number "" in .../ngproxy.pid` on reload: nginx isn’t running yet; NGProxy will fall back to starting it.

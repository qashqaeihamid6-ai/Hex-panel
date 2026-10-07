# HEX Panel

A Cloudflare Worker based control panel for managing proxy subscriptions, DNS routing, users, and node sharing from one dashboard.

> **Status:** bundled production worker. The main entrypoint is `worker-fixed.js`.

## Features

- Persian-friendly admin dashboard with responsive glass UI
- Persistent settings and credentials through Cloudflare KV
- Per-user subscription tokens and protocol links
- VLESS, Trojan, Shadowsocks, Sing-box, Clash/Mihomo, Xray, Warp, Amnezia and OpenVPN exports
- DNS-over-HTTPS gateway and client DNS routing controls
- Fake-IP and real-IP DNS modes
- Routing presets, proxy chaining, domain fronting, XHTTP, HTTP upgrade and fragmentation options
- Node share export/import for syncing configuration between panels
- Health endpoint at `/api/health`

## Requirements

- A Cloudflare account with Workers and KV enabled
- Node.js 18+ and Wrangler 3+
- One KV namespace bound as `WD_KV` or `BK_KV`
- A custom domain is recommended for stable subscription URLs

## Deploy in 5 minutes

```bash
npm install -g wrangler
wrangler login
wrangler kv namespace create WD_KV
```

Copy the returned namespace ID into `wrangler.toml`, then deploy:

```bash
wrangler deploy
```

Open the deployed URL and create the first admin password at `/panel/setup`.

## Local development

```bash
wrangler dev
```

For local persistence, create `.dev.vars` only when your local setup requires secrets. Never commit passwords, tokens, private keys, or real node configuration.

## Configuration

The Worker reads its KV binding from `WD_KV` first and falls back to `BK_KV`. The dashboard stores settings in KV, so no secret values should be hard-coded into the source.

Optional environment values:

| Variable | Purpose |
| --- | --- |
| `PROXY_PORTS` | Comma-separated proxy ports used by generated configurations |
| `NATIVE_CLIENT_CONFIG` | Optional native Sing-box client JSON merged into subscriptions |
| `OPENVPN_CLIENT_PROFILE` | Optional OpenVPN client profile content |
| `DNS_FETCH` | Optional fetch-compatible DNS implementation for tests/integrations |

## Important routes

| Route | Description |
| --- | --- |
| `/panel` | Admin dashboard |
| `/panel/setup` | First-run password setup |
| `/panel/login` | Admin login |
| `/api/health` | Health check |
| `/dns-query` | DNS wire-format endpoint |
| `/dns-json` | JSON DNS endpoint |
| `/sub/*` | Subscription and protocol exports |
| `/api/node/export` | Export node-share configuration |
| `/api/node/import` | Import node-share configuration |

## Security notes

- Keep the Worker URL and subscription tokens private.
- Use a strong, unique admin password.
- Do not commit `.dev.vars`, exported node files, KV dumps, or screenshots containing credentials.
- Rotate subscription tokens after sharing them publicly.
- DNS and proxy providers may receive requests depending on your selected routing settings.
- This project does not bypass provider terms or guarantee access to any service.

## Project structure

```text
.
├── worker-fixed.js   # bundled Cloudflare Worker entrypoint
├── wrangler.toml     # Wrangler deployment configuration
├── package.json      # project scripts and metadata
├── LICENSE           # MIT license
└── .github/          # issue templates and CI
```

## License

Released under the MIT License. See [LICENSE](LICENSE).

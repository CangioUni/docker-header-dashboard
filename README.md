# docker-header-dashboard

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-scratch%20image-2496ED?logo=docker&logoColor=white)
![Image size](https://img.shields.io/badge/image%20size-~5%20MB-brightgreen)
![Vibe coded](https://img.shields.io/badge/vibe-coded-ff69b4)

A tiny Docker container that shows you what a server sees about your request: received headers, origin IP, request IP and other useful info. Handy for debugging reverse proxies, load balancers, CDNs and tunnels.

> ⚠️ **This project is vibe coded.** It was generated with an AI assistant and has not been audited or thoroughly tested. Read the code before trusting it with anything important.

> 🌐 **Publicly exposed for a short time only.** If you're reading this while a live instance is reachable, it is temporary and will be taken down soon. Don't rely on it, and don't send anything sensitive to it: it echoes back everything it receives, including cookies and auth headers.

## Quick start

```bash
docker compose up -d --build
curl localhost:8080          # plain text
curl localhost:8080/json     # JSON
curl localhost:8080/ip       # just the IP
```

Opening it in a browser gives a styled HTML page.

Without Compose:

```bash
docker build -t whoami-lite .
docker run --rm -p 8080:8080 whoami-lite
```

## Endpoints

| Path | Output |
|------|--------|
| `/` | HTML for browsers, plain text for `curl` and similar, JSON if `Accept: application/json` |
| `/json` | Full info as JSON |
| `/ip` | Only the claimed client IP |
| `/?format=json` or `/?format=text` | Force an output format |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Port the server listens on |

## What it shows

- **Direct connection:** the TCP peer IP and port, which can't be spoofed.
- **Claimed client IP:** the original client, taken from `CF-Connecting-IP`, the first `X-Forwarded-For` entry, or `X-Real-IP`. The source is labelled, and the full `X-Forwarded-For` chain is listed.
- **Proxy headers:** `Forwarded`, `Via`, `X-Forwarded-Proto/Host/Port`, `CF-Ray` and similar are grouped together.
- **Request details:** method, protocol, scheme, host, URI, user agent and content length.
- **TLS:** version, SNI and ALPN, shown when the request is TLS.
- **Everything else:** all headers (sorted), query parameters, cookies, the container hostname and the time.

## Things to know

- The container only sees the Docker bridge gateway IP as the peer if you publish the port with the default userland proxy. Behind Traefik or Caddy, or with `network_mode: host`, you'll see the real peer.
- The claimed client IP is only trustworthy if your proxy overwrites those headers. Clients can set them to anything.
- Go doesn't preserve header order from the wire, so headers are listed alphabetically.
- The port is configurable via the `PORT` env var. The health check is built into the binary (`/whoami -healthcheck`) because `scratch` has no curl or shell.
- The container runs as a non-root user, with a read-only filesystem and all capabilities dropped in the provided Compose file.
- Responses are sent with `Cache-Control: no-store`.

## Project layout

```
.
├── main.go              # the whole server
├── go.mod
├── Dockerfile           # multi-stage build, final image is FROM scratch
├── docker-compose.yml
└── README.md
```

## License

Released under the [MIT License](LICENSE).
# Host Workbench

FastAPI, static frontend, nginx SSL proxy, and MongoDB 4.4 demo stack for host registration and group membership API integration testing.

> This is an auto-generated demo application for lab testing and integration validation only. It is not intended for production use.
> The repository does not include generated certificates, private keys, `.env` files, API keys, JWTs, or MongoDB data.

## URLs

- Web UI: `https://<your-ip>:8443/`
- Help page: `https://<your-ip>:8443/help`
- Public Swagger: `https://<your-ip>:8443/docs`
- OpenAPI JSON: `https://<your-ip>:8443/openapi.json`

The public API is documented in Swagger. Internal frontend endpoints under `/internal/*` are excluded from OpenAPI.
Hosts are intentionally focused: `hostIP`, `registered`, and `groups`. The web UI includes a `Clear Host Data` control that removes host records and clears group memberships while preserving group definitions and the demo API key.

## Branding

The app is branded as `Host Workbench` and includes:

- SVG brand mark: `frontend/assets/brand-mark.svg`
- SVG favicon: `frontend/assets/favicon.svg`
- Web app manifest: `frontend/site.webmanifest`
- Help/documentation page: `frontend/help.html`

## Public API flow

1. Open the web UI and click `Generate API Key`.
2. Exchange the API key for a JWT:

   ```bash
   curl -k -X POST https://<your-ip>:8443/public/auth/token \
     -H "X-API-Key: <api-key>"
   ```

3. Use the JWT with public host APIs:

   ```bash
   curl -k https://<your-ip>:8443/public/hosts \
     -H "Authorization: Bearer <jwt>"
   ```

4. Create or update a host registration state:

   ```bash
   curl -k -X PUT https://<your-ip>:8443/public/hosts/192.0.2.44 \
     -H "Authorization: Bearer <jwt>" \
     -H "Content-Type: application/json" \
     -d '{"registered": true}'
   ```

5. Add or remove group membership:

   ```bash
   curl -k -X PUT https://<your-ip>:8443/public/hosts/192.0.2.44/groups/critical \
     -H "Authorization: Bearer <jwt>"

   curl -k -X DELETE https://<your-ip>:8443/public/hosts/192.0.2.44/groups/isolated \
     -H "Authorization: Bearer <jwt>"
   ```

## Deploy

From the project root, run:

```bash
./scripts/start_stack.sh --host <your-ip> --port 8443
```

The script will:

- create `.env` if needed
- generate a persistent random `JWT_SECRET`
- generate `nginx/certs/forescout-demo.crt`
- generate `nginx/certs/forescout-demo.key`
- build and start the full Docker Compose stack
- print the App, Help, and Swagger URLs

Useful options:

```bash
# Auto-detect host IP and use default HTTPS port 8443
./scripts/start_stack.sh

# Regenerate the self-signed certificate
./scripts/start_stack.sh --host <your-ip> --force-cert

# Use a different public HTTPS port
./scripts/start_stack.sh --host <your-ip> --port 9443
```

Manual equivalent:

```bash
mkdir -p nginx/certs
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout nginx/certs/forescout-demo.key \
  -out nginx/certs/forescout-demo.crt \
  -subj "/CN=<your-ip>" \
  -addext "subjectAltName=IP:<your-ip>,DNS:localhost"
docker compose up -d --build
```

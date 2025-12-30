# Jellyseerr SSO Bridge

A lightweight SSO bridge for Jellyseerr that enables OIDC authentication via Authentik, properly linking users to their Jellyfin accounts.

## Problem

Jellyseerr doesn't support OIDC authentication natively. When using Jellyfin with the SSO plugin for Authentik, users don't have local passwords, which prevents them from logging into Jellyseerr using the standard Jellyfin authentication flow.

## Solution

This bridge:
1. Handles OIDC authentication with Authentik
2. Looks up the user's Jellyfin account by username
3. Imports/links the user in Jellyseerr with their Jellyfin ID
4. Creates a valid Jellyseerr session
5. Uses Traefik forwardAuth middleware to auto-redirect unauthenticated users

## Architecture

```
User → Traefik (forwardAuth) → SSO Bridge → Authentik (OIDC)
                                    ↓
                              Jellyfin API (user lookup)
                                    ↓
                              Jellyseerr API (user import/session)
                                    ↓
                              User redirected with session cookie
```

## Requirements

- Authentik with OIDC application configured
- Jellyfin with SSO plugin (users created via Authentik)
- Jellyseerr connected to Jellyfin
- Traefik ingress controller
- Jellyfin admin API key
- Jellyseerr API key (optional, for admin features)

## Installation

### Using Helm

```bash
helm install jellyseerr-sso-bridge ./deploy/helm/jellyseerr-sso-bridge \
  --namespace servarr \
  --set config.oidc.issuer=https://auth.example.com/application/o/jellyseerr-bridge/ \
  --set config.oidc.clientId=your-client-id \
  --set config.jellyfin.url=http://jellyfin.servarr.svc:8096 \
  --set config.jellyseerr.url=http://jellyseerr.servarr.svc:5055 \
  --set config.bridge.externalURL=https://sso.example.com \
  --set config.bridge.cookieDomain=.example.com \
  --set secrets.oidcClientSecret=your-secret \
  --set secrets.jellyfinApiKey=your-jellyfin-api-key
```

### Using Terraform

See the terraform module in your homelab's `kubernetes/terraform/modules/jellyseerr-sso-bridge/`.

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `OIDC_ISSUER` | Authentik OIDC issuer URL | Yes |
| `OIDC_CLIENT_ID` | OIDC client ID | Yes |
| `OIDC_CLIENT_SECRET` | OIDC client secret | Yes |
| `JELLYFIN_URL` | Jellyfin internal URL | Yes |
| `JELLYFIN_API_KEY` | Jellyfin admin API key | Yes |
| `JELLYSEERR_URL` | Jellyseerr internal URL | Yes |
| `JELLYSEERR_API_KEY` | Jellyseerr API key | No |
| `BRIDGE_EXTERNAL_URL` | External URL of the bridge | Yes |
| `BRIDGE_COOKIE_DOMAIN` | Cookie domain (e.g., .example.com) | Yes |
| `SESSION_SECRET` | Secret for signing session cookies | Yes |
| `SESSION_TTL` | Session duration (default: 24h) | No |

### Authentik Setup

1. Create a new OIDC Provider in Authentik
2. Configure:
   - **Name**: Jellyseerr SSO Bridge
   - **Slug**: `jellyseerr-bridge`
   - **Redirect URIs**: `https://sso.example.com/callback`
   - **Scopes**: openid, email, profile
3. Create an Application and link it to the provider

### Traefik Configuration

The Helm chart creates a forwardAuth middleware. Add it to your Jellyseerr ingress:

```yaml
metadata:
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: servarr-jellyseerr-sso-redirect@kubernetescrd
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /ready` | Readiness check (verifies Jellyfin/Jellyseerr connectivity) |
| `GET /auth/check` | ForwardAuth endpoint for Traefik |
| `GET /login` | Initiates OIDC login flow |
| `GET /callback` | OIDC callback handler |
| `GET /logout` | Clears session |

## Building

```bash
# Build binary
make build

# Build Docker image
make docker-build

# Run tests
make test
```

## License

MIT


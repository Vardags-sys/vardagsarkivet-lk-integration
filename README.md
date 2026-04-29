# Vardagsarkivet LK Integration Service

Central Fastify/Node.js service for integrating Vardagsarkivet with LK Systems / LK AtHome.

## Purpose

Base44 should call this service instead of calling `my.lk.nu` directly.

Flow:

```text
Vardagsarkivet / Base44
    -> this LK Integration Service
    -> my.lk.nu
    -> user's LK Webserver
```

## Local setup

```bash
npm install
cp .env.example .env
npm run dev
```

Edit `.env` and set:

- `API_KEY`
- `LK_EMAIL`
- `LK_PASSWORD`

Do not commit `.env`.

## Test

Health check:

```bash
curl http://localhost:3000/health
```

Login test:

```bash
curl -H "Authorization: Bearer replace-with-long-random-api-key" \
  http://localhost:3000/lk/test-login
```

Thermostats:

```bash
curl -H "Authorization: Bearer replace-with-long-random-api-key" \
  http://localhost:3000/lk/thermostats
```

## Render deployment

Create a Render Web Service:

- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`

Add the same environment variables as in `.env.example`.

## Base44 secrets

In Base44, use:

```env
LK_INTEGRATION_API_URL=https://your-render-service.onrender.com
LK_INTEGRATION_API_KEY=same-value-as-API_KEY
```

Base44 should call:

- `GET /lk/thermostats`
- `GET /lk/thermostats/:tid`
- `POST /lk/thermostats/:tid/setpoint` later, when the real LK write request has been captured.

## Important security notes

This is a proof-of-concept.

For a real multi-user product:

- Do not store one global LK account in environment variables.
- Store credentials per Vardagsarkivet user.
- Encrypt credentials at rest.
- Never log LK passwords.
- Add rate limiting.
- Add audit logging.
- Add a way for users to delete their LK integration.
- Treat this as an unofficial LK integration and handle failures gracefully.

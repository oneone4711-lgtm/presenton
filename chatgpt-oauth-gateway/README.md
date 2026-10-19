# Presenton ChatGPT OAuth Gateway

OAuth 2.1 and Dynamic Client Registration gateway for connecting ChatGPT to a self-hosted Presenton MCP endpoint that uses a static Bearer API key.

## Environment

- `SIGNING_SECRET`: required, random secret used to sign stateless OAuth client registrations.
- `PUBLIC_URL`: the gateway's public HTTPS origin.
- `UPSTREAM_URL`: the Presenton origin. Defaults to the owner's Railway Presenton deployment.
- `ALLOWED_REDIRECT_HOSTS`: comma-separated OAuth callback host suffixes. Defaults to `chatgpt.com,openai.com`.

The Presenton API key is never stored in source code or an environment variable. The user supplies it on the authorization page. Authorization codes live in process memory for at most five minutes; ChatGPT receives the key as its OAuth access and refresh token and sends it to the gateway over HTTPS.


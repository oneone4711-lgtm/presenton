import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask


UPSTREAM_URL = os.getenv(
    "UPSTREAM_URL",
    "https://presentonpresentonlatest-production-38ee.up.railway.app",
).rstrip("/")
PUBLIC_URL = os.getenv("PUBLIC_URL", "").rstrip("/")
SIGNING_SECRET = os.getenv("SIGNING_SECRET", "")
ALLOWED_REDIRECT_HOSTS = tuple(
    host.strip().lower()
    for host in os.getenv("ALLOWED_REDIRECT_HOSTS", "chatgpt.com,openai.com").split(",")
    if host.strip()
)

if not SIGNING_SECRET:
    raise RuntimeError("SIGNING_SECRET is required")

app = FastAPI(title="Presenton ChatGPT OAuth Gateway")
codes: dict[str, dict] = {}
codes_lock = asyncio.Lock()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def sign(value: str) -> str:
    return b64url(hmac.new(SIGNING_SECRET.encode(), value.encode(), hashlib.sha256).digest())


def make_client_id(redirect_uris: list[str]) -> str:
    payload = b64url(json.dumps({"redirect_uris": redirect_uris}, separators=(",", ":")).encode())
    return f"pgw.{payload}.{sign(payload)}"


def decode_client_id(client_id: str) -> dict:
    try:
        prefix, payload, signature = client_id.split(".", 2)
        if prefix != "pgw" or not hmac.compare_digest(signature, sign(payload)):
            raise ValueError
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        data = json.loads(raw)
        if not isinstance(data.get("redirect_uris"), list):
            raise ValueError
        return data
    except Exception as exc:
        raise HTTPException(400, "invalid_client") from exc


def allowed_redirect(uri: str) -> bool:
    parsed = urlparse(uri)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    return any(host == allowed or host.endswith("." + allowed) for allowed in ALLOWED_REDIRECT_HOSTS)


def origin(request: Request) -> str:
    if PUBLIC_URL:
        return PUBLIC_URL
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    forwarded_host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{forwarded_proto}://{forwarded_host}"


def authorization_page(fields: dict[str, str], error: str = "") -> HTMLResponse:
    hidden = "".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value, quote=True)}">'
        for key, value in fields.items()
    )
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    body = f"""<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>連結 Presenton</title><style>
body{{font-family:system-ui,sans-serif;background:#f6f7f9;margin:0;padding:32px;color:#17202a}}
main{{max-width:520px;margin:8vh auto;background:white;padding:32px;border-radius:16px;box-shadow:0 8px 30px #0001}}
h1{{font-size:24px}}label{{display:block;font-weight:650;margin:24px 0 8px}}
input[type=password]{{box-sizing:border-box;width:100%;padding:12px;border:1px solid #bbb;border-radius:8px}}
button{{width:100%;margin-top:20px;padding:12px;border:0;border-radius:8px;background:#111;color:white;font-weight:650}}
.note{{color:#59636e;font-size:14px;line-height:1.5}}.error{{color:#b42318;background:#fef3f2;padding:10px;border-radius:8px}}
</style></head><body><main><h1>連結 Presenton 到 ChatGPT</h1>
<p class="note">輸入 Presenton 管理頁建立的 API 金鑰。金鑰只會經由 HTTPS 傳送給此閘道及 ChatGPT，並用於呼叫你的 Presenton 服務。</p>
{error_html}<form method="post" action="/authorize">{hidden}
<label for="access_key">Presenton API 金鑰</label><input id="access_key" name="access_key" type="password" required autocomplete="off" placeholder="sk-presenton-…">
<button type="submit">授權並返回 ChatGPT</button></form></main></body></html>"""
    return HTMLResponse(body, headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})


def validate_authorize(client_id: str, redirect_uri: str, response_type: str, code_challenge: str, code_challenge_method: str):
    client = decode_client_id(client_id)
    if redirect_uri not in client["redirect_uris"] or not allowed_redirect(redirect_uri):
        raise HTTPException(400, "invalid_redirect_uri")
    if response_type != "code":
        raise HTTPException(400, "unsupported_response_type")
    if code_challenge_method != "S256" or not code_challenge:
        raise HTTPException(400, "PKCE S256 is required")


@app.get("/")
async def health():
    return {"status": "ok", "service": "presenton-chatgpt-oauth-gateway"}


@app.get("/.well-known/oauth-protected-resource")
@app.get("/.well-known/oauth-protected-resource/mcp")
async def protected_resource(request: Request):
    base = origin(request)
    return {
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["presentations:create"],
    }


@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    base = origin(request)
    return {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["presentations:create"],
    }


@app.post("/register")
async def register(request: Request):
    data = await request.json()
    redirect_uris = data.get("redirect_uris") or []
    if not redirect_uris or not all(isinstance(uri, str) and allowed_redirect(uri) for uri in redirect_uris):
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    client_id = make_client_id(redirect_uris)
    return JSONResponse(
        {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
        status_code=201,
    )


@app.get("/authorize")
async def authorize_get(
    client_id: str,
    redirect_uri: str,
    response_type: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str = "",
    scope: str = "presentations:create",
    resource: str = "",
):
    validate_authorize(client_id, redirect_uri, response_type, code_challenge, code_challenge_method)
    return authorization_page(locals())


@app.post("/authorize")
async def authorize_post(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    response_type: str = Form(...),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form(...),
    access_key: str = Form(...),
    state: str = Form(""),
    scope: str = Form("presentations:create"),
    resource: str = Form(""),
):
    fields = {k: v for k, v in locals().items() if k != "access_key"}
    validate_authorize(client_id, redirect_uri, response_type, code_challenge, code_challenge_method)
    if not access_key.startswith("sk-presenton-"):
        return authorization_page(fields, "金鑰格式不正確，請重新貼上完整的 Presenton API 金鑰。")
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "oauth-gateway", "version": "1.0"}},
    }
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
            response = await client.post(
                f"{UPSTREAM_URL}/mcp",
                json=initialize,
                headers={"Authorization": f"Bearer {access_key}", "Accept": "application/json, text/event-stream"},
            )
        if response.status_code not in (200, 202):
            return authorization_page(fields, "Presenton 拒絕這組金鑰，請確認金鑰仍有效。")
    except httpx.HTTPError:
        return authorization_page(fields, "目前無法連線至 Presenton，請稍後再試。")
    code = secrets.token_urlsafe(32)
    async with codes_lock:
        now = time.time()
        for old_code in [key for key, value in codes.items() if value["expires"] < now]:
            codes.pop(old_code, None)
        codes[code] = {
            "access_key": access_key,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "scope": scope,
            "expires": now + 300,
        }
    query = {"code": code}
    if state:
        query["state"] = state
    return Response(status_code=302, headers={"Location": f"{redirect_uri}?{urlencode(query)}", "Cache-Control": "no-store"})


@app.post("/token")
async def token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    code: str = Form(""),
    redirect_uri: str = Form(""),
    code_verifier: str = Form(""),
    refresh_token: str = Form(""),
):
    decode_client_id(client_id)
    if grant_type == "authorization_code":
        async with codes_lock:
            record = codes.pop(code, None)
        if not record or record["expires"] < time.time():
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())
        if (
            record["client_id"] != client_id
            or record["redirect_uri"] != redirect_uri
            or not hmac.compare_digest(record["code_challenge"], challenge)
        ):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        access_key = record["access_key"]
        scope = record["scope"]
    elif grant_type == "refresh_token" and refresh_token.startswith("sk-presenton-"):
        access_key = refresh_token
        scope = "presentations:create"
    else:
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    return JSONResponse(
        {
            "access_token": access_key,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": access_key,
            "scope": scope,
        },
        headers={"Cache-Control": "no-store"},
    )


@app.api_route("/mcp", methods=["GET", "POST", "DELETE", "OPTIONS"])
async def mcp_proxy(request: Request):
    if request.method == "OPTIONS":
        return Response(status_code=204, headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*", "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS"})
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer "):
        metadata = f'{origin(request)}/.well-known/oauth-protected-resource'
        return JSONResponse(
            {"error": "authentication_required"},
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer resource_metadata="{metadata}"'},
        )
    body = await request.body()
    forward_headers = {"Authorization": authorization}
    for name in ("accept", "content-type", "mcp-session-id", "last-event-id", "mcp-protocol-version"):
        if name in request.headers:
            forward_headers[name] = request.headers[name]
    client = httpx.AsyncClient(timeout=httpx.Timeout(1800, connect=30), follow_redirects=True)
    upstream_request = client.build_request(request.method, f"{UPSTREAM_URL}/mcp", headers=forward_headers, content=body)
    upstream = await client.send(upstream_request, stream=True)
    response_headers = {}
    for name in ("content-type", "mcp-session-id", "www-authenticate", "cache-control"):
        if name in upstream.headers:
            response_headers[name] = upstream.headers[name]
    return StreamingResponse(
        upstream.aiter_raw(),
        status_code=upstream.status_code,
        headers=response_headers,
        background=BackgroundTask(client.aclose),
    )


import { Hono } from "hono@4";
import { cors } from "hono/cors";
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const app = new Hono();
const upstreamUrl = (Bun.env.UPSTREAM_URL ?? "https://presentonpresentonlatest-production-38ee.up.railway.app").replace(/\/$/, "");
const publicUrl = (Bun.env.PUBLIC_URL ?? "").replace(/\/$/, "");
const signingSecret = Bun.env.SIGNING_SECRET ?? "";
const allowedRedirectHosts = (Bun.env.ALLOWED_REDIRECT_HOSTS ?? "chatgpt.com,openai.com")
  .split(",").map((host) => host.trim().toLowerCase()).filter(Boolean);
if (!signingSecret) throw new Error("SIGNING_SECRET is required");

type CodeRecord = { accessKey: string; clientId: string; redirectUri: string; challenge: string; scope: string; expires: number };
const codes = new Map<string, CodeRecord>();

const b64url = (value: Buffer | string) => Buffer.from(value).toString("base64url");
const sign = (value: string) => createHmac("sha256", signingSecret).update(value).digest("base64url");
const safeEqual = (a: string, b: string) => {
  const left = Buffer.from(a); const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
};
const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[char]!));

function requestOrigin(c: any) {
  if (publicUrl) return publicUrl;
  const url = new URL(c.req.url);
  const proto = c.req.header("x-forwarded-proto") ?? url.protocol.replace(":", "");
  const host = c.req.header("x-forwarded-host") ?? c.req.header("host") ?? url.host;
  return `${proto}://${host}`;
}

function redirectAllowed(uri: string) {
  try {
    const parsed = new URL(uri);
    const host = parsed.hostname.toLowerCase();
    return parsed.protocol === "https:" && allowedRedirectHosts.some((allowed) => host === allowed || host.endsWith(`.${allowed}`));
  } catch { return false; }
}

function makeClientId(redirectUris: string[]) {
  const payload = b64url(JSON.stringify({ redirect_uris: redirectUris }));
  return `pgw.${payload}.${sign(payload)}`;
}

function decodeClientId(clientId: string): { redirect_uris: string[] } {
  const parts = clientId.split(".");
  if (parts.length !== 3 || parts[0] !== "pgw" || !safeEqual(parts[2], sign(parts[1]))) throw new Error("invalid_client");
  const data = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (!Array.isArray(data.redirect_uris)) throw new Error("invalid_client");
  return data;
}

function validateAuthorize(fields: Record<string, string>) {
  let client;
  try { client = decodeClientId(fields.client_id); } catch { throw new Error("invalid_client"); }
  if (!client.redirect_uris.includes(fields.redirect_uri) || !redirectAllowed(fields.redirect_uri)) throw new Error("invalid_redirect_uri");
  if (fields.response_type !== "code") throw new Error("unsupported_response_type");
  if (fields.code_challenge_method !== "S256" || !fields.code_challenge) throw new Error("PKCE S256 is required");
}

function authPage(fields: Record<string, string>, error = "") {
  const hidden = Object.entries(fields).map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`).join("");
  const errorHtml = error ? `<p class="error">${escapeHtml(error)}</p>` : "";
  return `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>連結 Presenton</title><style>
body{font-family:system-ui,sans-serif;background:#f6f7f9;margin:0;padding:32px;color:#17202a}main{max-width:520px;margin:8vh auto;background:#fff;padding:32px;border-radius:16px;box-shadow:0 8px 30px #0001}h1{font-size:24px}label{display:block;font-weight:650;margin:24px 0 8px}input[type=password]{box-sizing:border-box;width:100%;padding:12px;border:1px solid #bbb;border-radius:8px}button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:8px;background:#111;color:#fff;font-weight:650}.note{color:#59636e;font-size:14px;line-height:1.5}.error{color:#b42318;background:#fef3f2;padding:10px;border-radius:8px}</style></head><body><main><h1>連結 Presenton 到 ChatGPT</h1><p class="note">輸入 Presenton 管理頁建立的 API 金鑰。金鑰只會經由 HTTPS 傳送給此閘道及 ChatGPT，並用於呼叫你的 Presenton 服務。</p>${errorHtml}<form method="post" action="/authorize">${hidden}<label for="access_key">Presenton API 金鑰</label><input id="access_key" name="access_key" type="password" required autocomplete="off" placeholder="sk-presenton-…"><button type="submit">授權並返回 ChatGPT</button></form></main></body></html>`;
}

app.use("*", cors());
app.get("/", (c) => c.json({ status: "ok", service: "presenton-chatgpt-oauth-gateway" }));

const resourceMetadata = (c: any) => {
  const base = requestOrigin(c);
  return c.json({ resource: `${base}/mcp`, authorization_servers: [base], bearer_methods_supported: ["header"], scopes_supported: ["presentations:create"] });
};
app.get("/.well-known/oauth-protected-resource", resourceMetadata);
app.get("/.well-known/oauth-protected-resource/mcp", resourceMetadata);

app.get("/.well-known/oauth-authorization-server", (c) => {
  const base = requestOrigin(c);
  return c.json({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, registration_endpoint: `${base}/register`, response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"], scopes_supported: ["presentations:create"] });
});

app.post("/register", async (c) => {
  const data = await c.req.json().catch(() => ({}));
  const redirectUris = Array.isArray(data.redirect_uris) ? data.redirect_uris : [];
  if (!redirectUris.length || !redirectUris.every((uri: unknown) => typeof uri === "string" && redirectAllowed(uri))) return c.json({ error: "invalid_redirect_uri" }, 400);
  return c.json({ client_id: makeClientId(redirectUris), client_id_issued_at: Math.floor(Date.now() / 1000), redirect_uris: redirectUris, token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }, 201);
});

app.get("/authorize", (c) => {
  const fields: Record<string, string> = {
    client_id: c.req.query("client_id") ?? "", redirect_uri: c.req.query("redirect_uri") ?? "", response_type: c.req.query("response_type") ?? "",
    code_challenge: c.req.query("code_challenge") ?? "", code_challenge_method: c.req.query("code_challenge_method") ?? "", state: c.req.query("state") ?? "",
    scope: c.req.query("scope") ?? "presentations:create", resource: c.req.query("resource") ?? ""
  };
  try { validateAuthorize(fields); } catch (error: any) { return c.json({ error: error.message }, 400); }
  return c.html(authPage(fields), 200, { "Cache-Control": "no-store", "X-Frame-Options": "DENY" });
});

app.post("/authorize", async (c) => {
  const body = await c.req.parseBody();
  const get = (name: string) => typeof body[name] === "string" ? body[name] as string : "";
  const fields: Record<string, string> = { client_id: get("client_id"), redirect_uri: get("redirect_uri"), response_type: get("response_type"), code_challenge: get("code_challenge"), code_challenge_method: get("code_challenge_method"), state: get("state"), scope: get("scope") || "presentations:create", resource: get("resource") };
  try { validateAuthorize(fields); } catch (error: any) { return c.json({ error: error.message }, 400); }
  const accessKey = get("access_key");
  if (!accessKey.startsWith("sk-presenton-")) return c.html(authPage(fields, "金鑰格式不正確，請重新貼上完整的 Presenton API 金鑰。"), 400, { "Cache-Control": "no-store" });
  try {
    const response = await fetch(`${upstreamUrl}/mcp`, { method: "POST", headers: { Authorization: `Bearer ${accessKey}`, Accept: "application/json, text/event-stream", "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "oauth-gateway", version: "1.0" } } }) });
    if (![200, 202].includes(response.status)) return c.html(authPage(fields, "Presenton 拒絕這組金鑰，請確認金鑰仍有效。"), 401, { "Cache-Control": "no-store" });
  } catch { return c.html(authPage(fields, "目前無法連線至 Presenton，請稍後再試。"), 502, { "Cache-Control": "no-store" }); }
  const now = Date.now(); for (const [key, value] of codes) if (value.expires < now) codes.delete(key);
  const code = randomBytes(32).toString("base64url");
  codes.set(code, { accessKey, clientId: fields.client_id, redirectUri: fields.redirect_uri, challenge: fields.code_challenge, scope: fields.scope, expires: now + 300_000 });
  const target = new URL(fields.redirect_uri); target.searchParams.set("code", code); if (fields.state) target.searchParams.set("state", fields.state);
  return c.redirect(target.toString(), 302);
});

app.post("/token", async (c) => {
  const body = await c.req.parseBody(); const get = (name: string) => typeof body[name] === "string" ? body[name] as string : "";
  const grantType = get("grant_type"), clientId = get("client_id");
  try { decodeClientId(clientId); } catch { return c.json({ error: "invalid_client" }, 400); }
  let accessKey = "", scope = "presentations:create";
  if (grantType === "authorization_code") {
    const record = codes.get(get("code")); codes.delete(get("code"));
    const challenge = createHash("sha256").update(get("code_verifier")).digest("base64url");
    if (!record || record.expires < Date.now() || record.clientId !== clientId || record.redirectUri !== get("redirect_uri") || !safeEqual(record.challenge, challenge)) return c.json({ error: "invalid_grant" }, 400);
    accessKey = record.accessKey; scope = record.scope;
  } else if (grantType === "refresh_token" && get("refresh_token").startsWith("sk-presenton-")) accessKey = get("refresh_token");
  else return c.json({ error: "unsupported_grant_type" }, 400);
  return c.json({ access_token: accessKey, token_type: "Bearer", expires_in: 3600, refresh_token: accessKey, scope }, 200, { "Cache-Control": "no-store" });
});

app.all("/mcp", async (c) => {
  if (c.req.method === "OPTIONS") return c.body(null, 204);
  const authorization = c.req.header("authorization") ?? "";
  if (!authorization.startsWith("Bearer ")) return c.json({ error: "authentication_required" }, 401, { "WWW-Authenticate": `Bearer resource_metadata="${requestOrigin(c)}/.well-known/oauth-protected-resource"` });
  const headers = new Headers({ Authorization: authorization });
  for (const name of ["accept", "content-type", "mcp-session-id", "last-event-id", "mcp-protocol-version"]) { const value = c.req.header(name); if (value) headers.set(name, value); }
  const method = c.req.method; const body = method === "GET" || method === "HEAD" ? undefined : await c.req.arrayBuffer();
  const upstream = await fetch(`${upstreamUrl}/mcp`, { method, headers, body });
  const responseHeaders = new Headers(); for (const name of ["content-type", "mcp-session-id", "www-authenticate", "cache-control"]) { const value = upstream.headers.get(name); if (value) responseHeaders.set(name, value); }
  return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
});

Bun.serve({ port: Number(Bun.env.PORT ?? 3000), fetch: app.fetch });


/**
 * MotorScope Backend (Cloudflare Worker)
 * Endpoints:
 *  - POST /api/antispam         -> returns a short-lived token (60s). Optional Turnstile validation.
 *  - GET  /api/ves?vrm=AB12CDE  -> DVLA vehicle info (uses DVLA_VES_API_KEY). 5-minute edge cache.
 *  - GET  /api/mot/tests?vrm=   -> DVSA MOT history (OAuth2 + API Key) if DVSA_* secrets set.
 */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const method = request.method.toUpperCase();

    const allowOrigin = env.FRONTEND_ORIGIN || "";
    const corsHeaders = {
      "Access-Control-Allow-Origin": allowOrigin && origin === allowOrigin ? allowOrigin : "",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "content-type,x-client-token",
      "Vary": "Origin"
    };
    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }
    if (!allowOrigin || (origin && origin !== allowOrigin)) {
      return new Response("Origin not allowed", { status: 403, headers: corsHeaders });
    }

    if (!(await checkRateLimit(request, env))) {
      return json({ error: "Rate limit exceeded. Try again later." }, 429, corsHeaders);
    }

    try {
      if (url.pathname === "/api/antispam" && method === "POST") {
        return await handleAntiSpam(request, env, corsHeaders);
      }
      if (url.pathname === "/api/ves" && method === "GET") {
        return await handleVES(request, env, ctx, corsHeaders);
      }
      if (url.pathname === "/api/mot/tests" && method === "GET") {
        return await handleMOTTests(request, env, corsHeaders);
      }
      return json({ ok: true, service: "motorscope-backend" }, 200, corsHeaders);
    } catch (e) {
      return json({ error: e.message || "Server error" }, 500, corsHeaders);
    }
  }
}
function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}
async function checkRateLimit(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = Date.now();
  const key = `rl:${ip}`;
  if (!env.__RL) env.__RL = new Map();
  const arr = env.__RL.get(key) || [];
  const windowMs = 2 * 60 * 1000;
  const cutoff = now - windowMs;
  const filtered = arr.filter(ts => ts > cutoff);
  if (filtered.length >= 30) return false;
  filtered.push(now);
  env.__RL.set(key, filtered);
  return true;
}
async function handleAntiSpam(request, env, corsHeaders) {
  const { vrm, token } = await request.json().catch(() => ({}));
  if (env.TURNSTILE_SECRET && token) {
    const form = new FormData();
    form.append("secret", env.TURNSTILE_SECRET);
    form.append("response", token);
    const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
    const out = await verify.json();
    if (!out.success) return json({ error: "Captcha failed" }, 400, corsHeaders);
  }
  const exp = Math.floor(Date.now() / 1000) + 60;
  const payload = `${(vrm || "").toUpperCase()}|${exp}`;
  const sig = await hmac(payload, env.ANTISPAM_SECRET || cryptoRandom());
  return json({ token: `${payload}|${sig}` }, 200, corsHeaders);
}
async function validateClientToken(vrm, headerToken, env) {
  if (!headerToken) return false;
  const parts = headerToken.split("|");
  if (parts.length < 3) return false;
  const [vrmUpper, expStr, sig] = parts;
  if (vrmUpper !== vrm.toUpperCase()) return false;
  const exp = parseInt(expStr, 10);
  if (!exp || exp < Math.floor(Date.now() / 1000)) return false;
  const payload = `${vrmUpper}|${exp}`;
  const expected = await hmac(payload, env.ANTISPAM_SECRET || cryptoRandom());
  return timingSafeEqual(sig, expected);
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
async function hmac(message, key) {
  const enc = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(message));
  const bytes = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
  return bytes;
}
function cryptoRandom() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function handleVES(request, env, ctx, corsHeaders) {
  const url = new URL(request.url);
  const vrm = (url.searchParams.get("vrm") || "").replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  if (vrm.length < 2 || vrm.length > 10) return json({ error: "Invalid VRM" }, 400, corsHeaders);
  const clientToken = request.headers.get("x-client-token") || "";
  const ok = await validateClientToken(vrm, clientToken, env);
  if (!ok) return json({ error: "Anti-spam token invalid/expired" }, 401, corsHeaders);
  if (!env.DVLA_VES_API_KEY) return json({ error: "DVLA key not configured" }, 500, corsHeaders);
  const cacheKey = new Request(`${url.origin}/cache/ves/${vrm}`, { method: "GET" });
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) {
    return new Response(cached.body, { headers: { ...corsHeaders, "content-type": "application/json", "cf-cache": "HIT" } });
  }
  const res = await fetch("https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles", {
    method: "POST",
    headers: { "x-api-key": env.DVLA_VES_API_KEY, "content-type": "application/json", "accept": "application/json" },
    body: JSON.stringify({ registrationNumber: vrm }),
  });
  if (res.status === 404) return json({ error: "Vehicle not found" }, 404, corsHeaders);
  if (!res.ok) { const txt = await res.text(); return json({ error: `DVLA error: ${res.status} ${txt}` }, 502, corsHeaders); }
  const body = await res.text();
  const resp = new Response(body, { headers: { ...corsHeaders, "content-type": "application/json" } });
  ctx.waitUntil(cache.put(cacheKey, new Response(body, { headers: { "content-type": "application/json" } })));
  return resp;
}
async function handleMOTTests(request, env, corsHeaders) {
  const url = new URL(request.url);
  const vrm = (url.searchParams.get("vrm") || "").replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  const clientToken = request.headers.get("x-client-token") || "";
  const ok = await validateClientToken(vrm, clientToken, env);
  if (!ok) return json({ error: "Anti-spam token invalid/expired" }, 401, corsHeaders);
  if (!env.DVSA_MOT_CLIENT_ID || !env.DVSA_MOT_CLIENT_SECRET || !env.DVSA_MOT_TOKEN_URL || !env.DVSA_MOT_API_KEY) {
    return json({ info: "DVSA MOT API not configured yet. Add DVSA_* secrets to enable live MOT history." }, 501, corsHeaders);
  }
  const params = new URLSearchParams();
  params.set("grant_type", "client_credentials");
  params.set("client_id", env.DVSA_MOT_CLIENT_ID);
  params.set("client_secret", env.DVSA_MOT_CLIENT_SECRET);
  params.set("scope", env.DVSA_MOT_SCOPE || "https://tapi.dvsa.gov.uk/.default");
  const tok = await fetch(env.DVSA_MOT_TOKEN_URL, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: params });
  if (!tok.ok) { const txt = await tok.text(); return json({ error: `DVSA token error: ${tok.status} ${txt}` }, 502, corsHeaders); }
  const j = await tok.json();
  const accessToken = j.access_token;
  const base = env.DVSA_MOT_BASE_URL || "https://tapi.dvsa.gov.uk";
  const path = env.DVSA_MOT_TESTS_PATH || "/v1/mot-tests";
  const res = await fetch(`${base}${path}?registration=${vrm}`, {
    headers: { "Authorization": `Bearer ${accessToken}`, "X-API-Key": env.DVSA_MOT_API_KEY, "Accept": "application/json" }
  });
  if (res.status === 404) return json([], 200, corsHeaders);
  if (!res.ok) { const txt = await res.text(); return json({ error: `DVSA error: ${res.status} ${txt}` }, 502, corsHeaders); }
  const data = await res.json();
  return json(data, 200, corsHeaders);
}

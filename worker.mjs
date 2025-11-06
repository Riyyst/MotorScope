// MotorScope Cloudflare Worker (CORS + Anti-spam + DVLA/DVSA)
// -----------------------------------------------------------
// - FRONTEND_ORIGIN can be a CSV list (e.g., "https://riystt.github.io,https://riystt.github.io/MotorScope")
// - Anti-spam token is stateless: signed with HMAC, includes vrm + exp
// - /api/ves uses DVLA VES key
// - /api/mot/tests uses DVSA (client credentials + x-api-key)

const TEXT = { "content-type": "text/plain; charset=utf-8" };
const JSONH = { "content-type": "application/json; charset=utf-8" };
const ALLOW_HEADERS = "content-type,x-client-token";
const ALLOW_METHODS = "GET,POST,OPTIONS";
const MAX_AGE = "600";

// ---------- CORS helpers ----------
function normalizeOrigin(o) {
  try { return new URL(o).origin; } catch { return ""; }
}
function getAllowedOrigins(env) {
  return String(env.FRONTEND_ORIGIN || "")
    .split(",")
    .map(s => normalizeOrigin(s.trim()))
    .filter(Boolean);
}
function matchOrigin(req, env) {
  const o = normalizeOrigin(req.headers.get("origin") || "");
  const allowed = getAllowedOrigins(env);
  return allowed.includes(o) ? o : "";
}
function addCors(req, env, res) {
  const origin = matchOrigin(req, env);
  const h = new Headers(res.headers);
  if (origin) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Vary", "Origin");
  }
  return new Response(res.body, { ...res, headers: h });
}
function preflight(req, env) {
  const origin = matchOrigin(req, env);
  if (!origin) return new Response("CORS: origin not allowed", { status: 403, headers: TEXT });
  const h = new Headers();
  h.set("Access-Control-Allow-Origin", origin);
  h.set("Access-Control-Allow-Methods", ALLOW_METHODS);
  h.set("Access-Control-Allow-Headers", ALLOW_HEADERS);
  h.set("Access-Control-Max-Age", MAX_AGE);
  h.set("Vary", "Origin");
  return new Response(null, { status: 204, headers: h });
}

// ---------- Small utils ----------
const encoder = new TextEncoder();
async function hmacSha256Hex(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function b64urlEncode(jsonObj) {
  const s = JSON.stringify(jsonObj);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64urlDecodeToJson(b64) {
  const s = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(s);
}
function cleanVRM(v) {
  return String(v || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
}
function badRequest(msg) { return new Response(msg, { status: 400, headers: TEXT }); }
function unauthorized(msg) { return new Response(msg, { status: 401, headers: TEXT }); }
function forbidden(msg) { return new Response(msg, { status: 403, headers: TEXT }); }
function serverError(msg) { return new Response(msg, { status: 500, headers: TEXT }); }

// ---------- Anti-spam token (stateless HMAC "JWT-lite") ----------
async function issueToken(env, vrm, lifetimeSeconds = 60) {
  const now = Math.floor(Date.now()/1000);
  const payload = { vrm, iat: now, exp: now + lifetimeSeconds, n: crypto.getRandomValues(new Uint32Array(1))[0] };
  const b64 = b64urlEncode(payload);
  const sig = await hmacSha256Hex(env.ANTISPAM_SECRET || "", b64);
  return `${b64}.${sig}`;
}
async function verifyToken(env, token, vrmExpected) {
  if (!token || token.indexOf(".") < 0) return false;
  const [b64, sig] = token.split(".");
  const calc = await hmacSha256Hex(env.ANTISPAM_SECRET || "", b64);
  if (calc !== sig) return false;
  let payload;
  try { payload = b64urlDecodeToJson(b64); }
  catch { return false; }
  const now = Math.floor(Date.now()/1000);
  if (!payload || typeof payload !== "object") return false;
  if (payload.exp < now) return false;
  if (cleanVRM(payload.vrm) !== cleanVRM(vrmExpected)) return false;
  return true;
}

// ---------- External API calls ----------
async function dvlaVES(env, vrm) {
  // DVLA VES: https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles
  // POST { registrationNumber: "<VRM>" } with header "x-api-key"
  const url = "https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles";
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": env.DVLA_VES_API_KEY
    },
    body: JSON.stringify({ registrationNumber: vrm })
  });
  if (r.status === 404) {
    return { status: 404, data: { info: "Vehicle not found." } };
  }
  if (!r.ok) {
    const t = await r.text().catch(()=> r.statusText);
    return { status: r.status, error: `DVLA error: ${t}` };
  }
  const data = await r.json();
  // Light mapping for front-end fields:
  const mapped = {
    registrationNumber: data.registrationNumber || vrm,
    make: data.make || data.makeModel || data.makeModelCode || "",
    colour: data.colour || data.primaryColour || "",
    fuelType: data.fuelType || data.fuelTypeDescription || "",
    taxStatus: data.taxStatus || data.taxed || "",
    motStatus: data.motStatus || data.mot || ""
  };
  return { status: 200, data: mapped };
}

async function dvsaToken(env) {
  // Client credentials with AAD
  const params = new URLSearchParams();
  params.set("grant_type","client_credentials");
  if (env.DVSA_MOT_SCOPE) params.set("scope", env.DVSA_MOT_SCOPE);
  const r = await fetch(env.DVSA_MOT_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: params.toString(),
    // Basic auth header (AAD also supports client_id+secret in body, but Header is fine):
    // Some tenants require this exact format; fall back to body-only if needed.
  });
  if (!r.ok) {
    const t = await r.text().catch(()=> r.statusText);
    return { error: `DVSA token error: ${t}` };
  }
  const j = await r.json();
  return { access_token: j.access_token, token_type: j.token_type || "Bearer" };
}

async function dvsaMOT(env, vrm) {
  // DVSA TAPI historical tests endpoint often looks like:
  // https://tapi.dvsa.gov.uk/mot/history/vehicle/<VRM>
  // Needs `Authorization: Bearer <token>` and `x-api-key: <key>`
  const tok = await dvsaToken(env);
  if (tok.error || !tok.access_token) return { status: 501, data: { info: "DVSA not configured or token failed." } };

  const url = `https://tapi.dvsa.gov.uk/mot/history/vehicle/${encodeURIComponent(vrm)}`;
  const r = await fetch(url, {
    headers: {
      "authorization": `Bearer ${tok.access_token}`,
      "x-api-key": env.DVSA_MOT_API_KEY
    }
  });
  if (r.status === 404) return { status: 404, data: { info: "No MOT history found." } };
  if (!r.ok) {
    const t = await r.text().catch(()=> r.statusText);
    return { status: r.status, error: `DVSA error: ${t}` };
  }
  const j = await r.json();
  // j should be an array of tests; pass through for front-end rendering
  return { status: 200, data: j };
}

// ---------- Route handlers ----------
async function handleAntiSpam(req, env) {
  // CORS check
  if (!matchOrigin(req, env)) return forbidden("CORS: origin not allowed");
  let body;
  try { body = await req.json(); } catch { return badRequest("Invalid JSON"); }
  const vrm = cleanVRM(body.vrm);
  if (!vrm || vrm.length < 2 || vrm.length > 10) return badRequest("Invalid VRM");
  // issue short-lived token (60s)
  const token = await issueToken(env, vrm, 60);
  return new Response(JSON.stringify({ token }), { status: 200, headers: JSONH });
}

async function requireToken(req, env, vrm) {
  const token = req.headers.get("x-client-token") || "";
  const ok = await verifyToken(env, token, vrm);
  if (!ok) return false;
  return true;
}

async function handleVES(req, env, url) {
  if (!matchOrigin(req, env)) return forbidden("CORS: origin not allowed");
  const vrm = cleanVRM(url.searchParams.get("vrm"));
  if (!vrm) return badRequest("Missing vrm");
  if (!(await requireToken(req, env, vrm))) return unauthorized("Invalid token");

  if (!env.DVLA_VES_API_KEY) return serverError("VES not configured");
  const res = await dvlaVES(env, vrm);
  if (res.error) return serverError(res.error);
  return new Response(JSON.stringify(res.data), { status: res.status, headers: JSONH });
}

async function handleMOT(req, env, url) {
  if (!matchOrigin(req, env)) return forbidden("CORS: origin not allowed");
  const vrm = cleanVRM(url.searchParams.get("vrm"));
  if (!vrm) return badRequest("Missing vrm");
  if (!(await requireToken(req, env, vrm))) return unauthorized("Invalid token");

  if (!env.DVSA_MOT_CLIENT_ID || !env.DVSA_MOT_CLIENT_SECRET || !env.DVSA_MOT_TOKEN_URL || !env.DVSA_MOT_API_KEY) {
    // Graceful: tell frontend DVSA isn't configured yet
    return new Response(JSON.stringify({ info: "DVSA not configured." }), { status: 501, headers: JSONH });
  }
  const res = await dvsaMOT(env, vrm);
  if (res.error) return serverError(res.error);
  return new Response(JSON.stringify(res.data), { status: res.status, headers: JSONH });
}

async function handleDebugOrigin(req, env) {
  const reqOrigin = req.headers.get("origin") || "";
  const allowed = getAllowedOrigins(env);
  return new Response(JSON.stringify({ reqOrigin, allowed }, null, 2), { status: 200, headers: JSONH });
}

// ---------- Worker entry ----------
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      // OPTIONS preflight (CORS)
      if (request.method === "OPTIONS") {
        return preflight(request, env);
      }

      // Routes
      if (url.pathname === "/api/antispam" && request.method === "POST") {
        const res = await handleAntiSpam(request, env);
        return addCors(request, env, res);
      }

      if (url.pathname === "/api/ves" && request.method === "GET") {
        const res = await handleVES(request, env, url);
        return addCors(request, env, res);
      }

      if (url.pathname === "/api/mot/tests" && request.method === "GET") {
        const res = await handleMOT(request, env, url);
        return addCors(request, env, res);
      }

      // Optional debug endpoint
      if (url.pathname === "/__debug/origin") {
        const res = await handleDebugOrigin(request, env);
        return addCors(request, env, res);
      }

      // Health
      if (url.pathname === "/") {
        const res = new Response("MotorScope backend OK", { status: 200, headers: TEXT });
        return addCors(request, env, res);
      }

      return addCors(request, env, new Response("Not found", { status: 404, headers: TEXT }));
    } catch (err) {
      const msg = (err && err.message) ? err.message : String(err);
      return new Response(`Server error: ${msg}`, { status: 500, headers: TEXT });
    }
  }
};

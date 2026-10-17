// Authz Lab · Worker
// - Inicia sesión con OpenID Connect (Authorization Code + PKCE) contra el IAM Lab.
// - Guarda la sesión en una cookie HttpOnly con el id_token, que se valida en cada petición.
// - Expone una API que decide, con el motor de reglas, qué puede hacer cada persona.

import { decide } from "./engine.ts";
import { ACTIONS, KIND_LABELS, RESOURCES, RISKS, ROLES, principalBySub, resourceById, nameOf, type Kind, type Principal, type Risk } from "./model.ts";
import { CONTEXT, LIMITS, PROHIBITIONS, ROLE_GRANTS, type AuthzRequest } from "./policy.ts";

interface Fetcher {
  fetch(request: Request): Promise<Response>;
}
export interface Env {
  ASSETS?: Fetcher;
  IAM?: Fetcher; // service binding al Worker iam-lab
  IAM_ISSUER?: string;
}

const CLIENT_ID = "authz-lab";
const SESSION = "authz_session";
const TX = "authz_tx";

// ---------- utilidades ----------

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64url(bytes: ArrayBuffer | Uint8Array): string {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str: string): Uint8Array {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
const random = (n = 32) => b64url(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (s: string) => b64url(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const now = () => Math.floor(Date.now() / 1000);

function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
}
function redirect(location: string, cookies: string[] = []): Response {
  const h = new Headers({ location, "cache-control": "no-store" });
  for (const c of cookies) h.append("set-cookie", c);
  return new Response(null, { status: 302, headers: h });
}
function cookie(name: string, value: string, maxAge: number): string {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function readCookie(req: Request, name: string): string | null {
  const raw = req.headers.get("cookie") || "";
  for (const part of raw.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i) === name) return part.slice(i + 1);
  }
  return null;
}

// ---------- IAM Lab (proveedor de identidad) ----------

const issuer = (env: Env) => env.IAM_ISSUER || "https://lab.spliter.dev";

function iamFetch(env: Env, path: string, init?: RequestInit): Promise<Response> {
  const req = new Request(issuer(env) + path, init);
  return env.IAM ? env.IAM.fetch(req) : fetch(req);
}

let jwksCache: { key: CryptoKey; kid: string; at: number } | null = null;

async function signingKey(env: Env): Promise<{ key: CryptoKey; kid: string }> {
  if (jwksCache && Date.now() - jwksCache.at < 10 * 60_000) return jwksCache;
  const { keys } = (await (await iamFetch(env, "/as/jwks")).json()) as { keys: JsonWebKey[] & { kid?: string }[] };
  const k = keys[0] as JsonWebKey & { kid: string };
  const key = await crypto.subtle.importKey("jwk", { kty: k.kty, crv: k.crv, x: k.x, y: k.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  jwksCache = { key, kid: k.kid, at: Date.now() };
  return jwksCache;
}

export interface IdClaims {
  iss: string;
  aud: string;
  sub: string;
  exp: number;
  iat: number;
  auth_time?: number;
  amr?: string[];
  nonce?: string;
  name?: string;
  email?: string;
}

async function verifyIdToken(env: Env, token: string, nonce?: string): Promise<IdClaims | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  let header: { alg?: string };
  let claims: IdClaims;
  try {
    header = JSON.parse(dec.decode(b64urlDecode(parts[0])));
    claims = JSON.parse(dec.decode(b64urlDecode(parts[1])));
  } catch {
    return null;
  }
  if (header.alg !== "ES256") return null;
  const { key } = await signingKey(env);
  const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64urlDecode(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`));
  if (!ok) {
    jwksCache = null; // la clave pudo rotar: se recargará en la próxima petición
    return null;
  }
  if (claims.iss !== issuer(env) || claims.aud !== CLIENT_ID || claims.exp < now()) return null;
  if (nonce !== undefined && claims.nonce !== nonce) return null;
  return claims;
}

async function session(req: Request, env: Env): Promise<IdClaims | null> {
  const token = readCookie(req, SESSION);
  return token ? verifyIdToken(env, token) : null;
}

// ---------- flujo de inicio de sesión ----------

async function login(url: URL, env: Env): Promise<Response> {
  const tx = { verifier: random(32), state: random(16), nonce: random(16) };
  const authorize = new URL(issuer(env) + "/as/authorize");
  const params = {
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: `${url.origin}/callback`,
    scope: "openid profile email",
    state: tx.state,
    nonce: tx.nonce,
    code_challenge: await sha256(tx.verifier),
    code_challenge_method: "S256",
  };
  for (const [k, v] of Object.entries(params)) authorize.searchParams.set(k, v);
  return redirect(authorize.toString(), [cookie(TX, b64url(enc.encode(JSON.stringify(tx))), 600)]);
}

async function callback(req: Request, url: URL, env: Env): Promise<Response> {
  const fail = (code: string) => redirect(`/?error=${encodeURIComponent(code)}`, [cookie(TX, "", 0)]);
  if (url.searchParams.get("error")) return fail(url.searchParams.get("error") || "error");
  const rawTx = readCookie(req, TX);
  if (!rawTx) return fail("sin_transaccion");
  let tx: { verifier: string; state: string; nonce: string };
  try {
    tx = JSON.parse(dec.decode(b64urlDecode(rawTx)));
  } catch {
    return fail("sin_transaccion");
  }
  if (url.searchParams.get("state") !== tx.state) return fail("state_invalido");

  const res = await iamFetch(env, "/as/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      code: url.searchParams.get("code") || "",
      redirect_uri: `${url.origin}/callback`,
      code_verifier: tx.verifier,
    }),
  });
  if (!res.ok) return fail("canje_fallido");
  const tokens = (await res.json()) as { id_token: string };
  const claims = await verifyIdToken(env, tokens.id_token, tx.nonce);
  if (!claims) return fail("id_token_invalido");
  return redirect("/", [cookie(SESSION, tokens.id_token, Math.max(0, claims.exp - now())), cookie(TX, "", 0)]);
}

// ---------- API ----------

function contextFrom(claims: IdClaims, managedDevice: boolean) {
  return { mfa: Array.isArray(claims.amr) && claims.amr.includes("mfa"), managedDevice };
}

function describeResource(r: (typeof RESOURCES)[number]) {
  return {
    id: r.id,
    kind: r.kind,
    name: r.name,
    team: r.team ?? null,
    owner: r.owner ? nameOf(r.owner) : null,
    risk: r.risk ?? null,
    level: r.level ?? null,
    requester: r.requester ? nameOf(r.requester) : null,
    description: r.description,
  };
}

function catalog(principal: Principal | undefined, claims: IdClaims, managedDevice: boolean) {
  const ctx = contextFrom(claims, managedDevice);
  const kinds = (Object.keys(KIND_LABELS) as Kind[]).map((kind) => ({
    kind,
    label: KIND_LABELS[kind],
    resources: RESOURCES.filter((r) => r.kind === kind).map((r) => ({
      ...describeResource(r),
      actions: ACTIONS[kind].map((a) => {
        const params = a.param === "role" ? { role: "team_lead" } : a.param === "risk" ? { risk: "bajo" as Risk } : {};
        const allowed = principal ? decide({ principal, resource: r, action: a.id, params, context: ctx }).allowed : false;
        return { id: a.id, label: a.label, param: a.param ?? null, allowed };
      }),
    })),
  }));
  return {
    kinds,
    roles: ROLES.map((r) => ({ id: r.id, name: r.name, level: r.level })),
    risks: RISKS,
    rules: {
      capacidad: Object.entries(ROLE_GRANTS).map(([role, grants]) => ({
        role: ROLES.find((x) => x.id === role)?.name ?? role,
        grants: grants.map((g) => `${g.perm} · ámbito ${g.scope}${g.relation ? ` · relación: ${g.relation.replace(/_/g, " ")}` : ""}`),
      })),
      limite: LIMITS.map((x) => `${x.id} · ${x.text}`),
      contexto: CONTEXT.map((x) => `${x.id} · ${x.text}`),
      prohibicion: PROHIBITIONS.map((x) => `${x.id} · ${x.text}`),
    },
  };
}

async function api(req: Request, url: URL, env: Env): Promise<Response> {
  const claims = await session(req, env);
  if (!claims) return json({ error: "no_session" }, 401);
  const principal = principalBySub(claims.sub);
  const managedDevice = url.searchParams.get("device") === "1";

  if (url.pathname === "/api/me") {
    return json({
      claims: { sub: claims.sub, name: claims.name, email: claims.email, amr: claims.amr ?? [], auth_time: claims.auth_time, exp: claims.exp, iss: claims.iss, aud: claims.aud },
      profile: principal
        ? { name: principal.name, title: principal.title, team: principal.team, roles: principal.roles.map((id) => ROLES.find((r) => r.id === id)?.name ?? id), level: principal.level, maxRisk: principal.maxRisk, manager: principal.manager ? nameOf(principal.manager) : null }
        : null,
    });
  }

  if (url.pathname === "/api/catalog") return json(catalog(principal, claims, managedDevice));

  if (url.pathname === "/api/authorize" && req.method === "POST") {
    let body: { resourceId?: string; action?: string; role?: string; risk?: Risk; managedDevice?: boolean };
    try {
      body = await req.json();
    } catch {
      return json({ error: "invalid_request" }, 400);
    }
    const resource = resourceById(body.resourceId ?? "");
    if (!resource || !ACTIONS[resource.kind].some((a) => a.id === body.action)) return json({ error: "invalid_request" }, 400);
    if (!principal)
      return json({ allowed: false, summary: "No estás en el directorio de la empresa: el IAM Lab sabe quién eres, pero aquí no tienes atributos.", dimensions: [] });
    const request: AuthzRequest = {
      principal,
      resource,
      action: body.action!,
      params: { role: body.role, risk: RISKS.includes(body.risk as Risk) ? body.risk : undefined },
      context: contextFrom(claims, Boolean(body.managedDevice)),
    };
    return json({ request: { who: principal.name, action: body.action, resource: resource.name, params: request.params, context: request.context }, ...decide(request) });
  }
  return json({ error: "not_found" }, 404);
}

// ---------- router ----------

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    try {
      if (url.pathname === "/login") return await login(url, env);
      if (url.pathname === "/callback") return await callback(req, url, env);
      if (url.pathname === "/logout") return redirect("/", [cookie(SESSION, "", 0)]);
      if (url.pathname.startsWith("/api/")) return await api(req, url, env);
      if (env.ASSETS) return env.ASSETS.fetch(req);
      return new Response("Not found", { status: 404 });
    } catch {
      return json({ error: "server_error" }, 500);
    }
  },
};

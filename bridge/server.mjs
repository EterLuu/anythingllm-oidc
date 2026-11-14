// AnythingLLM <-> OIDC (Authelia) 登录桥
//
// 零依赖，Node.js >= 20。
//
// 流程：
//   /sso/oidc/login     -> 302 到 Authelia（authorization code + PKCE）
//   /sso/oidc/callback  -> 换 token，取 userinfo
//                       -> 在 AnythingLLM 中按用户名查找 / 自动创建账号
//                       -> 按 Authelia 组同步角色（admin / manager / default）和工作区
//                       -> 调 AnythingLLM 签发一次性 Simple SSO token
//                       -> 302 到 /sso/simple?token=...，浏览器完成登录
//
// 依赖 AnythingLLM 的 multi-user 模式 + SIMPLE_SSO_ENABLED + 一个开发者 API Key。

import http from "node:http";
import crypto from "node:crypto";

const BASE = "/sso/oidc";
const TX_COOKIE = "llm_oidc_tx";
const TX_TTL_MS = 10 * 60 * 1000;
const HTTP_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------- 配置

const list = (v) =>
  String(v || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

// "组A:ws-1|ws-2,组B:ws-3" -> [["组A", ["ws-1","ws-2"]], ["组B", ["ws-3"]]]
const parseGroupMap = (v) =>
  list(v)
    .map((pair) => {
      const i = pair.lastIndexOf(":");
      if (i <= 0) return null;
      const ws = pair
        .slice(i + 1)
        .split("|")
        .map((s) => s.trim())
        .filter(Boolean);
      return [pair.slice(0, i).trim(), ws];
    })
    .filter((x) => x && x[1].length);

const env = process.env;
const trimSlash = (s) => String(s || "").replace(/\/+$/, "");

const CFG = {
  port: Number(env.PORT || 8080),
  publicUrl: trimSlash(env.PUBLIC_URL),
  issuer: trimSlash(env.OIDC_ISSUER_URL),
  clientId: env.OIDC_CLIENT_ID || "",
  clientSecret: env.OIDC_CLIENT_SECRET || "",
  scopes: env.OIDC_SCOPES || "openid profile email groups",
  usernameClaim: env.OIDC_USERNAME_CLAIM || "preferred_username",
  groupsClaim: env.OIDC_GROUPS_CLAIM || "groups",
  llmUrl: trimSlash(env.ANYTHINGLLM_INTERNAL_URL || "http://anythingllm:3001"),
  llmApiKey: env.ANYTHINGLLM_API_KEY || "",
  secret: env.BRIDGE_SECRET || "",
  allowedGroups: list(env.ALLOWED_GROUPS),
  adminGroups: list(env.ADMIN_GROUPS),
  managerGroups: list(env.MANAGER_GROUPS),
  syncRole: String(env.SYNC_ROLE || "true").toLowerCase() === "true",
  defaultWorkspaces: list(env.DEFAULT_WORKSPACES),
  groupWorkspaces: parseGroupMap(env.GROUP_WORKSPACES),
};

const REQUIRED = {
  PUBLIC_URL: CFG.publicUrl,
  OIDC_ISSUER_URL: CFG.issuer,
  OIDC_CLIENT_ID: CFG.clientId,
  OIDC_CLIENT_SECRET: CFG.clientSecret,
  ANYTHINGLLM_API_KEY: CFG.llmApiKey,
  BRIDGE_SECRET: CFG.secret,
};
const MISSING = Object.entries(REQUIRED)
  .filter(([, v]) => !v)
  .map(([k]) => k);

const REDIRECT_URI = `${CFG.publicUrl}${BASE}/callback`;
const SECURE_COOKIE = CFG.publicUrl.startsWith("https://");
// 只有配置了管理员/经理组时才按组同步角色，避免把现有管理员全降成 default
const ROLE_MANAGED =
  CFG.syncRole && (CFG.adminGroups.length > 0 || CFG.managerGroups.length > 0);

const log = (...a) => console.log(new Date().toISOString(), "[bridge]", ...a);
const warn = (...a) => console.warn(new Date().toISOString(), "[bridge]", ...a);

// ---------------------------------------------------------------- 工具函数

const rand = (n = 32) => crypto.randomBytes(n).toString("base64url");

const hmac = (data) =>
  crypto.createHmac("sha256", CFG.secret).update(data).digest("base64url");

function seal(obj) {
  const p = Buffer.from(JSON.stringify(obj)).toString("base64url");
  return `${p}.${hmac(p)}`;
}

function unseal(value) {
  if (!value || !CFG.secret) return null;
  const [p, s] = String(value).split(".");
  if (!p || !s) return null;
  const expected = Buffer.from(hmac(p));
  const given = Buffer.from(s);
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given))
    return null;
  try {
    const obj = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    if (!obj.exp || obj.exp < Date.now()) return null;
    return obj;
  } catch {
    return null;
  }
}

function parseCookies(header = "") {
  const out = {};
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    try {
      out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
    } catch {
      /* 忽略坏 cookie */
    }
  }
  return out;
}

function txCookie(value, maxAgeSec) {
  return [
    `${TX_COOKIE}=${encodeURIComponent(value)}`,
    `Path=${BASE}`,
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSec}`,
    SECURE_COOKIE ? "Secure" : null,
  ]
    .filter(Boolean)
    .join("; ");
}

// 只允许站内相对路径，防止开放重定向
function safePath(p) {
  if (!p || typeof p !== "string") return null;
  if (!p.startsWith("/") || p.startsWith("//") || p.startsWith("/\\")) return null;
  if (p.length > 512) return null;
  return p;
}

const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
  );

function page(res, status, title, message) {
  if (res.headersSent) return res.end();
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title></head>
<body style="font-family:system-ui,-apple-system,sans-serif;max-width:560px;margin:15vh auto;padding:0 16px;line-height:1.6;color:#222">
<h2 style="margin-bottom:.5em">${esc(title)}</h2><p>${esc(message)}</p>
<p><a href="${BASE}/login">重新登录</a></p></body></html>`);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  res.end();
}

// 用户名转成 AnythingLLM 允许的格式：^[a-z][a-z0-9._@-]*$，2-64 字符
function toLlmUsername(raw) {
  let u = String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._@-]/g, "-");
  if (!u) return null;
  if (!/^[a-z]/.test(u)) u = `u${u}`;
  u = u.slice(0, 64);
  if (u.length < 2) u = u.padEnd(2, "0");
  return u;
}

// 内部占位密码：同时含大小写/数字/符号，满足 PASSWORD* 复杂度设置；用户不会用到它
const randomPassword = () => `${rand(36)}Aa1!`;

const toArray = (v) => (Array.isArray(v) ? v.map(String) : v ? [String(v)] : []);

function roleFor(groups) {
  if (CFG.adminGroups.some((g) => groups.includes(g))) return "admin";
  if (CFG.managerGroups.some((g) => groups.includes(g))) return "manager";
  return "default";
}

// ---------------------------------------------------------------- OIDC

let discoveryCache = null;
async function discovery() {
  if (discoveryCache) return discoveryCache;
  const r = await fetch(`${CFG.issuer}/.well-known/openid-configuration`, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  if (!r.ok) throw new Error(`OIDC discovery 失败: HTTP ${r.status}`);
  const d = await r.json();
  for (const k of ["issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint"])
    if (!d[k]) throw new Error(`OIDC discovery 缺少 ${k}`);
  discoveryCache = d;
  return d;
}

async function exchangeCode(d, code, verifier) {
  const basic = Buffer.from(
    `${encodeURIComponent(CFG.clientId)}:${encodeURIComponent(CFG.clientSecret)}`
  ).toString("base64");
  const r = await fetch(d.token_endpoint, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token || !j.id_token)
    throw new Error(
      `token 交换失败: HTTP ${r.status} ${j.error || ""} ${j.error_description || ""}`.trim()
    );
  return j;
}

function decodeJwtPayload(jwt) {
  const parts = String(jwt).split(".");
  if (parts.length !== 3) throw new Error("id_token 格式错误");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// id_token 是桥直接通过 TLS 从 token 端点拿到的，按 OIDC Core 3.1.3.7 第 6 条，
// 这种情况下可以用 TLS 服务器验证代替签名校验；其余声明仍逐项检查。
function checkIdToken(c, d, nonce) {
  if (c.iss !== d.issuer) throw new Error(`id_token iss 不匹配: ${c.iss}`);
  const aud = toArray(c.aud);
  if (!aud.includes(CFG.clientId)) throw new Error("id_token aud 不包含 client_id");
  if (aud.length > 1 && c.azp && c.azp !== CFG.clientId)
    throw new Error("id_token azp 不匹配");
  if (typeof c.exp !== "number" || c.exp * 1000 < Date.now() - 60_000)
    throw new Error("id_token 已过期");
  if (c.nonce !== nonce) throw new Error("id_token nonce 不匹配");
  if (!c.sub) throw new Error("id_token 缺少 sub");
}

async function fetchUserinfo(d, accessToken) {
  const r = await fetch(d.userinfo_endpoint, {
    headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  if (!r.ok) throw new Error(`userinfo 请求失败: HTTP ${r.status}`);
  return r.json();
}

// ---------------------------------------------------------------- AnythingLLM API

async function llm(method, path, body) {
  const r = await fetch(`${CFG.llmUrl}/api/v1${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${CFG.llmApiKey}`,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  const text = await r.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }
  if (!r.ok) {
    const detail = typeof data === "string" ? data : data?.error || JSON.stringify(data);
    throw new Error(`AnythingLLM ${method} ${path} -> HTTP ${r.status}: ${detail}`);
  }
  return data;
}

async function findUser(username) {
  const { users = [] } = await llm("GET", "/admin/users");
  return users.find((u) => u.username === username) || null;
}

async function syncUser(username, groups) {
  const desiredRole = roleFor(groups);
  let user = await findUser(username);
  let created = false;

  if (!user) {
    try {
      const r = await llm("POST", "/admin/users/new", {
        username,
        password: randomPassword(),
        role: ROLE_MANAGED ? desiredRole : "default",
      });
      user = r.user;
      created = true;
      log(`创建用户 ${username} (id=${user.id}, role=${user.role})`);
    } catch (e) {
      // 同一用户并发首次登录时，另一请求可能已创建成功
      user = await findUser(username);
      if (!user) throw e;
    }
  } else if (ROLE_MANAGED && user.role !== desiredRole) {
    const r = await llm("POST", `/admin/users/${user.id}`, { role: desiredRole });
    if (r.success) {
      log(`用户 ${username} 角色 ${user.role} -> ${desiredRole}`);
      user.role = desiredRole;
    } else {
      warn(`无法修改用户 ${username} 的角色: ${r.error}`);
    }
  }

  // 工作区：新用户加入默认工作区；每次登录按组追加（只增不减）
  const slugs = new Set(created ? CFG.defaultWorkspaces : []);
  for (const [group, wss] of CFG.groupWorkspaces)
    if (groups.includes(group)) wss.forEach((s) => slugs.add(s));
  for (const slug of slugs) {
    try {
      await llm("POST", `/admin/workspaces/${encodeURIComponent(slug)}/manage-users`, {
        userIds: [user.id],
        reset: false,
      });
    } catch (e) {
      warn(`把 ${username} 加入工作区 ${slug} 失败: ${e.message}`);
    }
  }

  return user;
}

// ---------------------------------------------------------------- 路由

async function handleLogin(req, res, url) {
  if (MISSING.length)
    return page(res, 503, "单点登录尚未配置", `缺少配置项：${MISSING.join(", ")}`);

  const d = await discovery();
  const state = rand();
  const nonce = rand();
  const verifier = rand(48);
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");

  const tx = {
    state,
    nonce,
    verifier,
    redirectTo: safePath(url.searchParams.get("redirectTo")),
    exp: Date.now() + TX_TTL_MS,
  };

  const authUrl = new URL(d.authorization_endpoint);
  authUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: CFG.clientId,
    redirect_uri: REDIRECT_URI,
    scope: CFG.scopes,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
  }).toString();

  res.setHeader("Set-Cookie", txCookie(seal(tx), TX_TTL_MS / 1000));
  redirect(res, authUrl.toString());
}

async function handleCallback(req, res, url) {
  const tx = unseal(parseCookies(req.headers.cookie)[TX_COOKIE]);
  res.setHeader("Set-Cookie", txCookie("", 0)); // 一次性

  const err = url.searchParams.get("error");
  if (err)
    return page(res, 401, "登录被拒绝", url.searchParams.get("error_description") || err);

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!tx || !code || !state || tx.state !== state)
    return page(res, 400, "登录会话已失效", "登录链接已过期或无效，请重新登录。");

  const d = await discovery();
  const tokens = await exchangeCode(d, code, tx.verifier);
  const idClaims = decodeJwtPayload(tokens.id_token);
  checkIdToken(idClaims, d, tx.nonce);

  // Authelia 默认只把 groups / preferred_username 等放在 userinfo 里
  const info = await fetchUserinfo(d, tokens.access_token);
  if (info.sub !== idClaims.sub) throw new Error("userinfo sub 与 id_token 不一致");
  const claims = { ...idClaims, ...info };

  const groups = toArray(claims[CFG.groupsClaim]);
  if (CFG.allowedGroups.length && !CFG.allowedGroups.some((g) => groups.includes(g))) {
    log(`拒绝 ${claims[CFG.usernameClaim] || claims.sub}: 不在允许的组中`);
    return page(res, 403, "无权访问", "你的账号不在允许使用 AnythingLLM 的用户组中。");
  }

  const username = toLlmUsername(claims[CFG.usernameClaim] || claims.email);
  if (!username) throw new Error(`userinfo 中没有可用的用户名（${CFG.usernameClaim}）`);

  const user = await syncUser(username, groups);
  if (Number(user.suspended))
    return page(res, 403, "账号已停用", "你的 AnythingLLM 账号已被管理员停用。");

  const issued = await llm("GET", `/users/${user.id}/issue-auth-token`);
  const loginPath =
    issued.loginPath || `/sso/simple?token=${encodeURIComponent(issued.token)}`;
  let target = `${CFG.publicUrl}${loginPath}`;
  if (tx.redirectTo)
    target += `${loginPath.includes("?") ? "&" : "?"}redirectTo=${encodeURIComponent(tx.redirectTo)}`;

  log(`登录 ${username} (id=${user.id}, role=${user.role}, groups=${groups.join("|")})`);
  redirect(res, target);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://bridge.local");
  try {
    if (req.method !== "GET" && req.method !== "HEAD")
      return page(res, 405, "不支持的请求", "");
    switch (url.pathname) {
      case `${BASE}/healthz`:
        res.writeHead(200, { "Content-Type": "text/plain" });
        return res.end("ok");
      case `${BASE}/login`:
        return await handleLogin(req, res, url);
      case `${BASE}/callback`:
        return await handleCallback(req, res, url);
      default:
        return page(res, 404, "页面不存在", "");
    }
  } catch (e) {
    warn(`${url.pathname} 出错:`, e?.message || e);
    if (e?.message?.startsWith("OIDC discovery")) discoveryCache = null;
    page(res, 502, "登录失败", "单点登录过程中出错，请稍后重试。详情见 oidc-bridge 容器日志。");
  }
});

server.listen(CFG.port, () => {
  log(`listening on :${CFG.port}, redirect_uri=${REDIRECT_URI}`);
  if (MISSING.length) warn(`缺少配置: ${MISSING.join(", ")}（登录会返回 503）`);
  if (CFG.secret && CFG.secret.length < 32) warn("BRIDGE_SECRET 太短，建议至少 32 个字符");
  if (CFG.syncRole && !ROLE_MANAGED)
    warn("未配置 ADMIN_GROUPS / MANAGER_GROUPS，角色不会按组同步");
});

for (const sig of ["SIGINT", "SIGTERM"])
  process.on(sig, () => server.close(() => process.exit(0)));

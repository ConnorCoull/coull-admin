/**
 * coull-admin: admin panel for *.coull.ai
 *
 * Routes:
 *   GET  /                           → redirect to /requests
 *   GET  /requests                   → access request management (owner-only)
 *   GET  /feedback                   → feedback viewer (owner-only)
 *   GET  /favicon                    → favicon manager (owner-only)
 *   GET  /api/admin/requests         → JSON list (owner-only)
 *   POST /api/admin/requests/:id/approve
 *   POST /api/admin/requests/:id/decline
 *   POST /api/admin/revoke
 *   POST /api/admin/favicons/:site   → write favicon to KV (owner-only)
 *   DELETE /api/admin/favicons/:site → remove favicon from KV (owner-only)
 *   OPTIONS /api/feedback            → CORS preflight
 *   POST /api/feedback               → submit feedback (session-optional)
 */

import { type Context, Hono } from "hono";
import { validateFeedback } from "./lib/feedback-validate";
import { escapeHtml } from "./lib/html";
import { WIDGET_SOURCE } from "./widget";

type Env = {
    DB: D1Database;
    OWNER_EMAIL: string;
    // Override to http://localhost:8788 in .dev.vars for local development.
    AUTH_URL?: string;
    // Service Binding to coull-auth — avoids same-zone HTTP 522s in production.
    AUTH_SERVICE?: { fetch(request: Request): Promise<Response> };
    PLATFORM_ASSETS: KVNamespace;
};

const app = new Hono<{ Bindings: Env }>();

const FALLBACK_SVG =
    `<svg width="800" height="800" viewBox="0 0 800 800" fill="none" xmlns="http://www.w3.org/2000/svg">` +
    `<path d="M0.999023 550H800V800H250.687L0.999023 550Z" fill="#E6BA42"/>` +
    `<path d="M0.999023 550H800V800H250.687L0.999023 550Z" fill="black" fill-opacity="0.2"/>` +
    `<path d="M0.999023 550H800V800H250.687L0.999023 550Z" fill="black" fill-opacity="0.2"/>` +
    `<path d="M0.994772 550L0 249L249.688 0L249.688 800L0.994772 550Z" fill="#E6BA42"/>` +
    `<path d="M0.994772 550L0 249L249.688 0L249.688 800L0.994772 550Z" fill="black" fill-opacity="0.2"/>` +
    `<path d="M249.753 0H800V250H0.999023L249.753 0Z" fill="#E6BA42"/>` +
    `</svg>`;

app.get("/favicon.svg", async (c) => {
    const lHost = c.req.header("host") ?? "";
    const lSite = c.req.query("site") ?? lHost.split(".")[0];
    let lSvg = FALLBACK_SVG;
    try {
        lSvg =
            (await c.env.PLATFORM_ASSETS.get(`platform_favicon:${lSite}`)) ??
            (await c.env.PLATFORM_ASSETS.get("platform_favicon")) ??
            FALLBACK_SVG;
    } catch {}
    return c.body(lSvg, 200, {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "public, max-age=3600",
    });
});

app.get("/favicon.ico", (c) => c.redirect("/favicon.svg", 302));

// Origins permitted to POST /api/feedback with credentials.
const ALLOWED_ORIGINS = new Set([
    "https://flashcards.coull.ai",
    "https://coull.ai",
    "http://localhost:5173",
    "http://localhost:4321",
]);

// ---------------------------------------------------------------------------
// GET /widget.js — embeddable feedback widget for all coull.ai apps.
// ---------------------------------------------------------------------------

// Inputs: none. Outputs: the widget script with a JS content-type (required
// alongside the nosniff header below) and a short cache so widget updates
// propagate to all apps within minutes without cache-busting.
app.get("/widget.js", (c) =>
    c.body(WIDGET_SOURCE, 200, {
        "Content-Type": "text/javascript; charset=utf-8",
        "Cache-Control": "public, max-age=300",
    }),
);

// ---------------------------------------------------------------------------
// Security headers — applied to every response.
// ---------------------------------------------------------------------------

app.use("*", async (c, next) => {
    await next();
    c.res.headers.set("X-Content-Type-Options", "nosniff");
    c.res.headers.set("X-Frame-Options", "DENY");
    c.res.headers.set("Referrer-Policy", "no-referrer");
    c.res.headers.set(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains",
    );
    c.res.headers.set(
        "Content-Security-Policy",
        [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "object-src 'none'",
            "form-action 'self'",
        ].join("; "),
    );
    c.res.headers.set(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    );
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Inputs: timestamp in Unix ms.
 * Outputs: human-readable date string, e.g. "25 May 2026".
 * Logic: en-GB locale for consistent day-first formatting.
 */
function fmtDate(xits: number): string {
    return new Date(xits).toLocaleDateString("en-GB", {
        day: "numeric",
        month: "short",
        year: "numeric",
    });
}

/**
 * Inputs: Hono context.
 * Outputs: null if caller is the owner; a redirect/403 Response otherwise.
 * Logic: forwards cookie to auth.coull.ai/validate, then checks owner email.
 */
async function requireOwner(
    c: Context<{ Bindings: Env }>,
): Promise<Response | null> {
    const lAuthBase = c.env.AUTH_URL ?? "https://auth.coull.ai";
    const lCookie = c.req.header("cookie") ?? "";
    let lUser: { id: string; email: string; name: string } | null = null;
    try {
        const lReq = new Request("https://auth.coull.ai/validate", {
            headers: { cookie: lCookie },
        });
        const lRes = c.env.AUTH_SERVICE
            ? await c.env.AUTH_SERVICE.fetch(lReq)
            : await fetch(`${lAuthBase}/validate`, {
                  headers: { cookie: lCookie },
                  signal: AbortSignal.timeout(3000),
              });
        if (lRes.ok) {
            lUser = (await lRes.json()) as {
                id: string;
                email: string;
                name: string;
            };
        }
    } catch (_) {}
    if (!lUser) {
        const lReturn = encodeURIComponent(c.req.url);
        return c.redirect(`${lAuthBase}/login?callbackURL=${lReturn}`, 302);
    }
    if (lUser.email !== c.env.OWNER_EMAIL) {
        return c.html(
            `<!DOCTYPE html><html lang="en"><body>
              <h1>403 Forbidden</h1>
            </body></html>`,
            403,
        );
    }
    return null;
}

/**
 * Inputs: origin string from request header.
 * Outputs: CORS headers record, or empty object if origin not allowlisted.
 * Logic: only returns credentialed CORS headers for known *.coull.ai origins.
 */
function corsFor(xiOrigin: string): Record<string, string> {
    if (!ALLOWED_ORIGINS.has(xiOrigin)) return {};
    return {
        "Access-Control-Allow-Origin": xiOrigin,
        "Access-Control-Allow-Credentials": "true",
    };
}

/**
 * Inputs: context, route key, max requests per window, window duration ms.
 * Outputs: true if the request is within the limit, false if exceeded.
 * Logic: upserts a row in ip_rate_limits keyed by CF-Connecting-IP;
 *   resets count when a new time window begins.
 */
async function checkIpRateLimit(
    c: Context<{ Bindings: Env }>,
    xiRouteKey: string,
    xiMax: number,
    xiWindowMs: number,
): Promise<boolean> {
    const lIp = c.req.header("cf-connecting-ip") ?? "unknown";
    const lWindow = Math.floor(Date.now() / xiWindowMs) * xiWindowMs;
    const lRow = await c.env.DB.prepare(
        `INSERT INTO ip_rate_limits (ip, route_key, window_start, count)
         VALUES (?, ?, ?, 1)
         ON CONFLICT (ip, route_key) DO UPDATE SET
           count        = CASE
                            WHEN window_start = excluded.window_start
                            THEN count + 1
                            ELSE 1
                          END,
           window_start = excluded.window_start
         RETURNING count`,
    )
        .bind(lIp, xiRouteKey, lWindow)
        .first<{ count: number }>();
    return (lRow?.count ?? 1) <= xiMax;
}

/**
 * Inputs: active page name for nav highlighting.
 * Outputs: HTML nav string.
 */
function nav(xiActive: "requests" | "feedback" | "favicon"): string {
    const lRActive = xiActive === "requests" ? ' class="active"' : "";
    const lFActive = xiActive === "feedback" ? ' class="active"' : "";
    const lIActive = xiActive === "favicon" ? ' class="active"' : "";
    return `<nav class="nav">
  <a href="/requests"${lRActive}>Requests</a>
  <a href="/feedback"${lFActive}>Feedback</a>
  <a href="/favicon"${lIActive}>Favicons</a>
</nav>`;
}

// Shared CSS injected into every admin page.
const SHARED_STYLES = `
html { height: 100%; }
*, *::before, *::after { box-sizing: border-box; }
body {
  font-family: system-ui, sans-serif;
  margin: 0;
  padding: 2rem;
  background: #f5f5f5;
  color: #111;
  height: 100%;
  display: flex;
  flex-direction: column;
}
.nav { display: flex; gap: 1.25rem; margin-bottom: 1.25rem; flex-shrink: 0; }
.nav a {
  color: #666; text-decoration: none;
  font-size: .9rem; padding-bottom: .2rem;
}
.nav a.active {
  color: #111; font-weight: 600;
  border-bottom: 2px solid #111;
}
.nav a:hover { color: #111; }
h1 { font-size: 1.25rem; margin: 0 0 .75rem; flex-shrink: 0; }
h2 { font-size: 1rem; margin: 0; }
.subtitle { color: #666; font-size: .85rem; margin: 0; }
.search, .filter-select {
  width: 100%; padding: .45rem .75rem;
  border: 1px solid #ddd; border-radius: 6px;
  font-size: .9rem; margin-bottom: .75rem; background: #fff;
}
.search:focus, .filter-select:focus {
  outline: 2px solid #111; border-color: transparent;
}
table {
  width: 100%; border-collapse: collapse;
  background: #fff; border-radius: 8px;
  overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08);
}
th {
  text-align: left; padding: .6rem 1rem;
  font-size: .75rem; text-transform: uppercase;
  letter-spacing: .05em; color: #666; border-bottom: 1px solid #eee;
}
td { padding: .75rem 1rem; border-bottom: 1px solid #f0f0f0; font-size: .9rem; }
tr:last-child td { border-bottom: none; }
.action-btns { display: flex; gap: .4rem; }
.approve-btn, .decline-btn, .revoke-btn {
  padding: .3rem .8rem; border: none;
  border-radius: 4px; font-size: .8rem; cursor: pointer;
}
.approve-btn { background: #111; color: #fff; }
.approve-btn:hover { background: #333; }
.decline-btn { background: #fdecea; color: #c0392b; }
.decline-btn:hover { background: #f5c6c2; }
.revoke-btn { background: #fdecea; color: #c0392b; }
.revoke-btn:hover { background: #f5c6c2; }
.approve-btn:disabled,
.decline-btn:disabled,
.revoke-btn:disabled { opacity: .5; cursor: default; }
.msg-cell { max-width: 300px; word-break: break-word; white-space: pre-wrap; }
/* ── Split-pane layout ── */
.layout {
  display: flex;
  flex-direction: row;
  flex: 1;
  min-height: 0;
  overflow: hidden;
}
.main {
  display: flex;
  flex-direction: column;
  min-width: 0;
  overflow: hidden;
}
.sidebar {
  flex-shrink: 0;
  min-width: 0;
  overflow-y: auto;
  padding-left: 1.25rem;
}
.panel {
  overflow-y: auto;
  min-height: 0;
  padding-bottom: .75rem;
}
.panel-head {
  display: flex;
  align-items: baseline;
  gap: .5rem;
  margin-bottom: .6rem;
  flex-shrink: 0;
}
/* ── Table scroll containment ── */
.table-wrap {
  overflow-x: auto;
  -webkit-overflow-scrolling: touch;
  border-radius: 8px;
}
/* ── Drag handles ── */
.drag-h {
  width: 5px;
  cursor: col-resize;
  background: #ddd;
  flex-shrink: 0;
  transition: background .15s;
}
.drag-v {
  height: 5px;
  cursor: row-resize;
  background: #ddd;
  flex-shrink: 0;
  transition: background .15s;
}
.drag-h:hover, .drag-h.dragging,
.drag-v:hover, .drag-v.dragging { background: #aaa; }
/* ── Mobile: stack, no drag ── */
@media (max-width: 768px) {
  html, body { height: auto; }
  body { display: block; }
  .layout { display: block; overflow: visible; }
  .main { display: block; overflow: visible; }
  .sidebar { padding-left: 0; padding-top: 1.25rem; overflow-y: visible; }
  .panel { overflow-y: visible; min-height: unset; }
  .drag-h, .drag-v { display: none; }
}
@media (max-width: 640px) {
  body { padding: 1rem; }
  td { padding: .55rem .75rem; font-size: .85rem; }
  th { padding: .45rem .75rem; }
  .approve-btn, .decline-btn, .revoke-btn {
    padding: .45rem 1rem; font-size: .82rem;
  }
}
/* ── Favicon manager ── */
.badge {
  display: inline-block; padding: .2rem .5rem;
  border-radius: 4px; font-size: .75rem; font-weight: 500;
}
.badge-custom { background: #e8f5e9; color: #2e7d32; }
.badge-default { background: #f5f5f5; color: #888; }
.edit-area {
  display: flex; gap: 1.25rem;
  align-items: flex-start; padding: .75rem 0;
}
.svg-textarea {
  width: 100%; font-family: monospace; font-size: .8rem;
  border: 1px solid #ddd; border-radius: 6px;
  padding: .5rem; resize: vertical;
}
.svg-textarea:focus { outline: 2px solid #111; border-color: transparent; }
.add-form {
  margin-top: 1.5rem; padding: 1.25rem;
  background: #fff; border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
}
.add-form h2 { font-size: .95rem; margin: 0 0 .75rem; }
.add-form-row { display: flex; gap: 1.25rem; align-items: flex-start; }
.add-form input[type=text] {
  width: 200px; padding: .45rem .75rem;
  border: 1px solid #ddd; border-radius: 6px; font-size: .9rem;
}
.add-form input[type=text]:focus {
  outline: 2px solid #111; border-color: transparent;
}
/* ── Feedback archive ── */
.archive-btn {
  padding: .3rem .8rem; border: none; border-radius: 4px;
  font-size: .8rem; cursor: pointer; background: #f5f5f5; color: #555;
}
.archive-btn:hover { background: #e8e8e8; color: #111; }
.archive-pick { display: flex; align-items: center; gap: .35rem; }
.close-select {
  padding: .25rem .4rem; font-size: .8rem;
  border: 1px solid #ddd; border-radius: 4px; background: #fff;
}
.confirm-archive-btn {
  background: #111; color: #fff; border: none;
  border-radius: 4px; padding: .25rem .5rem;
  cursor: pointer; font-size: .85rem;
}
.confirm-archive-btn:hover { background: #333; }
.cancel-archive-btn {
  background: #f5f5f5; color: #555; border: none;
  border-radius: 4px; padding: .25rem .5rem;
  cursor: pointer; font-size: .85rem;
}
.cancel-archive-btn:hover { background: #e8e8e8; }
.close-badge {
  display: inline-block; padding: .2rem .5rem;
  border-radius: 4px; font-size: .75rem; font-weight: 500;
  background: #f0f0f0; color: #555;
}
.purge-btn {
  padding: .3rem .9rem; border: none; border-radius: 4px;
  font-size: .8rem; cursor: pointer;
  background: #fdecea; color: #c0392b;
}
.purge-btn:hover:not(:disabled) { background: #f5c6c2; }
.purge-btn:disabled { opacity: .5; cursor: default; }
/* ── Email obfuscation ── */
.email-cell {
  display: inline-flex; align-items: center; gap: .35rem;
}
.eye-btn {
  background: none; border: none; cursor: pointer;
  padding: 0; color: #aaa; line-height: 1;
  display: inline-flex; align-items: center; flex-shrink: 0;
}
.eye-btn:hover { color: #111; }
/* ── Favicon picker ── */
.favicon-picker {
  display: flex; gap: .5rem; flex-wrap: wrap;
  margin: .5rem 0; padding: .5rem;
  background: #f9f9f9; border-radius: 6px; border: 1px solid #eee;
  min-height: 60px;
}
.favicon-picker:empty::before {
  content: 'No presets'; color: #bbb; font-size: .8rem; align-self: center;
}
.pick-btn {
  display: inline-flex; flex-direction: column; align-items: center;
  gap: .2rem; padding: .4rem .5rem; border: 2px solid #ddd;
  border-radius: 6px; background: #fff; cursor: pointer;
  font-size: .72rem; color: #555; min-width: 52px;
}
.pick-btn:hover { border-color: #999; background: #f5f5f5; }
.pick-btn.selected { border-color: #111; background: #f0f0f0; }
.pick-btn img { border-radius: 2px; display: block; }
`;

// Inline SVG icons for the email reveal toggle button.
const EYE_SVG =
    `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" ` +
    `viewBox="0 0 24 24" fill="none" stroke="currentColor" ` +
    `stroke-width="2" stroke-linecap="round" stroke-linejoin="round">` +
    `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>` +
    `<circle cx="12" cy="12" r="3"/></svg>`;

/**
 * Inputs: email address string.
 * Outputs: obfuscated version showing first char, ***, and @domain.
 * Logic: hides most of local part to prevent accidental shoulder-surf leakage.
 */
function obfuscateEmail(xiEmail: string): string {
    const lAt = xiEmail.indexOf("@");
    if (lAt < 0) return xiEmail;
    return `${xiEmail[0]}***${xiEmail.slice(lAt)}`;
}

/**
 * Inputs: email address string.
 * Outputs: HTML span with masked email text and an eye-toggle button.
 * Logic: full email stored in data-full; client toggleEmail() handles reveal.
 */
function emailCellHtml(xiEmail: string): string {
    return (
        `<span class="email-cell">` +
        `<span class="email-text">${escapeHtml(obfuscateEmail(xiEmail))}</span>` +
        `<button class="eye-btn" onclick="toggleEmail(this)" ` +
        `data-full="${escapeHtml(xiEmail)}" title="Show email">${EYE_SVG}</button>` +
        `</span>`
    );
}

const KNOWN_SITES = ["coull", "admin", "auth", "flashcards"] as const;

const FAVICON_PRESETS: { label: string; svg: string }[] = [
    {
        label: "Default",
        svg: FALLBACK_SVG,
    },
    {
        label: "Heve Monet",
        svg:
            `<svg width="801" height="800" viewBox="0 0 801 800"` +
            ` fill="none" xmlns="http://www.w3.org/2000/svg">` +
            `<path d="M1 550H801V800H251L1 550Z" fill="#383127"/>` +
            `<path d="M1 550L0 249L251 0L251 800L1 550Z" fill="#6F5129"/>` +
            `<path d="M250.065 0H801V250H1L250.065 0Z" fill="#73422E"/>` +
            `</svg>`,
    },
];

const SITE_RE = /^[a-z0-9-]{1,63}$/;

/**
 * Inputs: raw SVG string submitted by the client.
 * Outputs: trimmed SVG on success; error message on failure.
 * Logic: structural and security checks sufficient for owner-only use.
 */
function validateSvg(
    xiRaw: string,
): { ok: true; svg: string } | { ok: false; error: string } {
    const lSvg = xiRaw.trim();
    if (lSvg.length > 65536)
        return { ok: false, error: "SVG too large (max 64 KB)" };
    if (!/^<svg[\s>]/i.test(lSvg))
        return { ok: false, error: "Must begin with <svg" };
    if (!lSvg.toLowerCase().endsWith("</svg>"))
        return { ok: false, error: "Must end with </svg>" };
    if (/<script/i.test(lSvg))
        return { ok: false, error: "SVG must not contain <script>" };
    if (/javascript:/i.test(lSvg))
        return { ok: false, error: "SVG must not contain javascript:" };
    if (/\bon\w+\s*=/i.test(lSvg))
        return { ok: false, error: "SVG must not contain event handlers" };
    return { ok: true, svg: lSvg };
}

// ---------------------------------------------------------------------------
// GET / — redirect to /requests
// ---------------------------------------------------------------------------

app.get("/", (c) => c.redirect("/requests", 302));

// ---------------------------------------------------------------------------
// GET /requests — owner-gated access request management panel
// ---------------------------------------------------------------------------

app.get("/requests", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lAllRows = await c.env.DB.prepare(
        "SELECT id, email, name, createdAt, approved, declined, message" +
            " FROM access_requests ORDER BY createdAt DESC",
    ).all<{
        id: string;
        email: string;
        name: string;
        createdAt: number;
        approved: number;
        declined: number;
        message: string | null;
    }>();

    const lRequests = lAllRows.results;
    const lPending = lRequests.filter((r) => !r.approved && !r.declined);
    const lDeclined = lRequests.filter((r) => r.declined);

    const lApprovedRows = await c.env.DB.prepare(
        "SELECT ae.email, ar.id, ar.name, ae.addedAt" +
            " FROM allowed_emails ae" +
            " LEFT JOIN access_requests ar" +
            "   ON ar.email = ae.email AND ar.approved = 1" +
            " WHERE ae.email != ?" +
            " ORDER BY ae.addedAt DESC",
    )
        .bind(c.env.OWNER_EMAIL)
        .all<{
            email: string;
            id: string | null;
            name: string | null;
            addedAt: number;
        }>();
    const lApproved = lApprovedRows.results;

    const lPendingHtml =
        lPending.length === 0
            ? `<tr><td colspan="4" style="text-align:center;color:#888;padding:2rem">No pending requests</td></tr>`
            : lPending
                  .map(
                      (r) => `
    <tr>
      <td>${escapeHtml(r.name ?? "—")}</td>
      <td data-full="${escapeHtml(r.email)}">${emailCellHtml(r.email)}</td>
      <td>${fmtDate(r.createdAt)}</td>
      <td class="msg-cell">${r.message ? escapeHtml(r.message) : '<span style="color:#bbb">—</span>'}</td>
      <td><span class="action-btns">
        <button class="approve-btn" data-id="${r.id}" onclick="approve(this)">Approve</button>
        <button class="decline-btn" data-id="${r.id}" onclick="decline(this)">Decline</button>
      </span></td>
    </tr>`,
                  )
                  .join("");

    const lDeclinedHtml =
        lDeclined.length === 0
            ? `<tr class="declined-row"><td colspan="4" style="text-align:center;color:#888;padding:2rem">No declined requests</td></tr>`
            : lDeclined
                  .map(
                      (r) => `
    <tr class="declined-row" data-name="${escapeHtml(r.name?.toLowerCase() ?? "")}" data-email="${escapeHtml(r.email.toLowerCase())}">
      <td>${escapeHtml(r.name ?? "—")}</td>
      <td data-full="${escapeHtml(r.email)}">${emailCellHtml(r.email)}</td>
      <td>${fmtDate(r.createdAt)}</td>
      <td><button class="approve-btn" data-id="${r.id}" onclick="restore(this)">Approve</button></td>
    </tr>`,
                  )
                  .join("");

    const lApprovedHtml =
        lApproved.length === 0
            ? `<tr class="approved-row"><td colspan="3" style="text-align:center;color:#888;padding:2rem">No approved users</td></tr>`
            : lApproved
                  .map(
                      (r) => `
    <tr class="approved-row" data-name="${escapeHtml(r.name?.toLowerCase() ?? "")}" data-email="${escapeHtml(r.email.toLowerCase())}">
      <td>${escapeHtml(r.name ?? "—")}</td>
      <td data-full="${escapeHtml(r.email)}">${emailCellHtml(r.email)}</td>
      <td><button class="revoke-btn" data-email="${escapeHtml(r.email)}" onclick="revoke(this)">Revoke</button></td>
    </tr>`,
                  )
                  .join("");

    return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin — Requests</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>${SHARED_STYLES}</style>
</head>
<body>
${nav("requests")}
<h1>Access Requests</h1>
<div class="layout">

  <div class="main" id="main-panel">
    <div class="panel" id="pending-panel">
      <div class="panel-head">
        <h2>Pending</h2>
        <span class="subtitle" id="pending-count">${lPending.length} pending</span>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Email</th><th>Requested</th><th>Message</th><th>Action</th></tr></thead>
          <tbody id="pending-body">${lPendingHtml}</tbody>
        </table>
      </div>
    </div>

    <div class="drag-v" id="drag-v" title="Drag to resize"></div>

    <div class="panel" id="declined-panel">
      <div class="panel-head">
        <h2>Declined</h2>
        <span class="subtitle" id="declined-count">${lDeclined.length} declined</span>
      </div>
      <input class="search" type="search" placeholder="Search by name or email…"
             oninput="filterDeclined(this.value)" />
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Email</th><th>Requested</th><th>Action</th></tr></thead>
          <tbody id="declined-body">${lDeclinedHtml}</tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="drag-h" id="drag-h" title="Drag to resize"></div>

  <div class="sidebar" id="sidebar-panel">
    <div class="panel-head">
      <h2>Approved</h2>
      <span class="subtitle" id="approved-count">${lApproved.length} users</span>
    </div>
    <input class="search" type="search" placeholder="Search…"
           oninput="filterApproved(this.value)" />
    <div class="table-wrap">
      <table>
        <thead><tr><th>Name</th><th>Email</th><th></th></tr></thead>
        <tbody id="approved-body">${lApprovedHtml}</tbody>
      </table>
    </div>
  </div>

</div>

<script>
  const eyeSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14"' +
    ' viewBox="0 0 24 24" fill="none" stroke="currentColor"' +
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>' +
    '<circle cx="12" cy="12" r="3"/></svg>';
  const eyeOffSvg = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14"' +
    ' viewBox="0 0 24 24" fill="none" stroke="currentColor"' +
    ' stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
    '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8' +
    'a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4' +
    'c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>' +
    '<line x1="1" y1="1" x2="23" y2="23"/></svg>';

  function obfEmail(email) {
    const at = email.indexOf('@');
    return at < 0 ? email : email[0] + '***' + email.slice(at);
  }

  function toggleEmail(btn) {
    const textSpan = btn.previousElementSibling;
    if (btn.dataset.shown) {
      textSpan.textContent = obfEmail(btn.dataset.full);
      btn.innerHTML = eyeSvg;
      btn.title = 'Show email';
      delete btn.dataset.shown;
    } else {
      textSpan.textContent = btn.dataset.full;
      btn.innerHTML = eyeOffSvg;
      btn.title = 'Hide email';
      btn.dataset.shown = '1';
    }
  }

  function makeEmailTd(email) {
    const td = document.createElement('td');
    td.dataset.full = email;
    const wrap = document.createElement('span');
    wrap.className = 'email-cell';
    const text = document.createElement('span');
    text.className = 'email-text';
    text.textContent = obfEmail(email);
    const eyeBtn = document.createElement('button');
    eyeBtn.className = 'eye-btn';
    eyeBtn.title = 'Show email';
    eyeBtn.setAttribute('onclick', 'toggleEmail(this)');
    eyeBtn.dataset.full = email;
    eyeBtn.innerHTML = eyeSvg;
    wrap.appendChild(text);
    wrap.appendChild(eyeBtn);
    td.appendChild(wrap);
    return td;
  }

  function filterDeclined(q) {
    const lQ = q.toLowerCase();
    document.querySelectorAll('#declined-body .declined-row').forEach(row => {
      const lMatch = !lQ ||
        row.dataset.name.includes(lQ) ||
        row.dataset.email.includes(lQ);
      row.style.display = lMatch ? '' : 'none';
    });
  }

  async function approve(btn) {
    const siblings = btn.parentElement.querySelectorAll('button');
    siblings.forEach(b => b.disabled = true);
    btn.textContent = 'Approving…';
    const res = await fetch(
      '/api/admin/requests/' + btn.dataset.id + '/approve',
      { method: 'POST' },
    );
    if (res.ok) {
      btn.closest('tr').remove();
      const el = document.getElementById('pending-count');
      el.textContent =
        Math.max(0, parseInt(el.textContent) - 1) + ' pending';
    } else {
      siblings.forEach(b => b.disabled = false);
      btn.textContent = 'Approve';
    }
  }

  async function decline(btn) {
    const siblings = btn.parentElement.querySelectorAll('button');
    siblings.forEach(b => b.disabled = true);
    btn.textContent = 'Declining…';
    const row = btn.closest('tr');
    const cells = row.querySelectorAll('td');
    const name = cells[0].textContent.trim();
    const email = cells[1].dataset.full || cells[1].textContent.trim();
    const date = cells[2].textContent.trim();
    const id = btn.dataset.id;
    const res = await fetch(
      '/api/admin/requests/' + id + '/decline',
      { method: 'POST' },
    );
    if (res.ok) {
      row.remove();
      const pendingEl = document.getElementById('pending-count');
      pendingEl.textContent =
        Math.max(0, parseInt(pendingEl.textContent) - 1) + ' pending';
      const declinedEl = document.getElementById('declined-count');
      declinedEl.textContent =
        (parseInt(declinedEl.textContent) + 1) + ' declined';
      const tbody = document.getElementById('declined-body');
      const emptyRow = tbody.querySelector('tr:not(.declined-row)');
      if (emptyRow) emptyRow.remove();
      const newRow = document.createElement('tr');
      newRow.className = 'declined-row';
      newRow.dataset.name = name.toLowerCase();
      newRow.dataset.email = email.toLowerCase();
      const tdN = document.createElement('td');
      tdN.textContent = name;
      const tdE = makeEmailTd(email);
      const tdD = document.createElement('td');
      tdD.textContent = date;
      const tdA = document.createElement('td');
      const restoreBtn = document.createElement('button');
      restoreBtn.className = 'approve-btn';
      restoreBtn.dataset.id = id;
      restoreBtn.setAttribute('onclick', 'restore(this)');
      restoreBtn.textContent = 'Approve';
      tdA.appendChild(restoreBtn);
      newRow.appendChild(tdN);
      newRow.appendChild(tdE);
      newRow.appendChild(tdD);
      newRow.appendChild(tdA);
      tbody.insertBefore(newRow, tbody.firstChild);
    } else {
      siblings.forEach(b => b.disabled = false);
      btn.textContent = 'Decline';
    }
  }

  function filterApproved(q) {
    const lQ = q.toLowerCase();
    document.querySelectorAll('#approved-body .approved-row').forEach(row => {
      const lMatch = !lQ ||
        row.dataset.name.includes(lQ) ||
        row.dataset.email.includes(lQ);
      row.style.display = lMatch ? '' : 'none';
    });
  }

  async function revoke(btn) {
    if (!confirm('Revoke access for ' + btn.dataset.email + '?')) return;
    btn.disabled = true;
    btn.textContent = 'Revoking…';
    const res = await fetch('/api/admin/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: btn.dataset.email }),
    });
    if (res.ok) {
      btn.closest('tr').remove();
      const el = document.getElementById('approved-count');
      el.textContent =
        Math.max(0, parseInt(el.textContent) - 1) + ' users';
    } else {
      btn.disabled = false;
      btn.textContent = 'Revoke';
    }
  }

  async function restore(btn) {
    btn.disabled = true;
    btn.textContent = 'Approving…';
    const res = await fetch(
      '/api/admin/requests/' + btn.dataset.id + '/approve',
      { method: 'POST' },
    );
    if (res.ok) {
      btn.closest('tr').remove();
      const el = document.getElementById('declined-count');
      el.textContent =
        Math.max(0, parseInt(el.textContent) - 1) + ' declined';
    } else {
      btn.disabled = false;
      btn.textContent = 'Approve';
    }
  }

  // Drag-to-resize split panes. Sizes persist in localStorage.
  (function () {
    var STORE_KEY = 'admin-layout';
    var MIN = 20, MAX = 80;
    function load() {
      try { return JSON.parse(localStorage.getItem(STORE_KEY)) || {}; }
      catch (_) { return {}; }
    }
    function save(obj) {
      try { localStorage.setItem(STORE_KEY, JSON.stringify(obj)); } catch (_) {}
    }
    var state = load();
    var hPct = Math.min(MAX, Math.max(MIN, state.h || 65));
    var vPct = Math.min(MAX, Math.max(MIN, state.v || 50));
    var layoutEl = document.querySelector('.layout');
    var mainEl = document.getElementById('main-panel');
    var sideEl = document.getElementById('sidebar-panel');
    var pendingEl = document.getElementById('pending-panel');
    var declinedEl = document.getElementById('declined-panel');
    function applyH(pct) {
      mainEl.style.flex = '0 0 ' + pct + '%';
      sideEl.style.flex = '0 0 calc(' + (100 - pct) + '% - 5px)';
    }
    function applyV(pct) {
      pendingEl.style.flex = '0 0 ' + pct + '%';
      declinedEl.style.flex = '0 0 calc(' + (100 - pct) + '% - 5px)';
    }
    applyH(hPct);
    applyV(vPct);
    function makeDraggable(handleId, onDrag) {
      var handle = document.getElementById(handleId);
      if (!handle) return;
      var dragging = false;
      function start(e) {
        dragging = true;
        handle.classList.add('dragging');
        e.preventDefault();
      }
      function move(e) {
        if (!dragging) return;
        var cx = e.touches ? e.touches[0].clientX : e.clientX;
        var cy = e.touches ? e.touches[0].clientY : e.clientY;
        onDrag(cx, cy);
      }
      function end() {
        if (!dragging) return;
        dragging = false;
        handle.classList.remove('dragging');
        save({ h: hPct, v: vPct });
      }
      handle.addEventListener('mousedown', start);
      handle.addEventListener('touchstart', start, { passive: false });
      document.addEventListener('mousemove', move);
      document.addEventListener('touchmove', move, { passive: false });
      document.addEventListener('mouseup', end);
      document.addEventListener('touchend', end);
    }
    makeDraggable('drag-h', function (cx) {
      var r = layoutEl.getBoundingClientRect();
      hPct = Math.min(MAX, Math.max(MIN, ((cx - r.left) / r.width) * 100));
      applyH(hPct);
    });
    makeDraggable('drag-v', function (_cx, cy) {
      var r = mainEl.getBoundingClientRect();
      vPct = Math.min(MAX, Math.max(MIN, ((cy - r.top) / r.height) * 100));
      applyV(vPct);
    });
  })();
</script>
</body>
</html>`);
});

// ---------------------------------------------------------------------------
// GET /favicon — owner-gated favicon manager
// ---------------------------------------------------------------------------

app.get("/favicon", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    // Discover all configured sites from KV and merge with well-known list.
    const lList = await c.env.PLATFORM_ASSETS.list({
        prefix: "platform_favicon:",
    });
    const lCustomSites = lList.keys.map((k) =>
        k.name.slice("platform_favicon:".length),
    );
    const lAllSites = [...new Set([...KNOWN_SITES, ...lCustomSites])];

    // Fetch SVG values only for custom sites.
    const lSvgMap = new Map<string, string>();
    await Promise.all(
        lCustomSites.map(async (lSite) => {
            const lVal = await c.env.PLATFORM_ASSETS.get(
                `platform_favicon:${lSite}`,
            );
            if (lVal) lSvgMap.set(lSite, lVal);
        }),
    );

    const lGlobalSvg = await c.env.PLATFORM_ASSETS.get("platform_favicon");

    const lRowsHtml = lAllSites
        .map((lSite) => {
            const lSvg = lSvgMap.get(lSite);
            const lIsCustom = lSvg !== undefined;
            const lThumbSrc = `/favicon.svg?site=${encodeURIComponent(lSite)}`;
            const lStatusHtml = lIsCustom
                ? `<span class="badge badge-custom">Custom</span>`
                : `<span class="badge badge-default">Default</span>`;
            const lResetBtn = lIsCustom
                ? `<button class="decline-btn"` +
                  ` onclick="resetFavicon('${lSite}',this)">Reset</button>`
                : "";
            return (
                `
    <tr id="row-${lSite}" data-svg="${escapeHtml(lSvg ?? "")}">
      <td>
        <img id="thumb-${lSite}" src="${lThumbSrc}"
             width="32" height="32" alt="">
      </td>
      <td><code>${escapeHtml(lSite)}</code></td>
      <td id="status-${lSite}">${lStatusHtml}</td>
      <td class="action-btns" id="actions-${lSite}">
        <button class="approve-btn"
                onclick="openEdit('${lSite}')">Edit</button>
        ${lResetBtn}
      </td>
    </tr>
    <tr id="edit-${lSite}" style="display:none">
      <td colspan="4">
        <div class="edit-area">
          <div style="flex:1;min-width:0">
            <div class="favicon-picker" id="picker-${lSite}"></div>
            <textarea
              id="svg-input-${lSite}"
              class="svg-textarea"
              rows="4"
              placeholder="Or paste custom SVG…"
              oninput="updatePreview('${lSite}')"
            ></textarea>
            <div style="display:flex;gap:.5rem;margin-top:.5rem">
              <button class="approve-btn"
                      onclick="saveFavicon('${lSite}')">Save</button>
              <button
                style="padding:.3rem .8rem;border:1px solid #ddd;` +
                `border-radius:4px;background:#fff;cursor:pointer;` +
                `font-size:.8rem"
                onclick="closeEdit('${lSite}')">Cancel</button>
            </div>
            <p id="err-${lSite}"
               style="color:#c0392b;font-size:.8rem;margin:.4rem 0 0">
            </p>
          </div>
          <img id="preview-${lSite}" width="80" height="80" alt="Preview"
               style="border:1px solid #eee;border-radius:4px;` +
                `flex-shrink:0;background:#fafafa">
        </div>
      </td>
    </tr>`
            );
        })
        .join("");

    const lGlobalResetBtn = lGlobalSvg
        ? `\n      <button class="decline-btn" onclick="resetDefault(this)">` +
          `Reset to fallback</button>`
        : "";
    const lGlobalStatusHtml = lGlobalSvg
        ? `<span class="badge badge-custom">Custom</span>`
        : `<span class="badge badge-default">Hardcoded fallback</span>`;
    const lDefaultCardHtml =
        `<div class="add-form" style="margin-top:.75rem">` +
        `\n  <h2>Platform default</h2>` +
        `\n  <p style="color:#666;font-size:.85rem;margin:.25rem 0 .75rem">` +
        `\n    Served to any site without a custom entry.` +
        ` Key: <code>platform_favicon</code>` +
        `\n  </p>` +
        `\n  <div style="display:flex;gap:1rem;align-items:center">` +
        `\n    <img id="default-thumb" src="/favicon.svg"` +
        ` width="48" height="48" alt=""` +
        `\n         style="border:1px solid #eee;border-radius:4px;` +
        `background:#fafafa;flex-shrink:0">` +
        `\n    <span id="default-status">${lGlobalStatusHtml}</span>` +
        `\n    <div id="default-actions" class="action-btns">` +
        `\n      <button class="approve-btn"` +
        ` onclick="openDefaultEdit()">Edit</button>${lGlobalResetBtn}` +
        `\n    </div>` +
        `\n  </div>` +
        `\n  <div id="default-edit-area"` +
        ` style="display:none;margin-top:.75rem">` +
        `\n    <div class="edit-area">` +
        `\n      <div style="flex:1;min-width:0">` +
        `\n        <div class="favicon-picker" id="picker-default"></div>` +
        `\n        <textarea id="default-svg-input" class="svg-textarea"` +
        ` rows="4" placeholder="Or paste custom SVG…"` +
        `\n                  oninput="updateDefaultPreview()"></textarea>` +
        `\n        <div style="display:flex;gap:.5rem;margin-top:.5rem">` +
        `\n          <button class="approve-btn"` +
        ` onclick="saveDefault()">Save</button>` +
        `\n          <button style="padding:.3rem .8rem;border:1px solid #ddd;` +
        `border-radius:4px;background:#fff;cursor:pointer;font-size:.8rem"` +
        `\n            onclick="closeDefaultEdit()">Cancel</button>` +
        `\n        </div>` +
        `\n        <p id="default-err"` +
        ` style="color:#c0392b;font-size:.8rem;margin:.4rem 0 0"></p>` +
        `\n      </div>` +
        `\n      <img id="default-preview" width="80" height="80"` +
        ` alt="Preview" style="border:1px solid #eee;border-radius:4px;` +
        `flex-shrink:0;background:#fafafa">` +
        `\n    </div>` +
        `\n  </div>` +
        `\n</div>`;

    return c.html(
        `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin — Favicons</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>${SHARED_STYLES}</style>
</head>
<body>
${nav("favicon")}
<h1>Favicons</h1>
<p class="subtitle">
  Per-site icons served at
  <code>coull.ai/favicon.svg?site=…</code>
</p>
${lDefaultCardHtml}
<div class="table-wrap" style="margin-top:1.5rem;flex:1;overflow-y:auto;min-height:0">
  <table>
    <thead>
      <tr>
        <th>Preview</th><th>Site</th><th>Status</th><th></th>
      </tr>
    </thead>
    <tbody id="favicon-body">${lRowsHtml}</tbody>
  </table>
</div>

<div class="add-form" style="flex-shrink:0">
  <h2>Add site</h2>
  <div class="favicon-picker" id="picker-new"></div>
  <div class="add-form-row" style="margin-top:.5rem">
    <div>
      <input type="text" id="new-site-name"
             placeholder="subdomain" maxlength="63"
             pattern="[a-z0-9\\-]+"
             title="Lowercase letters, digits, hyphens only">
    </div>
    <div style="flex:1;min-width:0">
      <textarea id="new-svg-input" class="svg-textarea" rows="4"
                placeholder="Or paste custom SVG…"
                oninput="updateNewPreview()"></textarea>
    </div>
    <img id="new-preview" width="80" height="80" alt="Preview"
         style="border:1px solid #eee;border-radius:4px;` +
            `flex-shrink:0;background:#fafafa">
  </div>
  <div style="display:flex;gap:.5rem;margin-top:.75rem;align-items:center">
    <button class="approve-btn" onclick="addSite()">Add</button>
    <p id="add-err"
       style="color:#c0392b;font-size:.8rem;margin:0"></p>
  </div>
</div>

<script>
  var KNOWN_SITES = ${JSON.stringify([...KNOWN_SITES])};
  var DEFAULT_STORED_SVG = ${JSON.stringify(lGlobalSvg ?? "")};
  var FAVICON_PRESETS = ${JSON.stringify(
      FAVICON_PRESETS.map((lP) => ({ label: lP.label, svg: lP.svg })),
  )};
  var STORED_FAVICONS = ${JSON.stringify(Object.fromEntries(lSvgMap))};

  var pickerData = {};

  function renderPicker(pickerId, textareaId, kind, kindArg, currentSvg) {
    var options = [];
    FAVICON_PRESETS.forEach(function(p) {
      options.push({ label: p.label, svg: p.svg });
    });
    Object.keys(STORED_FAVICONS).forEach(function(s) {
      if (s === kindArg) return;
      options.push({ label: s, svg: STORED_FAVICONS[s] });
    });
    pickerData[pickerId] = options;
    var html = options.map(function(opt, i) {
      var thumb = 'data:image/svg+xml,' + encodeURIComponent(opt.svg);
      var sel = opt.svg === currentSvg ? ' selected' : '';
      return '<button class="pick-btn' + sel + '"'
        + ' onclick="pickFavicon(\'' + pickerId + '\',\'' + textareaId
        + '\',\'' + kind + '\',\'' + kindArg + '\',' + i + ',this)">'
        + '<img src="' + thumb + '" width="32" height="32" alt="">'
        + '<span>' + opt.label + '</span>'
        + '</button>';
    }).join('');
    document.getElementById(pickerId).innerHTML = html;
  }

  function pickFavicon(pickerId, textareaId, kind, kindArg, idx, btn) {
    var svg = pickerData[pickerId][idx].svg;
    document.getElementById(textareaId).value = svg;
    if (kind === 'site') updatePreview(kindArg);
    else if (kind === 'new') updateNewPreview();
    else updateDefaultPreview();
    document.getElementById(pickerId)
      .querySelectorAll('.pick-btn')
      .forEach(function(b) { b.classList.remove('selected'); });
    btn.classList.add('selected');
  }

  // ── Per-site edit ──────────────────────────────────────────────────────────

  function openEdit(site) {
    var row = document.getElementById('row-' + site);
    var editRow = document.getElementById('edit-' + site);
    var textarea = document.getElementById('svg-input-' + site);
    var currentSvg = row.dataset.svg || '';
    textarea.value = currentSvg;
    updatePreview(site);
    renderPicker('picker-' + site, 'svg-input-' + site, 'site', site, currentSvg);
    editRow.style.display = '';
    textarea.focus();
  }

  function closeEdit(site) {
    document.getElementById('edit-' + site).style.display = 'none';
    document.getElementById('err-' + site).textContent = '';
  }

  function updatePreview(site) {
    var svg = document.getElementById('svg-input-' + site).value.trim();
    document.getElementById('preview-' + site).src = svg
      ? 'data:image/svg+xml,' + encodeURIComponent(svg) : '';
  }

  async function saveFavicon(site) {
    var svg = document.getElementById('svg-input-' + site).value.trim();
    var errEl = document.getElementById('err-' + site);
    errEl.textContent = '';
    var res = await fetch('/api/admin/favicons/' + site, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: svg,
    });
    var data = await res.json();
    if (!res.ok) { errEl.textContent = data.error || 'Save failed'; return; }
    var row = document.getElementById('row-' + site);
    row.dataset.svg = svg;
    document.getElementById('thumb-' + site).src =
      '/favicon.svg?site=' + encodeURIComponent(site) + '&t=' + Date.now();
    document.getElementById('status-' + site).innerHTML =
      '<span class="badge badge-custom">Custom</span>';
    var actionsEl = document.getElementById('actions-' + site);
    if (!actionsEl.querySelector('.decline-btn')) {
      var btn = document.createElement('button');
      btn.className = 'decline-btn';
      btn.setAttribute('onclick', "resetFavicon('" + site + "',this)");
      btn.textContent = 'Reset';
      actionsEl.appendChild(btn);
    }
    closeEdit(site);
  }

  async function resetFavicon(site, btn) {
    if (!confirm('Reset ' + site + ' to the default favicon?')) return;
    btn.disabled = true;
    var res = await fetch('/api/admin/favicons/' + site, { method: 'DELETE' });
    if (!res.ok) { btn.disabled = false; return; }
    if (KNOWN_SITES.indexOf(site) === -1) {
      document.getElementById('row-' + site).remove();
      document.getElementById('edit-' + site).remove();
      return;
    }
    var row = document.getElementById('row-' + site);
    row.dataset.svg = '';
    document.getElementById('thumb-' + site).src =
      '/favicon.svg?site=' + encodeURIComponent(site) + '&t=' + Date.now();
    document.getElementById('status-' + site).innerHTML =
      '<span class="badge badge-default">Default</span>';
    btn.remove();
  }

  function updateNewPreview() {
    var svg = document.getElementById('new-svg-input').value.trim();
    document.getElementById('new-preview').src = svg
      ? 'data:image/svg+xml,' + encodeURIComponent(svg) : '';
  }

  async function addSite() {
    var site = document.getElementById('new-site-name')
      .value.trim().toLowerCase();
    var svg = document.getElementById('new-svg-input').value.trim();
    var errEl = document.getElementById('add-err');
    errEl.textContent = '';
    if (!/^[a-z0-9-]{1,63}$/.test(site)) {
      errEl.textContent =
        'Invalid name — lowercase letters, digits, hyphens, 1-63 chars';
      return;
    }
    if (!svg) { errEl.textContent = 'SVG is required'; return; }
    var res = await fetch('/api/admin/favicons/' + site, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: svg,
    });
    var data = await res.json();
    if (!res.ok) { errEl.textContent = data.error || 'Save failed'; return; }
    window.location.reload();
  }

  // ── Platform default ───────────────────────────────────────────────────────

  function openDefaultEdit() {
    var ta = document.getElementById('default-svg-input');
    ta.value = DEFAULT_STORED_SVG;
    updateDefaultPreview();
    renderPicker(
      'picker-default', 'default-svg-input', 'default', '',
      DEFAULT_STORED_SVG
    );
    document.getElementById('default-edit-area').style.display = '';
    ta.focus();
  }

  function closeDefaultEdit() {
    document.getElementById('default-edit-area').style.display = 'none';
    document.getElementById('default-err').textContent = '';
  }

  function updateDefaultPreview() {
    var svg = document.getElementById('default-svg-input').value.trim();
    document.getElementById('default-preview').src = svg
      ? 'data:image/svg+xml,' + encodeURIComponent(svg) : '';
  }

  async function saveDefault() {
    var svg = document.getElementById('default-svg-input').value.trim();
    var errEl = document.getElementById('default-err');
    errEl.textContent = '';
    var res = await fetch('/api/admin/favicon/default', {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: svg,
    });
    var data = await res.json();
    if (!res.ok) { errEl.textContent = data.error || 'Save failed'; return; }
    DEFAULT_STORED_SVG = svg;
    var t = Date.now();
    document.getElementById('default-thumb').src = '/favicon.svg?t=' + t;
    document.getElementById('default-status').innerHTML =
      '<span class="badge badge-custom">Custom</span>';
    var actEl = document.getElementById('default-actions');
    if (!actEl.querySelector('.decline-btn')) {
      var btn = document.createElement('button');
      btn.className = 'decline-btn';
      btn.setAttribute('onclick', 'resetDefault(this)');
      btn.textContent = 'Reset to fallback';
      actEl.appendChild(btn);
    }
    document.querySelectorAll('[id^="thumb-"]').forEach(function(img) {
      var site = img.id.slice('thumb-'.length);
      var row = document.getElementById('row-' + site);
      if (row && !row.dataset.svg)
        img.src = '/favicon.svg?site=' + encodeURIComponent(site) + '&t=' + t;
    });
    closeDefaultEdit();
  }

  async function resetDefault(btn) {
    if (!confirm('Reset platform default to the hardcoded fallback?')) return;
    btn.disabled = true;
    var res = await fetch('/api/admin/favicon/default', { method: 'DELETE' });
    if (!res.ok) { btn.disabled = false; return; }
    window.location.reload();
  }

  renderPicker('picker-new', 'new-svg-input', 'new', '', '');
</script>
</body>
</html>`,
    );
});

// ---------------------------------------------------------------------------
// POST /api/admin/favicons/:site — write a favicon SVG to KV (owner-only)
// ---------------------------------------------------------------------------

app.post("/api/admin/favicons/:site", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lSite = c.req.param("site");
    if (!SITE_RE.test(lSite))
        return c.json({ error: "Invalid site name" }, 400);

    const lRaw = await c.req.text();
    const lResult = validateSvg(lRaw);
    if (!lResult.ok) return c.json({ error: lResult.error }, 400);

    await c.env.PLATFORM_ASSETS.put(`platform_favicon:${lSite}`, lResult.svg);
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// DELETE /api/admin/favicons/:site — remove a favicon from KV (owner-only)
// ---------------------------------------------------------------------------

app.delete("/api/admin/favicons/:site", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lSite = c.req.param("site");
    if (!SITE_RE.test(lSite))
        return c.json({ error: "Invalid site name" }, 400);

    await c.env.PLATFORM_ASSETS.delete(`platform_favicon:${lSite}`);
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// POST /api/admin/favicon/default — write the global platform_favicon key
// ---------------------------------------------------------------------------

app.post("/api/admin/favicon/default", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lRaw = await c.req.text();
    const lResult = validateSvg(lRaw);
    if (!lResult.ok) return c.json({ error: lResult.error }, 400);

    await c.env.PLATFORM_ASSETS.put("platform_favicon", lResult.svg);
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// DELETE /api/admin/favicon/default — remove the global platform_favicon key
// ---------------------------------------------------------------------------

app.delete("/api/admin/favicon/default", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    await c.env.PLATFORM_ASSETS.delete("platform_favicon");
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// GET /api/admin/requests — JSON list of all access requests (owner-only)
// ---------------------------------------------------------------------------

app.get("/api/admin/requests", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;
    const lRows = await c.env.DB.prepare(
        "SELECT id, email, name, createdAt, approved, declined, message" +
            " FROM access_requests ORDER BY createdAt DESC",
    ).all();
    return c.json(lRows.results);
});

// ---------------------------------------------------------------------------
// POST /api/admin/requests/:id/approve — approve a request (owner-only)
// ---------------------------------------------------------------------------

app.post("/api/admin/requests/:id/approve", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;
    const lId = c.req.param("id");
    const lRequest = await c.env.DB.prepare(
        "SELECT email FROM access_requests WHERE id = ?",
    )
        .bind(lId)
        .first<{ email: string }>();
    if (!lRequest) return c.json({ error: "Not found" }, 404);
    await c.env.DB.batch([
        c.env.DB.prepare(
            "INSERT OR IGNORE INTO allowed_emails (email) VALUES (?)",
        ).bind(lRequest.email),
        c.env.DB.prepare(
            "UPDATE access_requests SET approved = 1, declined = 0" +
                " WHERE id = ?",
        ).bind(lId),
    ]);
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// POST /api/admin/requests/:id/decline — decline a request (owner-only)
// ---------------------------------------------------------------------------

app.post("/api/admin/requests/:id/decline", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;
    const lId = c.req.param("id");
    const lResult = await c.env.DB.prepare(
        "UPDATE access_requests SET declined = 1 WHERE id = ?",
    )
        .bind(lId)
        .run();
    if (!lResult.meta.changes) return c.json({ error: "Not found" }, 404);
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// POST /api/admin/revoke — revoke a user's access (owner-only)
// ---------------------------------------------------------------------------

app.post("/api/admin/revoke", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;
    const lRevokeBody = await c.req.json<{ email: unknown }>();
    if (typeof lRevokeBody?.email !== "string" || !lRevokeBody.email) {
        return c.json({ error: "email required" }, 400);
    }
    const email = lRevokeBody.email;
    const lUser = await c.env.DB.prepare("SELECT id FROM user WHERE email = ?")
        .bind(email)
        .first<{ id: string }>();
    await c.env.DB.batch([
        c.env.DB.prepare("DELETE FROM allowed_emails WHERE email = ?").bind(
            email,
        ),
        ...(lUser
            ? [c.env.DB.prepare("DELETE FROM user WHERE id = ?").bind(lUser.id)]
            : []),
        c.env.DB.prepare(
            "UPDATE access_requests SET approved = 0 WHERE email = ?",
        ).bind(email),
    ]);
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// GET /feedback — owner-gated feedback submissions viewer
// ---------------------------------------------------------------------------

const CLOSE_REASONS = new Set([
    "spam",
    "fixed",
    "not-going-to-fix",
    "made-ticket",
]);

app.get("/feedback", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lActiveRows = await c.env.DB.prepare(
        "SELECT id, user_email, user_name, app_name, page_url," +
            " message, reason, created_at" +
            " FROM feedback WHERE archived_at IS NULL ORDER BY created_at DESC",
    ).all<{
        id: string;
        user_email: string | null;
        user_name: string | null;
        app_name: string;
        page_url: string;
        message: string;
        reason: string | null;
        created_at: number;
    }>();

    const lArchivedRows = await c.env.DB.prepare(
        "SELECT id, user_email, user_name, app_name, page_url," +
            " message, reason, created_at, close_reason" +
            " FROM feedback WHERE archived_at IS NOT NULL" +
            " ORDER BY archived_at DESC",
    ).all<{
        id: string;
        user_email: string | null;
        user_name: string | null;
        app_name: string;
        page_url: string;
        message: string;
        reason: string | null;
        created_at: number;
        close_reason: string | null;
    }>();

    const lActive = lActiveRows.results;
    const lArchived = lArchivedRows.results;

    const lAppNames = [...new Set(lActive.map((r) => r.app_name))];
    const lAppOptions = lAppNames
        .map(
            (a) => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`,
        )
        .join("");

    const lReasons = [
        ...new Set(
            lActive.map((r) => r.reason).filter((r): r is string => r !== null),
        ),
    ];
    const lReasonOptions = lReasons
        .map(
            (r) => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`,
        )
        .join("");

    /**
     * Inputs: feedback row object.
     * Outputs: HTML string for a user cell (name + obfuscated email or anon).
     * Logic: shared between active and archived row renderers.
     */
    function userCellHtml(r: {
        user_email: string | null;
        user_name: string | null;
    }): string {
        return r.user_email
            ? `${escapeHtml(r.user_name ?? "—")}<br>` +
                  `<span style="color:#888;font-size:.8rem">` +
                  emailCellHtml(r.user_email) +
                  `</span>`
            : `<span style="color:#aaa">anonymous</span>`;
    }

    const lFeedbackHtml =
        lActive.length === 0
            ? `<tr><td colspan="7" style="text-align:center;color:#888;padding:2rem">No feedback yet</td></tr>`
            : lActive
                  .map((r) => {
                      const lPageDisplay =
                          r.page_url.length > 50
                              ? `${r.page_url.slice(0, 50)}…`
                              : r.page_url;
                      const lReasonCell = r.reason
                          ? escapeHtml(r.reason)
                          : `<span style="color:#bbb">—</span>`;
                      return `
    <tr class="feedback-row" data-app="${escapeHtml(r.app_name)}" data-reason="${escapeHtml(r.reason ?? "")}" data-id="${escapeHtml(r.id)}">
      <td style="white-space:nowrap">${fmtDate(r.created_at)}</td>
      <td><code>${escapeHtml(r.app_name)}</code></td>
      <td>${lReasonCell}</td>
      <td>${userCellHtml(r)}</td>
      <td title="${escapeHtml(r.page_url)}" style="font-size:.8rem;color:#555">${escapeHtml(lPageDisplay)}</td>
      <td class="msg-cell">${escapeHtml(r.message)}</td>
      <td><button class="archive-btn" onclick="archiveRow(this)">Archive</button></td>
    </tr>`;
                  })
                  .join("");

    const lArchivedHtml =
        lArchived.length === 0
            ? `<tr class="archived-empty"><td colspan="7" style="text-align:center;color:#888;padding:2rem">No archived items</td></tr>`
            : lArchived
                  .map((r) => {
                      const lPageDisplay =
                          r.page_url.length > 50
                              ? `${r.page_url.slice(0, 50)}…`
                              : r.page_url;
                      const lReasonCell = r.reason
                          ? escapeHtml(r.reason)
                          : `<span style="color:#bbb">—</span>`;
                      const lCloseBadge = r.close_reason
                          ? `<span class="close-badge">${escapeHtml(r.close_reason)}</span>`
                          : `<span style="color:#bbb">—</span>`;
                      return `
    <tr class="archived-row">
      <td style="white-space:nowrap">${fmtDate(r.created_at)}</td>
      <td><code>${escapeHtml(r.app_name)}</code></td>
      <td>${lReasonCell}</td>
      <td>${userCellHtml(r)}</td>
      <td title="${escapeHtml(r.page_url)}" style="font-size:.8rem;color:#555">${escapeHtml(lPageDisplay)}</td>
      <td class="msg-cell">${escapeHtml(r.message)}</td>
      <td>${lCloseBadge}</td>
    </tr>`;
                  })
                  .join("");

    return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin — Feedback</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>${SHARED_STYLES}</style>
</head>
<body>
${nav("feedback")}
<h1>Feedback</h1>
<p class="subtitle" id="active-count">${lActive.length} submissions</p>
<select id="app-filter" class="filter-select" oninput="applyFilters()" style="max-width:200px">
  <option value="">All apps</option>
  ${lAppOptions}
</select>
<select id="reason-filter" class="filter-select" oninput="applyFilters()" style="max-width:200px">
  <option value="">All reasons</option>
  ${lReasonOptions}
</select>
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Date</th><th>App</th><th>Category</th><th>User</th><th>Page</th><th>Message</th><th></th>
      </tr>
    </thead>
    <tbody id="feedback-body">${lFeedbackHtml}</tbody>
  </table>
</div>

<div style="margin-top:2rem">
  <div class="panel-head" style="justify-content:space-between;margin-bottom:.6rem">
    <div style="display:flex;align-items:baseline;gap:.5rem">
      <h2>Archived</h2>
      <span class="subtitle" id="archived-count">${lArchived.length} items</span>
    </div>
    <button id="purge-btn" class="purge-btn" onclick="purgeArchived()"${lArchived.length === 0 ? " disabled" : ""}>Delete all</button>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Date</th><th>App</th><th>Category</th><th>User</th><th>Page</th><th>Message</th><th>Close</th>
        </tr>
      </thead>
      <tbody id="archived-body">${lArchivedHtml}</tbody>
    </table>
  </div>
</div>

<script>
  function applyFilters() {
    const app = document.getElementById('app-filter').value;
    const reason = document.getElementById('reason-filter').value;
    document.querySelectorAll('.feedback-row').forEach(row => {
      const show = (!app || row.dataset.app === app)
        && (!reason || row.dataset.reason === reason);
      row.style.display = show ? '' : 'none';
    });
  }

  function archiveRow(btn) {
    const td = btn.parentElement;
    td.innerHTML =
      '<div class="archive-pick">' +
        '<select class="close-select">' +
          '<option value="spam">Spam</option>' +
          '<option value="fixed">Fixed</option>' +
          '<option value="not-going-to-fix">Not going to fix</option>' +
          '<option value="made-ticket">Made ticket</option>' +
        '</select>' +
        '<button class="confirm-archive-btn" onclick="confirmArchive(this)">✓</button>' +
        '<button class="cancel-archive-btn" onclick="cancelArchive(this)">✗</button>' +
      '</div>';
  }

  function cancelArchive(btn) {
    const td = btn.closest('td');
    td.innerHTML = '<button class="archive-btn" onclick="archiveRow(this)">Archive</button>';
  }

  async function confirmArchive(btn) {
    const pick = btn.closest('.archive-pick');
    const closeReason = pick.querySelector('.close-select').value;
    const row = pick.closest('tr');
    const id = row.dataset.id;

    pick.querySelectorAll('button').forEach(b => b.disabled = true);

    const res = await fetch('/api/admin/feedback/' + id + '/archive', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ closeReason }),
    });

    if (!res.ok) {
      pick.querySelectorAll('button').forEach(b => b.disabled = false);
      return;
    }

    // Move row to archived section.
    const actionTd = pick.closest('td');
    const badge = '<span class="close-badge">' + closeReason + '</span>';
    actionTd.innerHTML = badge;
    row.classList.remove('feedback-row');
    row.classList.add('archived-row');
    delete row.dataset.id;

    const archivedBody = document.getElementById('archived-body');
    const emptyRow = archivedBody.querySelector('.archived-empty');
    if (emptyRow) emptyRow.remove();
    archivedBody.insertBefore(row, archivedBody.firstChild);

    const activeEl = document.getElementById('active-count');
    const lActiveN = Math.max(0, parseInt(activeEl.textContent) - 1);
    activeEl.textContent = lActiveN + ' submissions';

    const archivedEl = document.getElementById('archived-count');
    archivedEl.textContent = (parseInt(archivedEl.textContent) + 1) + ' items';

    document.getElementById('purge-btn').disabled = false;
  }

  async function purgeArchived() {
    const count = parseInt(document.getElementById('archived-count').textContent);
    if (!count || !confirm('Permanently delete ' + count + ' archived items?')) return;
    const btn = document.getElementById('purge-btn');
    btn.disabled = true;
    btn.textContent = 'Deleting…';
    const res = await fetch('/api/admin/feedback/archived', { method: 'DELETE' });
    if (res.ok) {
      const tbody = document.getElementById('archived-body');
      tbody.innerHTML =
        '<tr class="archived-empty"><td colspan="7"' +
        ' style="text-align:center;color:#888;padding:2rem">No archived items</td></tr>';
      document.getElementById('archived-count').textContent = '0 items';
      btn.textContent = 'Delete all';
    } else {
      btn.disabled = false;
      btn.textContent = 'Delete all';
    }
  }
</script>
</body>
</html>`);
});

// ---------------------------------------------------------------------------
// POST /api/admin/feedback/:id/archive — soft-archive a feedback row
// ---------------------------------------------------------------------------

app.post("/api/admin/feedback/:id/archive", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lId = c.req.param("id");
    let lBody: { closeReason?: unknown };
    try {
        lBody = await c.req.json();
    } catch (_) {
        return c.json({ error: "Invalid JSON" }, 400);
    }

    if (
        typeof lBody?.closeReason !== "string" ||
        !CLOSE_REASONS.has(lBody.closeReason)
    ) {
        return c.json({ error: "invalid closeReason" }, 400);
    }

    const lResult = await c.env.DB.prepare(
        "UPDATE feedback SET archived_at = ?, close_reason = ?" +
            " WHERE id = ? AND archived_at IS NULL",
    )
        .bind(Date.now(), lBody.closeReason, lId)
        .run();

    if (!lResult.meta.changes) {
        return c.json({ error: "not found or already archived" }, 404);
    }
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// DELETE /api/admin/feedback/archived — permanently purge all archived rows
// ---------------------------------------------------------------------------

app.delete("/api/admin/feedback/archived", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lResult = await c.env.DB.prepare(
        "DELETE FROM feedback WHERE archived_at IS NOT NULL",
    ).run();

    return c.json({ ok: true, deleted: lResult.meta.changes });
});

// ---------------------------------------------------------------------------
// OPTIONS /api/feedback — CORS preflight for cross-origin submissions
// ---------------------------------------------------------------------------

app.options("/api/feedback", (c) => {
    const lOrigin = c.req.header("origin") ?? "";
    if (!ALLOWED_ORIGINS.has(lOrigin)) return c.text("", 403);
    return new Response(null, {
        status: 204,
        headers: {
            "Access-Control-Allow-Origin": lOrigin,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Max-Age": "86400",
        },
    });
});

// ---------------------------------------------------------------------------
// POST /api/feedback — submit feedback (session attempted; anonymous fallback)
// ---------------------------------------------------------------------------

app.post("/api/feedback", async (c) => {
    const lOrigin = c.req.header("origin") ?? "";
    const lCors = corsFor(lOrigin);

    const lRateOk = await checkIpRateLimit(c, "feedback", 10, 60_000);
    if (!lRateOk) {
        return c.json({ error: "Rate limit exceeded" }, 429, lCors);
    }

    // Attempt session validation — records as anonymous if no valid session.
    const lAuthBase = c.env.AUTH_URL ?? "https://auth.coull.ai";
    let lUser: { id: string; email: string; name: string } | null = null;
    const lCookie = c.req.header("cookie") ?? "";
    if (lCookie) {
        try {
            const lReq = new Request("https://auth.coull.ai/validate", {
                headers: { cookie: lCookie },
            });
            const lAuthRes = c.env.AUTH_SERVICE
                ? await c.env.AUTH_SERVICE.fetch(lReq)
                : await fetch(`${lAuthBase}/validate`, {
                      headers: { cookie: lCookie },
                      signal: AbortSignal.timeout(3000),
                  });
            if (lAuthRes.ok) {
                lUser = (await lAuthRes.json()) as {
                    id: string;
                    email: string;
                    name: string;
                };
            }
        } catch (_) {}
    }

    let lBody: {
        message?: string;
        appName?: string;
        pageUrl?: string;
        reason?: string;
    };
    try {
        lBody = await c.req.json();
    } catch (_) {
        return c.json({ error: "Invalid JSON" }, 400, lCors);
    }

    const lChecked = validateFeedback(lBody);
    if (!lChecked.ok) {
        return c.json({ error: lChecked.error }, 400, lCors);
    }
    const lFields = lChecked.fields;

    const lId = crypto.randomUUID();
    await c.env.DB.prepare(
        "INSERT INTO feedback" +
            " (id, user_id, user_email, user_name, app_name, page_url," +
            "  message, reason, created_at)" +
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
        .bind(
            lId,
            lUser?.id ?? null,
            lUser?.email ?? null,
            lUser?.name ?? null,
            lFields.appName,
            lFields.pageUrl,
            lFields.message,
            lFields.reason,
            Date.now(),
        )
        .run();

    return c.json({ ok: true }, 200, lCors);
});

export default app;

/**
 * coull-admin: admin panel for *.coull.ai
 *
 * Routes:
 *   GET  /                               → redirect to /requests
 *   GET  /requests                       → access request management (owner-only)
 *   GET  /feedback                       → feedback viewer (owner-only)
 *   GET  /favicon                        → favicon manager (owner-only)
 *   GET  /cv                             → CV upload (owner-only)
 *   GET  /content                        → reading + recommendations manager (owner-only)
 *   GET  /api/admin/requests             → JSON list (owner-only)
 *   POST /api/admin/requests/:id/approve
 *   POST /api/admin/requests/:id/decline
 *   POST /api/admin/revoke
 *   POST /api/admin/favicons/:site       → write favicon to KV (owner-only)
 *   DELETE /api/admin/favicons/:site     → remove favicon from KV (owner-only)
 *   POST /api/admin/reading              → add reading paper (owner-only)
 *   DELETE /api/admin/reading/:id        → remove reading paper (owner-only)
 *   POST /api/admin/recommendations      → add recommendation (owner-only)
 *   PUT  /api/admin/recommendations/:id  → edit recommendation (owner-only)
 *   DELETE /api/admin/recommendations/:id
 *   OPTIONS /api/feedback                → CORS preflight
 *   POST /api/feedback                   → submit feedback (session-optional)
 *
 * Banner (platform-wide announcement strip):
 *   GET  /banner                         → banner manager page (owner-only)
 *   GET  /banner.js                      → embeddable banner widget (public)
 *   GET  /api/banner                     → resolved banner config (public, CORS)
 *   PUT  /api/admin/banner/global        → set global banner (owner-only)
 *   PUT  /api/admin/banner/:site         → set per-site banner (owner-only)
 *   DELETE /api/admin/banner/:site       → clear per-site banner (owner-only)
 */

import { type Context, Hono } from "hono";
import { BANNER_SOURCE } from "./banner";
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
    CV_BUCKET: R2Bucket;
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

// GET /banner.js — embeddable platform banner for all coull.ai apps.
// ---------------------------------------------------------------------------

// Inputs: none. Outputs: the banner script with a JS content-type and a
// short cache so banner updates propagate to all apps within minutes.
app.get("/banner.js", (c) =>
    c.body(BANNER_SOURCE, 200, {
        "Content-Type": "text/javascript; charset=utf-8",
        "Cache-Control": "public, max-age=300",
    }),
);

// GET /api/banner — resolved banner config for the embedding widget.
// ---------------------------------------------------------------------------

// Inputs: ?site=<site-key> query param. Outputs: JSON { enabled, message }.
// Logic: global config (platform_banner) wins when enabled; falls back to
// per-site config (platform_banner:<site>); otherwise returns enabled:false.
// Public — no auth required. CORS header added so cross-origin widgets can
// read the response. Short cache so toggle changes propagate within ~1 min.
app.get("/api/banner", async (c) => {
    const lSite = (c.req.query("site") ?? "").trim().toLowerCase();

    const lGlobalRaw = await c.env.PLATFORM_ASSETS.get("platform_banner");
    if (lGlobalRaw) {
        let lGlobal: { enabled?: boolean; message?: string } = {};
        try {
            lGlobal = JSON.parse(lGlobalRaw);
        } catch (_) {}
        if (lGlobal.enabled && lGlobal.message) {
            return c.json({ enabled: true, message: lGlobal.message }, 200, {
                "Cache-Control": "public, max-age=60",
                "Access-Control-Allow-Origin": "*",
            });
        }
    }

    if (lSite) {
        const lSiteRaw = await c.env.PLATFORM_ASSETS.get(
            `platform_banner:${lSite}`,
        );
        if (lSiteRaw) {
            let lSiteConf: { enabled?: boolean; message?: string } = {};
            try {
                lSiteConf = JSON.parse(lSiteRaw);
            } catch (_) {}
            if (lSiteConf.enabled && lSiteConf.message) {
                return c.json(
                    { enabled: true, message: lSiteConf.message },
                    200,
                    {
                        "Cache-Control": "public, max-age=60",
                        "Access-Control-Allow-Origin": "*",
                    },
                );
            }
        }
    }

    return c.json({ enabled: false }, 200, {
        "Cache-Control": "public, max-age=60",
        "Access-Control-Allow-Origin": "*",
    });
});

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
            "img-src 'self' data:",
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
function nav(
    xiActive: "requests" | "feedback" | "favicon" | "cv" | "content" | "banner",
): string {
    const lRActive = xiActive === "requests" ? ' class="active"' : "";
    const lFActive = xiActive === "feedback" ? ' class="active"' : "";
    const lIActive = xiActive === "favicon" ? ' class="active"' : "";
    const lCActive = xiActive === "cv" ? ' class="active"' : "";
    const lNActive = xiActive === "content" ? ' class="active"' : "";
    const lBActive = xiActive === "banner" ? ' class="active"' : "";
    return `<nav class="nav">
  <a href="/requests"${lRActive}>Requests</a>
  <a href="/feedback"${lFActive}>Feedback</a>
  <a href="/favicon"${lIActive}>Favicons</a>
  <a href="/cv"${lCActive}>CV</a>
  <a href="/content"${lNActive}>Content</a>
  <a href="/banner"${lBActive}>Banner</a>
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
.add-form {
  margin-top: 1.5rem; padding: 1.25rem;
  background: #fff; border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
}
.add-form h2 { font-size: .95rem; margin: 0 0 .75rem; }
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
/* ── Favicon library ── */
.library-grid {
  display: flex; flex-wrap: wrap; gap: .75rem;
  min-height: 64px; align-items: flex-start;
}
.design-card {
  display: flex; flex-direction: column; align-items: center;
  gap: .3rem; padding: .6rem .75rem; position: relative;
  border: 2px solid #eee; border-radius: 8px; background: #fff;
  min-width: 80px; transition: border-color .12s;
}
.design-card.clickable { cursor: pointer; }
.design-card.clickable:hover { border-color: #111; }
.design-card.selected { border-color: #111; box-shadow: 0 0 0 2px #111; }
.design-name {
  font-size: .75rem; color: #555; text-align: center;
  max-width: 80px; overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap;
}
.del-btn {
  position: absolute; top: .2rem; right: .3rem;
  background: none; border: none; cursor: pointer;
  color: #ccc; font-size: .9rem; line-height: 1; padding: 0;
}
.del-btn:hover { color: #c0392b; }
.upload-row {
  display: flex; align-items: center; gap: .6rem; flex-wrap: wrap;
  margin-top: .75rem; padding-top: .75rem;
  border-top: 1px solid #f0f0f0;
}
.file-btn {
  display: inline-block; padding: .35rem .75rem;
  border: 1px solid #ddd; border-radius: 6px;
  font-size: .85rem; background: #fafafa; cursor: pointer;
}
.file-btn:hover { background: #efefef; }
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

const SITE_RE = /^[a-z0-9-]{1,63}$/;
const LIBRARY_NAME_RE = /^[a-z0-9-]{1,63}$/;

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

    const lList = await c.env.PLATFORM_ASSETS.list({
        prefix: "platform_favicon:",
    });
    const lCustomSites = lList.keys.map((k) =>
        k.name.slice("platform_favicon:".length),
    );
    const lAllSites = [...new Set([...KNOWN_SITES, ...lCustomSites])];
    const lCustomSet = new Set(lCustomSites);

    const lGlobalSvg = await c.env.PLATFORM_ASSETS.get("platform_favicon");

    const lRowsHtml = lAllSites
        .map((lSite) => {
            const lIsCustom = lCustomSet.has(lSite);
            const lThumbSrc = `/favicon.svg?site=${encodeURIComponent(lSite)}`;
            const lStatusHtml = lIsCustom
                ? `<span class="badge badge-custom">Custom</span>`
                : `<span class="badge badge-default">Default</span>`;
            const lResetBtn = lIsCustom
                ? `<button class="decline-btn"` +
                  ` onclick="resetSite('${lSite}',this)">Reset</button>`
                : "";
            return (
                `<tr id="row-${lSite}">` +
                `<td><img id="thumb-${lSite}" src="${lThumbSrc}"` +
                ` width="32" height="32" alt=""></td>` +
                `<td><code>${escapeHtml(lSite)}</code></td>` +
                `<td id="status-${lSite}">${lStatusHtml}</td>` +
                `<td class="action-btns" id="actions-${lSite}">` +
                `<button class="approve-btn"` +
                ` onclick="openSitePicker('${lSite}')">Change</button>` +
                `${lResetBtn}</td></tr>` +
                `<tr id="picker-row-${lSite}" style="display:none">` +
                `<td colspan="4"` +
                ` style="padding:.5rem 1rem .75rem;background:#fafafa">` +
                `<p style="font-size:.8rem;color:#888;margin:0 0 .25rem">` +
                `Select a design for` +
                ` <strong>${escapeHtml(lSite)}</strong>:</p>` +
                `<div id="picker-grid-${lSite}" class="library-grid">` +
                `<em style="color:#bbb;font-size:.8rem">Loading…</em>` +
                `</div>` +
                `<div style="display:flex;gap:.5rem;margin-top:.5rem;align-items:center">` +
                `<button id="confirm-${lSite}" class="approve-btn"` +
                ` disabled>Confirm</button>` +
                `<button style="padding:.25rem .6rem;font-size:.8rem;` +
                `border:1px solid #ddd;border-radius:4px;background:#fff;` +
                `cursor:pointer" onclick="closePicker()">Cancel</button>` +
                `<span id="assign-msg-${lSite}"` +
                ` style="color:#c0392b;font-size:.8rem"></span>` +
                `</div>` +
                `</td></tr>`
            );
        })
        .join("");

    const lGlobalStatus = lGlobalSvg
        ? `<span class="badge badge-custom">Custom</span>`
        : `<span class="badge badge-default">Default</span>`;
    const lGlobalReset = lGlobalSvg
        ? `<button class="decline-btn" onclick="resetDefault(this)">` +
          `Reset to fallback</button>`
        : "";

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
<p class="subtitle">Per-site icons served at
  <code>coull.ai/favicon.svg?site=…</code></p>

<div class="add-form">
  <h2>Design library</h2>
  <p style="color:#666;font-size:.85rem;margin:.2rem 0 .75rem">
    Upload SVG designs here — click one under a site to assign it.
  </p>
  <div id="library-grid" class="library-grid">
    <em style="color:#bbb;font-size:.8rem">Loading…</em>
  </div>
  <div class="upload-row">
    <input type="text" id="design-name"
           placeholder="design name" maxlength="63"
           style="width:180px;padding:.4rem .6rem;
                  border:1px solid #ddd;border-radius:6px;
                  font-size:.85rem">
    <label style="cursor:pointer">
      <input type="file" id="design-file"
             accept=".svg,image/svg+xml" style="display:none">
      <span class="file-btn">Choose SVG</span>
    </label>
    <img id="upload-preview" width="40" height="40" alt=""
         style="border:1px solid #eee;border-radius:4px;
                background:#fafafa;display:none">
    <button class="approve-btn" onclick="uploadDesign()">
      Save design</button>
    <span id="upload-err"
          style="color:#c0392b;font-size:.8rem"></span>
  </div>
</div>

<div class="add-form" style="margin-top:.75rem">
  <h2>Platform default</h2>
  <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap">
    <img id="default-thumb" src="/favicon.svg?t=${Date.now()}"
         width="40" height="40" alt=""
         style="border:1px solid #eee;border-radius:4px;
                background:#fafafa;flex-shrink:0">
    <span id="default-status">${lGlobalStatus}</span>
    <div id="default-actions"
         style="display:flex;gap:.5rem;flex-wrap:wrap">
      <button class="approve-btn" onclick="openDefaultPicker()">
        Change</button>
      ${lGlobalReset}
    </div>
  </div>
  <div id="default-picker" style="display:none;margin-top:.75rem">
    <p style="font-size:.8rem;color:#888;margin:0 0 .25rem">
      Select a design for the platform default (used when no
      per-site design is set):</p>
    <div id="default-picker-grid" class="library-grid">
      <em style="color:#bbb;font-size:.8rem">Loading…</em></div>
    <div style="display:flex;gap:.5rem;margin-top:.5rem;align-items:center">
      <button id="confirm-default" class="approve-btn"
              disabled>Confirm</button>
      <button style="padding:.25rem .6rem;font-size:.8rem;
                     border:1px solid #ddd;border-radius:4px;
                     background:#fff;cursor:pointer"
              onclick="closePicker()">Cancel</button>
      <span id="default-msg"
            style="color:#c0392b;font-size:.8rem"></span>
    </div>
  </div>
</div>

<div class="table-wrap"
     style="margin-top:.75rem;min-height:40vh;overflow-y:auto">
  <table>
    <thead>
      <tr>
        <th>Preview</th><th>Site</th><th>Status</th><th></th>
      </tr>
    </thead>
    <tbody id="favicon-body">${lRowsHtml}</tbody>
  </table>
</div>

<script>
var knownSites = ${JSON.stringify([...KNOWN_SITES])};
var library = [];
var activePicker = null;
var currentPickerSite = null;

async function loadLibrary() {
  var res = await fetch('/api/admin/favicon-library');
  if (!res.ok) return;
  library = await res.json();
  renderLibraryGrid();
}

function svgThumb(svg) {
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

function renderLibraryGrid() {
  var grid = document.getElementById('library-grid');
  if (!library.length) {
    grid.onclick = null;
    grid.innerHTML = '<p style="color:#888;font-size:.85rem;margin:0">'
      + 'No designs yet — upload one using the form above.</p>';
    return;
  }
  grid.innerHTML = library.map(function(d) {
    return '<div class="design-card" data-name="' + d.name + '">'
      + '<img src="' + svgThumb(d.svg) + '"'
      + ' width="48" height="48" alt="">'
      + '<span class="design-name">' + d.name + '</span>'
      + '<button class="del-btn" title="Delete design">×</button>'
      + '</div>';
  }).join('');
  grid.onclick = function(e) {
    if (e.target.classList.contains('del-btn')) {
      var card = e.target.closest('.design-card');
      if (card) deleteDesign(card.getAttribute('data-name'));
    }
  };
}

function renderPickerGrid(gridId, confirmBtnId, callback) {
  var grid = document.getElementById(gridId);
  var confirmBtn = document.getElementById(confirmBtnId);
  if (!grid) return;
  var lSelected = null;
  grid.onclick = null;
  if (confirmBtn) { confirmBtn.disabled = true; confirmBtn.onclick = null; }
  if (!library.length) {
    grid.innerHTML = '<p style="color:#888;font-size:.85rem;margin:0">'
      + 'No designs in library — add one above first.</p>';
    return;
  }
  grid.innerHTML = library.map(function(d) {
    return '<div class="design-card clickable"'
      + ' data-name="' + d.name + '">'
      + '<img src="' + svgThumb(d.svg) + '"'
      + ' width="48" height="48" alt="">'
      + '<span class="design-name">' + d.name + '</span>'
      + '</div>';
  }).join('');
  grid.onclick = function(e) {
    var card = e.target.closest('.clickable');
    if (!card) return;
    var n = card.getAttribute('data-name');
    if (!n) return;
    grid.querySelectorAll('.design-card').forEach(function(c) {
      c.classList.remove('selected');
    });
    card.classList.add('selected');
    lSelected = n;
    if (confirmBtn) confirmBtn.disabled = false;
  };
  if (confirmBtn) {
    confirmBtn.onclick = function() {
      if (lSelected) callback(lSelected);
    };
  }
}

document.getElementById('design-file')
  .addEventListener('change', function(e) {
    var file = e.target.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function(ev) {
      var content = ev.target.result || '';
      var prev = document.getElementById('upload-preview');
      prev.style.display = content ? '' : 'none';
      prev.src = content
        ? 'data:image/svg+xml,' + encodeURIComponent(content) : '';
    };
    reader.readAsText(file);
  });

async function uploadDesign() {
  var name = document.getElementById('design-name')
    .value.trim().toLowerCase();
  var errEl = document.getElementById('upload-err');
  errEl.textContent = '';
  if (!/^[a-z0-9-]{1,63}$/.test(name)) {
    errEl.textContent = 'Name: lowercase letters, digits, hyphens only';
    return;
  }
  var file = document.getElementById('design-file').files[0];
  if (!file) {
    errEl.textContent = 'Choose an SVG file first';
    return;
  }
  var svg = await file.text();
  var res = await fetch('/api/admin/favicon-library/' + name, {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: svg,
  });
  var data = await res.json();
  if (!res.ok) {
    errEl.textContent = data.error || 'Save failed';
    return;
  }
  document.getElementById('design-name').value = '';
  document.getElementById('design-file').value = '';
  document.getElementById('upload-preview').style.display = 'none';
  /* Optimistic: update local state immediately instead of re-fetching from KV
     (KV list has eventual consistency — a fresh list call may miss a new key) */
  var idx = library.findIndex(function(d) { return d.name === name; });
  if (idx >= 0) {
    library[idx] = { name: name, svg: svg };
  } else {
    library.push({ name: name, svg: svg });
    library.sort(function(a, b) { return a.name.localeCompare(b.name); });
  }
  renderLibraryGrid();
}

async function deleteDesign(name) {
  if (!confirm('Delete design "' + name + '"?')) return;
  await fetch('/api/admin/favicon-library/' + name, { method: 'DELETE' });
  library = library.filter(function(d) { return d.name !== name; });
  renderLibraryGrid();
}

function closePicker() {
  if (!activePicker) return;
  if (activePicker === 'default') {
    document.getElementById('default-picker').style.display = 'none';
  } else {
    var site = activePicker.slice(5);
    document.getElementById('picker-row-' + site).style.display = 'none';
  }
  activePicker = null;
  currentPickerSite = null;
}

function openSitePicker(site) {
  closePicker();
  currentPickerSite = site;
  activePicker = 'site:' + site;
  var row = document.getElementById('picker-row-' + site);
  row.style.display = '';
  renderPickerGrid('picker-grid-' + site, 'confirm-' + site,
    function(designName) {
      var entry = library.find(function(d) { return d.name === designName; });
      if (entry) assignDesign(site, entry.svg);
    });
  row.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function openDefaultPicker() {
  closePicker();
  activePicker = 'default';
  document.getElementById('default-picker').style.display = '';
  renderPickerGrid('default-picker-grid', 'confirm-default',
    function(designName) {
      var entry = library.find(function(d) { return d.name === designName; });
      if (entry) assignDefault(entry.svg);
    });
}

async function assignDesign(site, svg) {
  var msgEl = document.getElementById('assign-msg-' + site);
  msgEl.textContent = '';
  var res = await fetch(
    '/api/admin/favicons/' + encodeURIComponent(site),
    { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: svg },
  );
  if (!res.ok) {
    var lErr = await res.json().catch(function() { return {}; });
    msgEl.textContent = lErr.error || 'Save failed (' + res.status + ')';
    return;
  }
  var t = Date.now();
  document.getElementById('thumb-' + site).src =
    '/favicon.svg?site=' + encodeURIComponent(site) + '&t=' + t;
  document.getElementById('status-' + site).innerHTML =
    '<span class="badge badge-custom">Custom</span>';
  var actEl = document.getElementById('actions-' + site);
  if (!actEl.querySelector('.decline-btn')) {
    var btn = document.createElement('button');
    btn.className = 'decline-btn';
    btn.textContent = 'Reset';
    btn.onclick = function() { resetSite(site, btn); };
    actEl.appendChild(btn);
  }
  closePicker();
}

async function resetSite(site, btn) {
  if (!confirm('Reset ' + site + ' to the platform default?')) return;
  btn.disabled = true;
  var res = await fetch(
    '/api/admin/favicons/' + encodeURIComponent(site),
    { method: 'DELETE' },
  );
  if (!res.ok) {
    btn.disabled = false;
    btn.textContent = 'Reset failed';
    setTimeout(function() { btn.textContent = 'Reset'; }, 3000);
    return;
  }
  document.getElementById('thumb-' + site).src =
    '/favicon.svg?site=' + encodeURIComponent(site) + '&t=' + Date.now();
  document.getElementById('status-' + site).innerHTML =
    '<span class="badge badge-default">Default</span>';
  btn.remove();
  if (knownSites.indexOf(site) === -1) {
    document.getElementById('row-' + site).remove();
    document.getElementById('picker-row-' + site).remove();
  }
}

async function assignDefault(svg) {
  var msgEl = document.getElementById('default-msg');
  msgEl.textContent = '';
  var res = await fetch('/api/admin/favicon/default', {
    method: 'POST',
    headers: { 'Content-Type': 'text/plain' },
    body: svg,
  });
  if (!res.ok) {
    var lErr = await res.json().catch(function() { return {}; });
    msgEl.textContent = lErr.error || 'Save failed (' + res.status + ')';
    return;
  }
  document.getElementById('default-thumb').src =
    '/favicon.svg?t=' + Date.now();
  document.getElementById('default-status').innerHTML =
    '<span class="badge badge-custom">Custom</span>';
  var actEl = document.getElementById('default-actions');
  if (!actEl.querySelector('.decline-btn')) {
    var btn = document.createElement('button');
    btn.className = 'decline-btn';
    btn.textContent = 'Reset to fallback';
    btn.onclick = function() { resetDefault(btn); };
    actEl.appendChild(btn);
  }
  closePicker();
}

async function resetDefault(btn) {
  if (!confirm('Reset platform default to the hardcoded fallback?')) return;
  btn.disabled = true;
  var res = await fetch('/api/admin/favicon/default', { method: 'DELETE' });
  if (!res.ok) { btn.disabled = false; return; }
  window.location.reload();
}

loadLibrary();
</script>
</body>
</html>`,
    );
});

// ---------------------------------------------------------------------------
// GET /api/admin/favicon-library — list all named SVG designs (owner-only)
// ---------------------------------------------------------------------------

app.get("/api/admin/favicon-library", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lList = await c.env.PLATFORM_ASSETS.list({
        prefix: "platform_favicon_library:",
    });
    const lEntries = await Promise.all(
        lList.keys.map(async (k) => {
            const lSvg = await c.env.PLATFORM_ASSETS.get(k.name);
            return {
                name: k.name.slice("platform_favicon_library:".length),
                svg: lSvg ?? "",
            };
        }),
    );
    return c.json(
        lEntries
            .filter((e) => e.svg !== "")
            .sort((a, b) => a.name.localeCompare(b.name)),
    );
});

// ---------------------------------------------------------------------------
// POST /api/admin/favicon-library/:name — save SVG design (owner-only)
// ---------------------------------------------------------------------------

app.post("/api/admin/favicon-library/:name", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lName = c.req.param("name");
    if (!LIBRARY_NAME_RE.test(lName))
        return c.json({ error: "Invalid design name" }, 400);

    const lRaw = await c.req.text();
    const lResult = validateSvg(lRaw);
    if (!lResult.ok) return c.json({ error: lResult.error }, 400);

    await c.env.PLATFORM_ASSETS.put(
        `platform_favicon_library:${lName}`,
        lResult.svg,
    );
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// DELETE /api/admin/favicon-library/:name — remove SVG design (owner-only)
// ---------------------------------------------------------------------------

app.delete("/api/admin/favicon-library/:name", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lName = c.req.param("name");
    if (!LIBRARY_NAME_RE.test(lName))
        return c.json({ error: "Invalid design name" }, 400);

    await c.env.PLATFORM_ASSETS.delete(`platform_favicon_library:${lName}`);
    return c.json({ ok: true });
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

// ---------------------------------------------------------------------------
// GET /cv — owner-gated CV upload page.
// ---------------------------------------------------------------------------

/**
 * Inputs: authenticated owner request.
 * Outputs: HTML page with a link to the live CV and a PDF upload form.
 * Logic: file input sends raw PDF body to POST /api/admin/cv via fetch.
 */
app.get("/cv", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    return c.html(
        `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin — CV</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>${SHARED_STYLES}
.cv-card {
  background: #fff; border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
  padding: 1.25rem; max-width: 480px;
}
.cv-card p { margin: 0 0 1rem; font-size: .9rem; color: #444; }
.upload-row { display: flex; gap: .6rem; align-items: center; flex-wrap: wrap; }
.upload-btn {
  padding: .4rem .9rem; background: #111; color: #fff;
  border: none; border-radius: 6px; font-size: .85rem; cursor: pointer;
}
.upload-btn:hover { background: #333; }
.upload-btn:disabled { opacity: .5; cursor: default; }
#upload-msg { font-size: .85rem; }
.success { color: #2e7d32; }
.error { color: #c0392b; }
  </style>
</head>
<body>
${nav("cv")}
<h1>CV</h1>
<p class="subtitle">Replace the PDF served at cv.coull.ai. The existing file
  is overwritten in place.</p>
<div class="cv-card" style="margin-top:1.25rem">
  <p>
    <a href="https://cv.coull.ai" target="_blank" rel="noopener noreferrer"
       style="color:#111;font-weight:600">View current CV →</a>
  </p>
  <div class="upload-row">
    <input type="file" id="cv-file" accept=".pdf"
           style="font-size:.85rem">
    <button class="upload-btn" id="upload-btn" onclick="uploadCv()">
      Upload
    </button>
  </div>
  <p id="upload-msg" style="margin:.75rem 0 0"></p>
</div>
<script>
async function uploadCv() {
  const lFile = document.getElementById('cv-file').files[0];
  const lMsg  = document.getElementById('upload-msg');
  const lBtn  = document.getElementById('upload-btn');
  if (!lFile) { lMsg.textContent = 'Select a PDF first.'; lMsg.className = 'error'; return; }
  lBtn.disabled = true;
  lMsg.textContent = 'Uploading…';
  lMsg.className = '';
  try {
    const lRes = await fetch('/api/admin/cv', {
      method: 'POST',
      headers: { 'Content-Type': 'application/pdf' },
      body: lFile,
    });
    const lData = await lRes.json();
    if (lRes.ok) {
      lMsg.textContent = 'CV updated successfully.';
      lMsg.className = 'success';
    } else {
      lMsg.textContent = lData.error ?? 'Upload failed.';
      lMsg.className = 'error';
    }
  } catch (_) {
    lMsg.textContent = 'Network error — please try again.';
    lMsg.className = 'error';
  }
  lBtn.disabled = false;
}
</script>
</body>
</html>`,
    );
});

// ---------------------------------------------------------------------------
// POST /api/admin/cv — owner-gated CV replacement.
// ---------------------------------------------------------------------------

const CV_MAX_BYTES = 5 * 1024 * 1024; // 5 MB

/**
 * Inputs: raw PDF body with Content-Type: application/pdf.
 * Outputs: { ok: true } on success; { error: string } (400) on validation
 *   failure.
 * Logic: validates content-type, size cap, and PDF magic bytes, then puts
 *   the file to R2 under the fixed key used by the cv worker.
 */
app.post("/api/admin/cv", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lContentType = c.req.header("content-type") ?? "";
    if (!lContentType.startsWith("application/pdf")) {
        return c.json({ error: "Content-Type must be application/pdf" }, 400);
    }

    const lBody = await c.req.arrayBuffer();

    if (lBody.byteLength === 0) {
        return c.json({ error: "File is empty" }, 400);
    }
    if (lBody.byteLength > CV_MAX_BYTES) {
        return c.json({ error: "File exceeds 5 MB limit" }, 400);
    }

    // Verify PDF magic bytes: %PDF (0x25 0x50 0x44 0x46)
    const lMagic = new Uint8Array(lBody, 0, 4);
    if (
        lMagic[0] !== 0x25 ||
        lMagic[1] !== 0x50 ||
        lMagic[2] !== 0x44 ||
        lMagic[3] !== 0x46
    ) {
        return c.json({ error: "File does not appear to be a valid PDF" }, 400);
    }

    await c.env.CV_BUCKET.put("Connor_Coull_CV.pdf", lBody, {
        httpMetadata: { contentType: "application/pdf" },
    });

    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// GET /content — owner-gated reading list + recommendations manager.
// ---------------------------------------------------------------------------

/**
 * Inputs: authenticated owner request.
 * Outputs: HTML page with two panels: reading papers and recommendations.
 * Logic: reads all papers (newest first) and all recommendations (oldest
 *   first) from D1; the top 5 papers are marked as "live" on the homepage.
 */
app.get("/content", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const [lPapers, lRecs] = await Promise.all([
        c.env.DB.prepare(
            "SELECT id, title, authors, year, href" +
                " FROM reading_papers ORDER BY created_at DESC",
        ).all<{
            id: string;
            title: string;
            authors: string;
            year: number;
            href: string | null;
        }>(),
        c.env.DB.prepare(
            "SELECT id, category, text" +
                " FROM recommendations ORDER BY created_at ASC",
        ).all<{ id: string; category: string; text: string }>(),
    ]);

    const lPaperRows = (lPapers.results ?? [])
        .map((p, i) => {
            const lLive =
                i < 5
                    ? `<span class="badge badge-custom" ` +
                      `style="margin-left:.4rem">live</span>`
                    : "";
            const lHref = p.href
                ? `<a href="${escapeHtml(p.href)}" target="_blank" ` +
                  `rel="noopener noreferrer" ` +
                  `style="color:#2e4a52;font-size:.8rem">↗</a> `
                : "";
            return (
                `<tr id="paper-row-${escapeHtml(p.id)}">` +
                `<td>${escapeHtml(p.title)}${lLive}</td>` +
                `<td>${escapeHtml(p.authors)}</td>` +
                `<td>${p.year}</td>` +
                `<td>${lHref}</td>` +
                `<td><button class="decline-btn" ` +
                `onclick="deletePaper('${escapeHtml(p.id)}')">Delete</button></td>` +
                `</tr>`
            );
        })
        .join("");

    const lRecRows = (lRecs.results ?? [])
        .map((r) => {
            return (
                `<tr id="rec-row-${escapeHtml(r.id)}">` +
                `<td class="rec-cat-cell">${escapeHtml(r.category)}</td>` +
                `<td class="rec-text-cell">${escapeHtml(r.text)}</td>` +
                `<td class="action-btns">` +
                `<button class="approve-btn" ` +
                `onclick="editRec('${escapeHtml(r.id)}','` +
                `${escapeHtml(r.category)}','${escapeHtml(r.text)}'` +
                `)">Edit</button>` +
                `<button class="decline-btn" ` +
                `onclick="deleteRec('${escapeHtml(r.id)}')">Delete</button>` +
                `</td>` +
                `</tr>`
            );
        })
        .join("");

    return c.html(
        `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin — Content</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>${SHARED_STYLES}
.content-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1.5rem;
  margin-top: 1rem;
}
@media (max-width: 900px) {
  .content-grid { grid-template-columns: 1fr; }
}
.section-card {
  background: #fff; border-radius: 8px;
  box-shadow: 0 1px 4px rgba(0,0,0,.08);
  padding: 1.25rem; display: flex; flex-direction: column; gap: 1rem;
}
.section-card h2 { font-size: 1rem; margin: 0; }
.section-card .hint { font-size: .8rem; color: #888; margin: 0; }
.add-row {
  display: grid; gap: .5rem;
}
.add-row label { font-size: .8rem; color: #555; }
.add-row input {
  width: 100%; padding: .4rem .6rem;
  border: 1px solid #ddd; border-radius: 6px;
  font-size: .9rem; background: #fafafa;
}
.add-row input:focus { outline: 2px solid #111; border-color: transparent; }
.add-submit {
  padding: .4rem .9rem; background: #111; color: #fff;
  border: none; border-radius: 6px; font-size: .85rem; cursor: pointer;
  align-self: flex-end; margin-top: .25rem;
}
.add-submit:hover { background: #333; }
.add-submit:disabled { opacity: .5; cursor: default; }
.form-err { color: #c0392b; font-size: .8rem; min-height: 1.1rem; }
.papers-table td:nth-child(3) { white-space: nowrap; }
.edit-modal-overlay {
  display: none; position: fixed; inset: 0;
  background: rgba(0,0,0,.35); z-index: 100;
  align-items: center; justify-content: center;
}
.edit-modal-overlay.open { display: flex; }
.edit-modal {
  background: #fff; border-radius: 10px; padding: 1.5rem;
  width: min(420px, 90vw); box-shadow: 0 4px 24px rgba(0,0,0,.18);
}
.edit-modal h3 { margin: 0 0 1rem; font-size: 1rem; }
.edit-modal .add-row { margin-bottom: .75rem; }
.modal-btns { display: flex; gap: .5rem; justify-content: flex-end; }
  </style>
</head>
<body>
${nav("content")}
<h1>Content</h1>
<p class="subtitle">Manage the homepage reading list and recommendations.
  Changes go live within ~1 minute (CDN cache).</p>

<div class="content-grid">

  <!-- ── Currently Reading ─────────────────────────── -->
  <div class="section-card">
    <div>
      <h2>Currently Reading</h2>
      <p class="hint">Top 5 (marked <strong>live</strong>) appear on the
        homepage. Newest added first.</p>
    </div>

    <div class="add-row" id="paper-form">
      <label for="p-title">Title</label>
      <input id="p-title" type="text" placeholder="Attention Is All You Need">
      <label for="p-authors">Authors</label>
      <input id="p-authors" type="text" placeholder="Vaswani et al.">
      <label for="p-year">Year</label>
      <input id="p-year" type="number" placeholder="2017"
             min="1900" max="2100" style="max-width:120px">
      <label for="p-href">Link (optional)</label>
      <input id="p-href" type="url" placeholder="https://arxiv.org/abs/…">
      <p class="form-err" id="paper-err"></p>
      <button class="add-submit" onclick="addPaper()">Add Paper</button>
    </div>

    <div class="table-wrap">
      <table class="papers-table">
        <thead>
          <tr>
            <th>Title</th><th>Authors</th><th>Year</th>
            <th>Link</th><th></th>
          </tr>
        </thead>
        <tbody id="papers-tbody">${lPaperRows}</tbody>
      </table>
    </div>
  </div>

  <!-- ── Recommendations ───────────────────────────── -->
  <div class="section-card">
    <div>
      <h2>Recommendations</h2>
      <p class="hint">All entries appear on the homepage in the order added.
        Category is the label (e.g. Album, Film).</p>
    </div>

    <div class="add-row" id="rec-form">
      <label for="r-cat">Category</label>
      <input id="r-cat" type="text" placeholder="Album">
      <label for="r-text">Recommendation</label>
      <input id="r-text" type="text"
             placeholder="WOR$T GIRL IN AMERICA by Slayyyter">
      <p class="form-err" id="rec-err"></p>
      <button class="add-submit" onclick="addRec()">Add</button>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Category</th><th>Text</th><th></th></tr>
        </thead>
        <tbody id="recs-tbody">${lRecRows}</tbody>
      </table>
    </div>
  </div>

</div>

<!-- Edit-recommendation modal -->
<div class="edit-modal-overlay" id="rec-modal">
  <div class="edit-modal">
    <h3>Edit recommendation</h3>
    <input type="hidden" id="edit-rec-id">
    <div class="add-row">
      <label for="edit-rec-cat">Category</label>
      <input id="edit-rec-cat" type="text">
      <label for="edit-rec-text">Text</label>
      <input id="edit-rec-text" type="text">
      <p class="form-err" id="edit-rec-err"></p>
    </div>
    <div class="modal-btns">
      <button class="archive-btn" onclick="closeRecModal()">Cancel</button>
      <button class="approve-btn" onclick="saveRec()">Save</button>
    </div>
  </div>
</div>

<script>
// ── Paper helpers ────────────────────────────────────────────────────────────

async function addPaper() {
  const lTitle   = document.getElementById('p-title').value.trim();
  const lAuthors = document.getElementById('p-authors').value.trim();
  const lYear    = parseInt(document.getElementById('p-year').value, 10);
  const lHref    = document.getElementById('p-href').value.trim();
  const lErr     = document.getElementById('paper-err');
  const lBtn     = document.querySelector('#paper-form .add-submit');

  if (!lTitle)   { lErr.textContent = 'Title is required.'; return; }
  if (!lAuthors) { lErr.textContent = 'Authors is required.'; return; }
  if (!lYear || lYear < 1900 || lYear > 2100) {
    lErr.textContent = 'Year must be between 1900 and 2100.'; return;
  }
  if (lHref && !/^https?:\\/\\//.test(lHref)) {
    lErr.textContent = 'Link must start with http:// or https://.'; return;
  }
  lErr.textContent = '';
  lBtn.disabled = true;

  try {
    const lRes = await fetch('/api/admin/reading', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: lTitle, authors: lAuthors,
        year: lYear, href: lHref || null }),
    });
    const lData = await lRes.json();
    if (!lRes.ok) { lErr.textContent = lData.error ?? 'Failed.'; return; }

    // Prepend new row to table — it's the newest, so it goes first.
    const lLive = document.querySelectorAll('#papers-tbody tr').length < 5
      ? '<span class="badge badge-custom" style="margin-left:.4rem">live</span>'
      : '';
    const lLinkCell = lHref
      ? '<a href="' + escHtml(lHref) + '" target="_blank" ' +
        'rel="noopener noreferrer" style="color:#2e4a52;font-size:.8rem">↗</a>'
      : '';
    const lRow = '<tr id="paper-row-' + escHtml(lData.id) + '">' +
      '<td>' + escHtml(lTitle) + lLive + '</td>' +
      '<td>' + escHtml(lAuthors) + '</td>' +
      '<td>' + lYear + '</td>' +
      '<td>' + lLinkCell + '</td>' +
      '<td><button class="decline-btn" ' +
      'onclick="deletePaper(\\'' + escHtml(lData.id) + '\\')">Delete</button></td>' +
      '</tr>';
    document.getElementById('papers-tbody').insertAdjacentHTML('afterbegin', lRow);

    // Refresh live badges (only top 5 should have them).
    refreshLiveBadges();

    // Clear form
    ['p-title','p-authors','p-year','p-href'].forEach(id =>
      document.getElementById(id).value = '');
  } catch (_) {
    lErr.textContent = 'Network error — please try again.';
  }
  lBtn.disabled = false;
}

async function deletePaper(xiId) {
  if (!confirm('Delete this paper?')) return;
  try {
    const lRes = await fetch('/api/admin/reading/' + encodeURIComponent(xiId),
      { method: 'DELETE' });
    if (lRes.ok) {
      document.getElementById('paper-row-' + xiId)?.remove();
      refreshLiveBadges();
    } else {
      const lData = await lRes.json();
      alert(lData.error ?? 'Delete failed.');
    }
  } catch (_) { alert('Network error.'); }
}

/**
 * Recalculates "live" badges so the first 5 rows in DOM show the badge
 * and others do not, after any add/delete.
 */
function refreshLiveBadges() {
  const lRows = document.querySelectorAll('#papers-tbody tr');
  lRows.forEach((lRow, i) => {
    const lTitleCell = lRow.querySelector('td:first-child');
    let lBadge = lTitleCell.querySelector('.badge-custom');
    if (i < 5) {
      if (!lBadge) {
        lBadge = document.createElement('span');
        lBadge.className = 'badge badge-custom';
        lBadge.style.marginLeft = '.4rem';
        lBadge.textContent = 'live';
        lTitleCell.appendChild(lBadge);
      }
    } else {
      lBadge?.remove();
    }
  });
}

// ── Recommendation helpers ───────────────────────────────────────────────────

async function addRec() {
  const lCat  = document.getElementById('r-cat').value.trim();
  const lText = document.getElementById('r-text').value.trim();
  const lErr  = document.getElementById('rec-err');
  const lBtn  = document.querySelector('#rec-form .add-submit');

  if (!lCat)  { lErr.textContent = 'Category is required.'; return; }
  if (!lText) { lErr.textContent = 'Text is required.'; return; }
  lErr.textContent = '';
  lBtn.disabled = true;

  try {
    const lRes = await fetch('/api/admin/recommendations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ category: lCat, text: lText }),
    });
    const lData = await lRes.json();
    if (!lRes.ok) { lErr.textContent = lData.error ?? 'Failed.'; return; }

    const lRow = '<tr id="rec-row-' + escHtml(lData.id) + '">' +
      '<td class="rec-cat-cell">' + escHtml(lCat) + '</td>' +
      '<td class="rec-text-cell">' + escHtml(lText) + '</td>' +
      '<td class="action-btns">' +
      '<button class="approve-btn" onclick="editRec(\\'' +
      escHtml(lData.id) + '\\',\\'' + escJs(lCat) + '\\',\\'' +
      escJs(lText) + '\\')">Edit</button>' +
      '<button class="decline-btn" onclick="deleteRec(\\'' +
      escHtml(lData.id) + '\\')">Delete</button>' +
      '</td></tr>';
    document.getElementById('recs-tbody').insertAdjacentHTML('beforeend', lRow);

    document.getElementById('r-cat').value = '';
    document.getElementById('r-text').value = '';
  } catch (_) {
    lErr.textContent = 'Network error — please try again.';
  }
  lBtn.disabled = false;
}

function editRec(xiId, xiCat, xiText) {
  document.getElementById('edit-rec-id').value  = xiId;
  document.getElementById('edit-rec-cat').value  = xiCat;
  document.getElementById('edit-rec-text').value = xiText;
  document.getElementById('edit-rec-err').textContent = '';
  document.getElementById('rec-modal').classList.add('open');
}

function closeRecModal() {
  document.getElementById('rec-modal').classList.remove('open');
}

async function saveRec() {
  const lId   = document.getElementById('edit-rec-id').value;
  const lCat  = document.getElementById('edit-rec-cat').value.trim();
  const lText = document.getElementById('edit-rec-text').value.trim();
  const lErr  = document.getElementById('edit-rec-err');

  if (!lCat)  { lErr.textContent = 'Category is required.'; return; }
  if (!lText) { lErr.textContent = 'Text is required.'; return; }
  lErr.textContent = '';

  try {
    const lRes = await fetch(
      '/api/admin/recommendations/' + encodeURIComponent(lId),
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ category: lCat, text: lText }),
      },
    );
    const lData = await lRes.json();
    if (!lRes.ok) { lErr.textContent = lData.error ?? 'Save failed.'; return; }

    // Update row in DOM
    const lRow = document.getElementById('rec-row-' + lId);
    if (lRow) {
      lRow.querySelector('.rec-cat-cell').textContent  = lCat;
      lRow.querySelector('.rec-text-cell').textContent = lText;
      // Refresh onclick attrs with updated values
      const lEditBtn = lRow.querySelector('.approve-btn');
      lEditBtn.setAttribute('onclick',
        "editRec('" + escHtml(lId) + "','" + escJs(lCat) +
        "','" + escJs(lText) + "')");
    }
    closeRecModal();
  } catch (_) {
    lErr.textContent = 'Network error — please try again.';
  }
}

async function deleteRec(xiId) {
  if (!confirm('Delete this recommendation?')) return;
  try {
    const lRes = await fetch(
      '/api/admin/recommendations/' + encodeURIComponent(xiId),
      { method: 'DELETE' },
    );
    if (lRes.ok) {
      document.getElementById('rec-row-' + xiId)?.remove();
    } else {
      const lData = await lRes.json();
      alert(lData.error ?? 'Delete failed.');
    }
  } catch (_) { alert('Network error.'); }
}

// ── Utilities ────────────────────────────────────────────────────────────────

/** Escape a string for safe insertion into HTML text content. */
function escHtml(xiStr) {
  return String(xiStr)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Escape a string for safe embedding in a JS string literal (inside quotes). */
function escJs(xiStr) {
  return String(xiStr).replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");
}

// Close modal when clicking the overlay backdrop.
document.getElementById('rec-modal').addEventListener('click', function(e) {
  if (e.target === this) closeRecModal();
});
</script>
</body>
</html>`,
    );
});

// ---------------------------------------------------------------------------
// POST /api/admin/reading — add a reading paper.
// ---------------------------------------------------------------------------

const HREF_RE = /^https?:\/\/.+/;

/**
 * Inputs: JSON body { title, authors, year, href? }.
 * Outputs: { ok: true, id: string } on success; { error } (400) on
 *   validation failure.
 * Logic: validates all fields, then inserts into reading_papers with a new
 *   UUID and the current timestamp as created_at (ordering key).
 */
app.post("/api/admin/reading", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lBody = await c.req.json<{
        title?: unknown;
        authors?: unknown;
        year?: unknown;
        href?: unknown;
    }>();

    const lTitle = typeof lBody.title === "string" ? lBody.title.trim() : "";
    const lAuthors =
        typeof lBody.authors === "string" ? lBody.authors.trim() : "";
    const lYear = typeof lBody.year === "number" ? Math.trunc(lBody.year) : NaN;
    const lHref =
        lBody.href == null
            ? null
            : typeof lBody.href === "string"
              ? lBody.href.trim()
              : "";

    if (!lTitle) return c.json({ error: "title is required" }, 400);
    if (!lAuthors) return c.json({ error: "authors is required" }, 400);
    if (!Number.isFinite(lYear) || lYear < 1900 || lYear > 2100) {
        return c.json({ error: "year must be an integer 1900–2100" }, 400);
    }
    if (lHref !== null && !HREF_RE.test(lHref)) {
        return c.json(
            { error: "href must start with http:// or https://" },
            400,
        );
    }

    const lId = crypto.randomUUID();
    await c.env.DB.prepare(
        "INSERT INTO reading_papers (id, title, authors, year, href, created_at)" +
            " VALUES (?, ?, ?, ?, ?, ?)",
    )
        .bind(lId, lTitle, lAuthors, lYear, lHref, Date.now())
        .run();

    return c.json({ ok: true, id: lId });
});

// ---------------------------------------------------------------------------
// DELETE /api/admin/reading/:id — remove a reading paper.
// ---------------------------------------------------------------------------

/**
 * Inputs: paper id path param.
 * Outputs: { ok: true } on success; { error } (404) if not found.
 * Logic: deletes the row; treats 0 affected rows as 404.
 */
app.delete("/api/admin/reading/:id", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lId = c.req.param("id");
    const lResult = await c.env.DB.prepare(
        "DELETE FROM reading_papers WHERE id = ?",
    )
        .bind(lId)
        .run();

    if ((lResult.meta.changes ?? 0) === 0) {
        return c.json({ error: "Not found" }, 404);
    }
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// POST /api/admin/recommendations — add a recommendation.
// ---------------------------------------------------------------------------

/**
 * Inputs: JSON body { category, text }.
 * Outputs: { ok: true, id: string } on success; { error } (400) on
 *   validation failure.
 * Logic: validates non-empty fields, inserts with a new UUID and current
 *   timestamp for both created_at (ordering) and updated_at.
 */
app.post("/api/admin/recommendations", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lBody = await c.req.json<{
        category?: unknown;
        text?: unknown;
    }>();

    const lCategory =
        typeof lBody.category === "string" ? lBody.category.trim() : "";
    const lText = typeof lBody.text === "string" ? lBody.text.trim() : "";

    if (!lCategory) return c.json({ error: "category is required" }, 400);
    if (!lText) return c.json({ error: "text is required" }, 400);

    const lId = crypto.randomUUID();
    const lNow = Date.now();
    await c.env.DB.prepare(
        "INSERT INTO recommendations (id, category, text, created_at, updated_at)" +
            " VALUES (?, ?, ?, ?, ?)",
    )
        .bind(lId, lCategory, lText, lNow, lNow)
        .run();

    return c.json({ ok: true, id: lId });
});

// ---------------------------------------------------------------------------
// PUT /api/admin/recommendations/:id — edit a recommendation.
// ---------------------------------------------------------------------------

/**
 * Inputs: recommendation id path param; JSON body { category, text }.
 * Outputs: { ok: true } on success; { error } (400/404) on failure.
 * Logic: validates fields, updates the row and bumps updated_at.
 */
app.put("/api/admin/recommendations/:id", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lId = c.req.param("id");
    const lBody = await c.req.json<{
        category?: unknown;
        text?: unknown;
    }>();

    const lCategory =
        typeof lBody.category === "string" ? lBody.category.trim() : "";
    const lText = typeof lBody.text === "string" ? lBody.text.trim() : "";

    if (!lCategory) return c.json({ error: "category is required" }, 400);
    if (!lText) return c.json({ error: "text is required" }, 400);

    const lResult = await c.env.DB.prepare(
        "UPDATE recommendations SET category = ?, text = ?, updated_at = ?" +
            " WHERE id = ?",
    )
        .bind(lCategory, lText, Date.now(), lId)
        .run();

    if ((lResult.meta.changes ?? 0) === 0) {
        return c.json({ error: "Not found" }, 404);
    }
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// DELETE /api/admin/recommendations/:id — remove a recommendation.
// ---------------------------------------------------------------------------

/**
 * Inputs: recommendation id path param.
 * Outputs: { ok: true } on success; { error } (404) if not found.
 * Logic: deletes the row; treats 0 affected rows as 404.
 */
app.delete("/api/admin/recommendations/:id", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lId = c.req.param("id");
    const lResult = await c.env.DB.prepare(
        "DELETE FROM recommendations WHERE id = ?",
    )
        .bind(lId)
        .run();

    if ((lResult.meta.changes ?? 0) === 0) {
        return c.json({ error: "Not found" }, 404);
    }
    return c.json({ ok: true });
});

// ===========================================================================
// Banner — platform-wide announcement strip
// ===========================================================================

// ---------------------------------------------------------------------------
// GET /banner — owner-gated banner manager page.
// ---------------------------------------------------------------------------

/**
 * Inputs: none (reads KV directly for current config).
 * Outputs: HTML page with a global section and a per-site section for each
 *   KNOWN_SITES entry. Inline JS handles save/clear without page reloads.
 * Logic: renders current stored values server-side so the form fields are
 *   pre-populated. The global banner wins over per-site when enabled.
 */
app.get("/banner", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    // Fetch global config.
    const lGlobalRaw = await c.env.PLATFORM_ASSETS.get("platform_banner");
    let lGlobal: { enabled?: boolean; message?: string } = {};
    try {
        if (lGlobalRaw) lGlobal = JSON.parse(lGlobalRaw);
    } catch (_) {}

    // Fetch per-site configs.
    const lSiteConfigs: Record<
        string,
        { enabled?: boolean; message?: string }
    > = {};
    for (const lSite of KNOWN_SITES) {
        const lRaw = await c.env.PLATFORM_ASSETS.get(
            `platform_banner:${lSite}`,
        );
        lSiteConfigs[lSite] = {};
        try {
            if (lRaw) lSiteConfigs[lSite] = JSON.parse(lRaw);
        } catch (_) {}
    }

    const lGlobalChecked = lGlobal.enabled ? " checked" : "";
    const lGlobalMsg = escapeHtml(lGlobal.message ?? "");

    const lSiteRowsHtml = KNOWN_SITES.map((lSite) => {
        const lConf = lSiteConfigs[lSite];
        const lChecked = lConf.enabled ? " checked" : "";
        const lMsg = escapeHtml(lConf.message ?? "");
        return (
            `<tr id="row-${lSite}">` +
            `<td><code>${escapeHtml(lSite)}</code></td>` +
            `<td>` +
            `<input type="checkbox" id="en-${lSite}"${lChecked}` +
            ` aria-label="Enabled for ${escapeHtml(lSite)}">` +
            `</td>` +
            `<td>` +
            `<input type="text" id="msg-${lSite}" value="${lMsg}"` +
            ` maxlength="300" placeholder="Per-site message…"` +
            ` style="width:100%;padding:.25rem .4rem;font-size:.85rem;` +
            `border:1px solid #e0e0e0;border-radius:4px">` +
            `</td>` +
            `<td class="action-btns">` +
            `<button class="approve-btn"` +
            ` onclick="saveSite('${lSite}',this)">Save</button>` +
            `<button class="decline-btn"` +
            ` onclick="clearSite('${lSite}',this)">Clear</button>` +
            `</td>` +
            `</tr>`
        );
    }).join("");

    return c.html(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Banner — coull admin</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <style>${SHARED_STYLES}</style>
</head>
<body>
<h1>coull admin</h1>
${nav("banner")}

<section class="add-form" style="margin-bottom:1.5rem">
  <h2 style="margin-top:0">Global banner</h2>
  <p style="font-size:.85rem;color:#666;margin-top:0">
    When the global banner is <strong>enabled</strong> it overrides any
    per-site config and appears on every app. Use it for platform-wide
    announcements (services down, new deploy, etc.).
  </p>
  <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.75rem">
    <label style="display:flex;align-items:center;gap:.4rem;font-size:.9rem">
      <input type="checkbox" id="global-enabled"${lGlobalChecked}>
      Enabled
    </label>
  </div>
  <div style="display:flex;gap:.5rem;align-items:flex-start">
    <input type="text" id="global-msg" value="${lGlobalMsg}"
      maxlength="300" placeholder="Global announcement message…"
      style="flex:1;padding:.35rem .5rem;font-size:.9rem;
             border:1px solid #e0e0e0;border-radius:4px">
    <button class="approve-btn" onclick="saveGlobal(this)">Save</button>
  </div>
  <p id="global-status" style="font-size:.8rem;margin:.4rem 0 0;min-height:1.2em"></p>
</section>

<section class="add-form">
  <h2 style="margin-top:0">Per-site banners</h2>
  <p style="font-size:.85rem;color:#666;margin-top:0">
    Only shown when the global banner is <strong>disabled</strong>.
    Clear a site entry to fall back to the global state.
  </p>
  <table style="width:100%;border-collapse:collapse">
    <thead>
      <tr>
        <th style="text-align:left;padding:.4rem .5rem;font-size:.8rem;
                   color:#888;font-weight:500;border-bottom:1px solid #e0e0e0">
          Site
        </th>
        <th style="text-align:left;padding:.4rem .5rem;font-size:.8rem;
                   color:#888;font-weight:500;border-bottom:1px solid #e0e0e0">
          Enabled
        </th>
        <th style="text-align:left;padding:.4rem .5rem;font-size:.8rem;
                   color:#888;font-weight:500;border-bottom:1px solid #e0e0e0">
          Message
        </th>
        <th style="text-align:left;padding:.4rem .5rem;font-size:.8rem;
                   color:#888;font-weight:500;border-bottom:1px solid #e0e0e0">
          Actions
        </th>
      </tr>
    </thead>
    <tbody id="site-tbody">${lSiteRowsHtml}</tbody>
  </table>
</section>

<script>
  async function saveGlobal(btn) {
    btn.disabled = true;
    const enabled = document.getElementById('global-enabled').checked;
    const message = document.getElementById('global-msg').value.trim();
    const status = document.getElementById('global-status');
    const res = await fetch('/api/admin/banner/global', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, message }),
    });
    if (res.ok) {
      status.style.color = '#27ae60';
      status.textContent = 'Saved.';
    } else {
      const body = await res.json().catch(() => ({}));
      status.style.color = '#c0392b';
      status.textContent = body.error || 'Save failed.';
    }
    btn.disabled = false;
    setTimeout(function() { status.textContent = ''; }, 3000);
  }

  async function saveSite(site, btn) {
    btn.disabled = true;
    const enabled = document.getElementById('en-' + site).checked;
    const message = document.getElementById('msg-' + site).value.trim();
    const res = await fetch('/api/admin/banner/' + encodeURIComponent(site), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, message }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      alert(body.error || 'Save failed.');
    }
    btn.disabled = false;
  }

  async function clearSite(site, btn) {
    if (!confirm('Clear banner config for "' + site + '"?')) return;
    btn.disabled = true;
    const res = await fetch('/api/admin/banner/' + encodeURIComponent(site), {
      method: 'DELETE',
    });
    if (res.ok) {
      document.getElementById('en-' + site).checked = false;
      document.getElementById('msg-' + site).value = '';
    } else {
      alert('Clear failed.');
    }
    btn.disabled = false;
  }
</script>
</body>
</html>`);
});

// ---------------------------------------------------------------------------
// PUT /api/admin/banner/global — write the global banner config.
// ---------------------------------------------------------------------------

/**
 * Inputs: JSON body { enabled: boolean, message: string }.
 * Outputs: { ok: true } on success; { error } (400) on validation failure.
 * Logic: trims message; enforces 300-char cap; writes to KV as JSON.
 */
app.put("/api/admin/banner/global", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lBody = await c.req.json<{
        enabled?: unknown;
        message?: unknown;
    }>();
    if (typeof lBody.enabled !== "boolean") {
        return c.json({ error: "enabled must be a boolean" }, 400);
    }
    const lMessage =
        typeof lBody.message === "string" ? lBody.message.trim() : "";
    if (lMessage.length > 300) {
        return c.json(
            { error: "message must be 300 characters or fewer" },
            400,
        );
    }

    await c.env.PLATFORM_ASSETS.put(
        "platform_banner",
        JSON.stringify({ enabled: lBody.enabled, message: lMessage }),
    );
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// PUT /api/admin/banner/:site — write a per-site banner config.
// ---------------------------------------------------------------------------

/**
 * Inputs: site path param; JSON body { enabled: boolean, message: string }.
 * Outputs: { ok: true } on success; { error } (400) on validation failure.
 * Logic: validates site key against SITE_RE; trims message; writes to KV.
 */
app.put("/api/admin/banner/:site", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lSite = c.req.param("site");
    if (!SITE_RE.test(lSite)) {
        return c.json({ error: "Invalid site name" }, 400);
    }

    const lBody = await c.req.json<{
        enabled?: unknown;
        message?: unknown;
    }>();
    if (typeof lBody.enabled !== "boolean") {
        return c.json({ error: "enabled must be a boolean" }, 400);
    }
    const lMessage =
        typeof lBody.message === "string" ? lBody.message.trim() : "";
    if (lMessage.length > 300) {
        return c.json(
            { error: "message must be 300 characters or fewer" },
            400,
        );
    }

    await c.env.PLATFORM_ASSETS.put(
        `platform_banner:${lSite}`,
        JSON.stringify({ enabled: lBody.enabled, message: lMessage }),
    );
    return c.json({ ok: true });
});

// ---------------------------------------------------------------------------
// DELETE /api/admin/banner/:site — remove a per-site banner config.
// ---------------------------------------------------------------------------

/**
 * Inputs: site path param.
 * Outputs: { ok: true }.
 * Logic: deletes the KV key; idempotent (missing key is not an error).
 */
app.delete("/api/admin/banner/:site", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lSite = c.req.param("site");
    if (!SITE_RE.test(lSite)) {
        return c.json({ error: "Invalid site name" }, 400);
    }

    await c.env.PLATFORM_ASSETS.delete(`platform_banner:${lSite}`);
    return c.json({ ok: true });
});

export default app;

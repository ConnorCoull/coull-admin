/**
 * coull-admin: admin panel for *.coull.ai
 *
 * Routes:
 *   GET  /                           → redirect to /requests
 *   GET  /requests                   → access request management (owner-only)
 *   GET  /feedback                   → feedback viewer (owner-only)
 *   GET  /api/admin/requests         → JSON list (owner-only)
 *   POST /api/admin/requests/:id/approve
 *   POST /api/admin/requests/:id/decline
 *   POST /api/admin/revoke
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
    try {
        const lHost = c.req.header("host") ?? "";
        const lSite = lHost.split(".")[0];
        const lResponse = await fetch(`https://coull.ai/favicon.svg?site=${lSite}`);
        if (lResponse.ok) {
            return new Response(lResponse.body, {
                headers: {
                    "Content-Type": "image/svg+xml",
                    "Cache-Control": "public, max-age=3600",
                },
            });
        }
    } catch {}
    return c.body(FALLBACK_SVG, 200, { "Content-Type": "image/svg+xml" });
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
function nav(xiActive: "requests" | "feedback"): string {
    const lRActive = xiActive === "requests" ? ' class="active"' : "";
    const lFActive = xiActive === "feedback" ? ' class="active"' : "";
    return `<nav class="nav">
  <a href="/requests"${lRActive}>Requests</a>
  <a href="/feedback"${lFActive}>Feedback</a>
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
`;

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
      <td>${escapeHtml(r.email)}</td>
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
      <td>${escapeHtml(r.email)}</td>
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
      <td style="font-size:.8rem;color:#555">${escapeHtml(r.email)}</td>
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
    const email = cells[1].textContent.trim();
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
      const tdE = document.createElement('td');
      tdE.textContent = email;
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

app.get("/feedback", async (c) => {
    const lUnauth = await requireOwner(c);
    if (lUnauth) return lUnauth;

    const lRows = await c.env.DB.prepare(
        "SELECT id, user_email, user_name, app_name, page_url," +
            " message, reason, created_at" +
            " FROM feedback ORDER BY created_at DESC",
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

    const lAppNames = [...new Set(lRows.results.map((r) => r.app_name))];
    const lAppOptions = lAppNames
        .map(
            (a) => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`,
        )
        .join("");

    // Reasons present in the data (pre-migration rows have none).
    const lReasons = [
        ...new Set(
            lRows.results
                .map((r) => r.reason)
                .filter((r): r is string => r !== null),
        ),
    ];
    const lReasonOptions = lReasons
        .map(
            (r) => `<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`,
        )
        .join("");

    const lFeedbackHtml =
        lRows.results.length === 0
            ? `<tr><td colspan="6" style="text-align:center;color:#888;padding:2rem">No feedback yet</td></tr>`
            : lRows.results
                  .map((r) => {
                      const lUserCell = r.user_email
                          ? `${escapeHtml(r.user_name ?? "—")}<br>` +
                            `<span style="color:#888;font-size:.8rem">${escapeHtml(r.user_email)}</span>`
                          : `<span style="color:#aaa">anonymous</span>`;
                      const lPageDisplay =
                          r.page_url.length > 50
                              ? `${r.page_url.slice(0, 50)}…`
                              : r.page_url;
                      const lReasonCell = r.reason
                          ? escapeHtml(r.reason)
                          : `<span style="color:#bbb">—</span>`;
                      return `
    <tr class="feedback-row" data-app="${escapeHtml(r.app_name)}" data-reason="${escapeHtml(r.reason ?? "")}">
      <td style="white-space:nowrap">${fmtDate(r.created_at)}</td>
      <td><code>${escapeHtml(r.app_name)}</code></td>
      <td>${lReasonCell}</td>
      <td>${lUserCell}</td>
      <td title="${escapeHtml(r.page_url)}" style="font-size:.8rem;color:#555">${escapeHtml(lPageDisplay)}</td>
      <td class="msg-cell">${escapeHtml(r.message)}</td>
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
<p class="subtitle">${lRows.results.length} submissions</p>
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
        <th>Date</th><th>App</th><th>Reason</th><th>User</th><th>Page</th><th>Message</th>
      </tr>
    </thead>
    <tbody id="feedback-body">${lFeedbackHtml}</tbody>
  </table>
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
</script>
</body>
</html>`);
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

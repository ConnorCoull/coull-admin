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

type Env = {
    DB: D1Database;
    OWNER_EMAIL: string;
    // Override to http://localhost:8788 in .dev.vars for local development.
    AUTH_URL?: string;
    // Service Binding to coull-auth — avoids same-zone HTTP 522s in production.
    AUTH_SERVICE?: { fetch(request: Request): Promise<Response> };
};

const app = new Hono<{ Bindings: Env }>();

// Origins permitted to POST /api/feedback with credentials.
const ALLOWED_ORIGINS = new Set([
    "https://flashcards.coull.ai",
    "http://localhost:5173",
]);

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
 * Inputs: raw string from untrusted source.
 * Outputs: HTML-safe string with &, <, >, ", ' escaped.
 * Logic: prevents XSS when interpolating user data into HTML templates.
 */
function escapeHtml(xiStr: string): string {
    return xiStr
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

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
*, *::before, *::after { box-sizing: border-box; }
body {
  font-family: system-ui, sans-serif;
  margin: 0;
  padding: 2rem;
  background: #f5f5f5;
  color: #111;
}
.nav { display: flex; gap: 1.25rem; margin-bottom: 2rem; }
.nav a {
  color: #666; text-decoration: none;
  font-size: .9rem; padding-bottom: .2rem;
}
.nav a.active {
  color: #111; font-weight: 600;
  border-bottom: 2px solid #111;
}
.nav a:hover { color: #111; }
.layout { display: flex; gap: 2rem; align-items: flex-start; }
.main { flex: 1; min-width: 0; }
.sidebar { width: 300px; flex-shrink: 0; position: sticky; top: 2rem; }
h1 { font-size: 1.25rem; margin: 0 0 .25rem; }
h2 { font-size: 1rem; margin: 2rem 0 .25rem; }
h2:first-child { margin-top: 0; }
.subtitle { color: #666; font-size: .9rem; margin: 0 0 1rem; }
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
        "SELECT id, email, name, createdAt, approved, declined" +
            " FROM access_requests ORDER BY createdAt DESC",
    ).all<{
        id: string;
        email: string;
        name: string;
        createdAt: number;
        approved: number;
        declined: number;
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
  <style>${SHARED_STYLES}</style>
</head>
<body>
${nav("requests")}
<div class="layout">
  <div class="main">
    <h1>Access Requests</h1>
    <p class="subtitle" id="pending-count">${lPending.length} pending</p>
    <table>
      <thead><tr><th>Name</th><th>Email</th><th>Requested</th><th>Action</th></tr></thead>
      <tbody id="pending-body">${lPendingHtml}</tbody>
    </table>

    <h2>Declined</h2>
    <p class="subtitle" id="declined-count">${lDeclined.length} declined</p>
    <input class="search" type="search" placeholder="Search by name or email…" oninput="filterDeclined(this.value)" />
    <table>
      <thead><tr><th>Name</th><th>Email</th><th>Requested</th><th>Action</th></tr></thead>
      <tbody id="declined-body">${lDeclinedHtml}</tbody>
    </table>
  </div>

  <div class="sidebar">
    <h2>Approved</h2>
    <p class="subtitle" id="approved-count">${lApproved.length} users</p>
    <input class="search" type="search" placeholder="Search…" oninput="filterApproved(this.value)" />
    <table>
      <thead><tr><th>Name</th><th>Email</th><th></th></tr></thead>
      <tbody id="approved-body">${lApprovedHtml}</tbody>
    </table>
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
        "SELECT id, email, name, createdAt, approved, declined" +
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
            " message, created_at" +
            " FROM feedback ORDER BY created_at DESC",
    ).all<{
        id: string;
        user_email: string | null;
        user_name: string | null;
        app_name: string;
        page_url: string;
        message: string;
        created_at: number;
    }>();

    const lAppNames = [...new Set(lRows.results.map((r) => r.app_name))];
    const lAppOptions = lAppNames
        .map(
            (a) => `<option value="${escapeHtml(a)}">${escapeHtml(a)}</option>`,
        )
        .join("");

    const lFeedbackHtml =
        lRows.results.length === 0
            ? `<tr><td colspan="5" style="text-align:center;color:#888;padding:2rem">No feedback yet</td></tr>`
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
                      return `
    <tr class="feedback-row" data-app="${escapeHtml(r.app_name)}">
      <td style="white-space:nowrap">${fmtDate(r.created_at)}</td>
      <td><code>${escapeHtml(r.app_name)}</code></td>
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
  <style>${SHARED_STYLES}</style>
</head>
<body>
${nav("feedback")}
<h1>Feedback</h1>
<p class="subtitle">${lRows.results.length} submissions</p>
<select class="filter-select" oninput="filterByApp(this.value)" style="max-width:200px">
  <option value="">All apps</option>
  ${lAppOptions}
</select>
<table>
  <thead>
    <tr>
      <th>Date</th><th>App</th><th>User</th><th>Page</th><th>Message</th>
    </tr>
  </thead>
  <tbody id="feedback-body">${lFeedbackHtml}</tbody>
</table>

<script>
  function filterByApp(val) {
    document.querySelectorAll('.feedback-row').forEach(row => {
      row.style.display = !val || row.dataset.app === val ? '' : 'none';
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

    let lBody: { message?: string; appName?: string; pageUrl?: string };
    try {
        lBody = await c.req.json();
    } catch (_) {
        return c.json({ error: "Invalid JSON" }, 400, lCors);
    }

    const lMessage = lBody.message?.trim() ?? "";
    const lAppName = lBody.appName?.trim() ?? "";
    const lPageUrl = lBody.pageUrl?.trim() ?? "";

    if (!lMessage || !lAppName || !lPageUrl) {
        return c.json(
            { error: "message, appName, and pageUrl are required" },
            400,
            lCors,
        );
    }
    if (lMessage.length > 2000) {
        return c.json(
            { error: "message too long (max 2000 chars)" },
            400,
            lCors,
        );
    }
    if (lAppName.length > 64) {
        return c.json({ error: "appName too long (max 64 chars)" }, 400, lCors);
    }
    if (lPageUrl.length > 512) {
        return c.json(
            { error: "pageUrl too long (max 512 chars)" },
            400,
            lCors,
        );
    }

    const lId = crypto.randomUUID();
    await c.env.DB.prepare(
        "INSERT INTO feedback" +
            " (id, user_id, user_email, user_name, app_name, page_url," +
            "  message, created_at)" +
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
        .bind(
            lId,
            lUser?.id ?? null,
            lUser?.email ?? null,
            lUser?.name ?? null,
            lAppName,
            lPageUrl,
            lMessage,
            Date.now(),
        )
        .run();

    return c.json({ ok: true }, 200, lCors);
});

export default app;

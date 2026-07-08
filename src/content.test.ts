/**
 * Tests for reading-papers and recommendations admin API routes.
 * Uses Hono's app.request() with mocked D1 and AUTH_SERVICE bindings.
 * No real DB or network calls are made.
 */

import { describe, expect, it } from "bun:test";
import app from "./index";

// ── Auth mock helpers ────────────────────────────────────────────────────────

const OWNER_EMAIL = "owner@test.coull.ai";

/**
 * Inputs: email of the "logged in" user (or null for unauthenticated).
 * Outputs: a mock AUTH_SERVICE binding.
 * Logic: the validate endpoint returns a user JSON for the given email,
 *   or a 401 for unauthenticated requests.
 */
function makeAuthService(xiEmail: string | null) {
    return {
        async fetch(_req: Request): Promise<Response> {
            if (xiEmail === null) {
                return new Response(null, { status: 401 });
            }
            return Response.json({
                id: "test-user-id",
                email: xiEmail,
                name: "Test User",
            });
        },
    };
}

// ── D1 mock helpers ──────────────────────────────────────────────────────────

interface D1MockOpts {
    // Returned by .all() calls
    rows?: unknown[];
    // Returned by .first() calls
    firstRow?: unknown;
    // Number of affected rows for .run() (default: 1)
    changes?: number;
    // Records each .batch() call's statement count, for assertions
    batchCalls?: number[];
}

/**
 * Inputs: options controlling what the D1 mock returns.
 * Outputs: a minimal D1Database-compatible mock.
 * Logic: every prepare().bind() chain returns the configured values so
 *   tests can verify route logic without touching a real database. .batch()
 *   just records how many statements it was given (via opts.batchCalls) and
 *   resolves each with a success result — real ordering isn't needed since
 *   routes bind the target values before batching.
 */
function makeDb(opts: D1MockOpts = {}): D1Database {
    const lChanges = opts.changes ?? 1;
    return {
        prepare(_sql: string) {
            return {
                bind(..._args: unknown[]) {
                    return {
                        async run() {
                            return {
                                success: true,
                                meta: { changes: lChanges },
                            };
                        },
                        async first<T>() {
                            return (opts.firstRow as T) ?? null;
                        },
                        async all<T>() {
                            return { results: (opts.rows ?? []) as T[] };
                        },
                    };
                },
                async run() {
                    return { success: true, meta: { changes: lChanges } };
                },
                async first<T>() {
                    return (opts.firstRow as T) ?? null;
                },
                async all<T>() {
                    return { results: (opts.rows ?? []) as T[] };
                },
            };
        },
        async batch(xiStatements: unknown[]) {
            opts.batchCalls?.push(xiStatements.length);
            return xiStatements.map(() => ({
                success: true,
                meta: { changes: 1 },
            }));
        },
    } as unknown as D1Database;
}

/**
 * Inputs: url path, HTTP method, body (optional), email for auth.
 * Outputs: Hono Response.
 * Logic: builds an app.request() call wiring up mock DB and auth bindings
 *   so each test controls exactly what the route sees.
 */
async function req(
    xiUrl: string,
    xiMethod: string,
    xiBody: unknown,
    xiEmail: string | null,
    xiDb: D1Database = makeDb(),
) {
    const lHeaders: Record<string, string> = {};
    let lBody: BodyInit | undefined;
    if (xiBody !== undefined) {
        lHeaders["content-type"] = "application/json";
        lBody = JSON.stringify(xiBody);
    }
    return app.request(
        xiUrl,
        { method: xiMethod, headers: lHeaders, body: lBody },
        {
            DB: xiDb,
            OWNER_EMAIL,
            AUTH_SERVICE: makeAuthService(xiEmail),
            AUTH_URL: "https://auth.coull.ai",
        },
    );
}

/**
 * Inputs: none.
 * Outputs: a minimal KVNamespace mock.
 * Logic: get()/list() return empty results — enough for admin GET pages to
 *   render their "nothing configured yet" state without throwing.
 */
function makeKv(): KVNamespace {
    return {
        async get() {
            return null;
        },
        async list() {
            return { keys: [], list_complete: true, cacheStatus: null };
        },
        async put() {},
        async delete() {},
    } as unknown as KVNamespace;
}

/**
 * Inputs: admin page path (e.g. "/content").
 * Outputs: Hono Response for a GET as the owner, with all bindings mocked.
 * Logic: used to verify a page renders and includes the shared toast helper,
 *   not to exercise any route-specific query logic.
 */
async function pageReq(xiUrl: string) {
    return app.request(
        xiUrl,
        { method: "GET" },
        {
            DB: makeDb(),
            OWNER_EMAIL,
            AUTH_SERVICE: makeAuthService(OWNER_EMAIL),
            AUTH_URL: "https://auth.coull.ai",
            PLATFORM_ASSETS: makeKv(),
        },
    );
}

// ── Reading papers ───────────────────────────────────────────────────────────

describe("POST /api/admin/reading", () => {
    // ── Standard cases ───────────────────────────────────────────────────

    it("adds a paper with all fields and returns { ok, id }", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            {
                title: "Attention Is All You Need",
                authors: "Vaswani et al.",
                year: 2017,
                href: "https://arxiv.org/abs/1706.03762",
            },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(200);
        const lData = await lRes.json();
        expect(lData.ok).toBe(true);
        expect(typeof lData.id).toBe("string");
        expect(lData.id.length).toBeGreaterThan(0);
    });

    it("adds a paper without an optional href", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            { title: "A Paper", authors: "Smith et al.", year: 2020 },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(200);
        const lData = await lRes.json();
        expect(lData.ok).toBe(true);
    });

    // ── Incorrect cases ──────────────────────────────────────────────────

    it("returns 400 when title is missing", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            { authors: "Smith et al.", year: 2020 },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
        const lData = await lRes.json();
        expect(lData.error).toBeTruthy();
    });

    it("returns 400 when authors is missing", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            { title: "A Paper", year: 2020 },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    it("returns 400 when year is too old (< 1900)", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            { title: "Old Paper", authors: "Plato", year: 380 },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    it("returns 400 when year is too far in future (> 2100)", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            { title: "Future Paper", authors: "Bot et al.", year: 2200 },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    it("returns 400 when href lacks http/https scheme", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            {
                title: "A Paper",
                authors: "X et al.",
                year: 2020,
                href: "ftp://example.com",
            },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    // ── Auth cases ───────────────────────────────────────────────────────

    it("redirects unauthenticated requests (302)", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            { title: "A Paper", authors: "X", year: 2020 },
            null,
        );
        expect(lRes.status).toBe(302);
    });

    it("returns 403 for a logged-in non-owner", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            { title: "A Paper", authors: "X", year: 2020 },
            "intruder@evil.com",
        );
        expect(lRes.status).toBe(403);
    });

    // ── Crazy cases ──────────────────────────────────────────────────────

    it("returns 400 when year is sent as a string", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            { title: "A Paper", authors: "X", year: "2025" },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    it("accepts a title containing script tags (storage is owner-only)", async () => {
        // Escaping is the renderer's responsibility; the API stores verbatim.
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            {
                title: "<script>alert(1)</script>",
                authors: "X",
                year: 2020,
            },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(200);
    });

    it("returns 400 for a javascript: href", async () => {
        const lRes = await req(
            "/api/admin/reading",
            "POST",
            {
                title: "A Paper",
                authors: "X",
                year: 2020,
                href: "javascript:alert(1)",
            },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });
});

describe("DELETE /api/admin/reading/:id", () => {
    // ── Standard cases ───────────────────────────────────────────────────

    it("deletes an existing paper and returns { ok: true }", async () => {
        const lRes = await req(
            "/api/admin/reading/some-paper-id",
            "DELETE",
            undefined,
            OWNER_EMAIL,
            makeDb({ changes: 1 }),
        );
        expect(lRes.status).toBe(200);
        const lData = await lRes.json();
        expect(lData.ok).toBe(true);
    });

    // ── Incorrect cases ──────────────────────────────────────────────────

    it("returns 404 when the paper does not exist", async () => {
        const lRes = await req(
            "/api/admin/reading/nonexistent-id",
            "DELETE",
            undefined,
            OWNER_EMAIL,
            makeDb({ changes: 0 }),
        );
        expect(lRes.status).toBe(404);
    });

    // ── Auth cases ───────────────────────────────────────────────────────

    it("redirects unauthenticated delete", async () => {
        const lRes = await req(
            "/api/admin/reading/x",
            "DELETE",
            undefined,
            null,
        );
        expect(lRes.status).toBe(302);
    });

    it("returns 403 for a non-owner delete", async () => {
        const lRes = await req(
            "/api/admin/reading/x",
            "DELETE",
            undefined,
            "other@test.com",
        );
        expect(lRes.status).toBe(403);
    });
});

// ── Recommendations ──────────────────────────────────────────────────────────

describe("POST /api/admin/recommendations", () => {
    // ── Standard cases ───────────────────────────────────────────────────

    it("adds a recommendation and returns { ok, id }", async () => {
        const lRes = await req(
            "/api/admin/recommendations",
            "POST",
            { category: "Album", text: "Some Album by Artist" },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(200);
        const lData = await lRes.json();
        expect(lData.ok).toBe(true);
        expect(typeof lData.id).toBe("string");
    });

    // ── Incorrect cases ──────────────────────────────────────────────────

    it("returns 400 when category is empty", async () => {
        const lRes = await req(
            "/api/admin/recommendations",
            "POST",
            { category: "", text: "Something" },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    it("returns 400 when text is missing", async () => {
        const lRes = await req(
            "/api/admin/recommendations",
            "POST",
            { category: "Film" },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    // ── Auth cases ───────────────────────────────────────────────────────

    it("returns 403 for a non-owner", async () => {
        const lRes = await req(
            "/api/admin/recommendations",
            "POST",
            { category: "Film", text: "Something" },
            "evil@test.com",
        );
        expect(lRes.status).toBe(403);
    });
});

describe("PUT /api/admin/recommendations/:id", () => {
    // ── Standard cases ───────────────────────────────────────────────────

    it("updates an existing recommendation", async () => {
        const lRes = await req(
            "/api/admin/recommendations/rec-id",
            "PUT",
            { category: "Painting", text: "New Painting Title" },
            OWNER_EMAIL,
            makeDb({ changes: 1 }),
        );
        expect(lRes.status).toBe(200);
        const lData = await lRes.json();
        expect(lData.ok).toBe(true);
    });

    // ── Incorrect cases ──────────────────────────────────────────────────

    it("returns 404 when the recommendation does not exist", async () => {
        const lRes = await req(
            "/api/admin/recommendations/nonexistent",
            "PUT",
            { category: "Film", text: "Something" },
            OWNER_EMAIL,
            makeDb({ changes: 0 }),
        );
        expect(lRes.status).toBe(404);
    });

    it("returns 400 when category is whitespace-only", async () => {
        const lRes = await req(
            "/api/admin/recommendations/rec-id",
            "PUT",
            { category: "   ", text: "Something" },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    // ── Auth cases ───────────────────────────────────────────────────────

    it("returns 403 for a non-owner update", async () => {
        const lRes = await req(
            "/api/admin/recommendations/rec-id",
            "PUT",
            { category: "Film", text: "Something" },
            "other@test.com",
        );
        expect(lRes.status).toBe(403);
    });
});

describe("DELETE /api/admin/recommendations/:id", () => {
    // ── Standard cases ───────────────────────────────────────────────────

    it("deletes a recommendation and returns { ok: true }", async () => {
        const lRes = await req(
            "/api/admin/recommendations/rec-id",
            "DELETE",
            undefined,
            OWNER_EMAIL,
            makeDb({ changes: 1 }),
        );
        expect(lRes.status).toBe(200);
        const lData = await lRes.json();
        expect(lData.ok).toBe(true);
    });

    // ── Incorrect cases ──────────────────────────────────────────────────

    it("returns 404 for a non-existent recommendation", async () => {
        const lRes = await req(
            "/api/admin/recommendations/gone",
            "DELETE",
            undefined,
            OWNER_EMAIL,
            makeDb({ changes: 0 }),
        );
        expect(lRes.status).toBe(404);
    });

    // ── Auth cases ───────────────────────────────────────────────────────

    it("redirects unauthenticated delete", async () => {
        const lRes = await req(
            "/api/admin/recommendations/x",
            "DELETE",
            undefined,
            null,
        );
        expect(lRes.status).toBe(302);
    });

    it("returns 403 for a non-owner delete", async () => {
        const lRes = await req(
            "/api/admin/recommendations/x",
            "DELETE",
            undefined,
            "not-owner@test.com",
        );
        expect(lRes.status).toBe(403);
    });

    // ── Crazy cases ──────────────────────────────────────────────────────

    it("handles a very long id safely (no SQL injection risk via param)", async () => {
        // The id is bound as a ? parameter in a prepared statement,
        // so even a malformed id is safe — it just returns 404.
        const lRes = await req(
            `/api/admin/recommendations/${"a".repeat(500)}`,
            "DELETE",
            undefined,
            OWNER_EMAIL,
            makeDb({ changes: 0 }),
        );
        expect(lRes.status).toBe(404);
    });
});

describe("POST /api/admin/recommendations/reorder", () => {
    // ── Standard cases ───────────────────────────────────────────────────

    it("accepts an id list and writes each as a sort_order via batch", async () => {
        const lBatchCalls: number[] = [];
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            { ids: ["rec-2", "rec-1", "rec-3"] },
            OWNER_EMAIL,
            makeDb({ batchCalls: lBatchCalls }),
        );
        expect(lRes.status).toBe(200);
        const lData = await lRes.json();
        expect(lData.ok).toBe(true);
        // One UPDATE statement per id, batched in a single call.
        expect(lBatchCalls).toEqual([3]);
    });

    it("accepts a single-id list", async () => {
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            { ids: ["only-one"] },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(200);
    });

    // ── Incorrect cases ──────────────────────────────────────────────────

    it("returns 400 when ids is missing", async () => {
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            {},
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    it("returns 400 when ids is an empty array", async () => {
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            { ids: [] },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    it("returns 400 when ids is not an array", async () => {
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            { ids: "rec-1" },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    it("returns 400 when ids contains a non-string element", async () => {
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            { ids: ["rec-1", 42] },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    it("returns 400 when ids contains an empty string", async () => {
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            { ids: ["rec-1", ""] },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(400);
    });

    // ── Auth cases ───────────────────────────────────────────────────────

    it("redirects an unauthenticated reorder", async () => {
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            { ids: ["rec-1"] },
            null,
        );
        expect(lRes.status).toBe(302);
    });

    it("returns 403 for a non-owner reorder", async () => {
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            { ids: ["rec-1"] },
            "not-owner@test.com",
        );
        expect(lRes.status).toBe(403);
    });

    // ── Crazy cases ──────────────────────────────────────────────────────

    it("handles a large id list safely (ids are bound, not interpolated)", async () => {
        const lIds = Array.from({ length: 200 }, (_, i) => `rec-${i}`);
        const lRes = await req(
            "/api/admin/recommendations/reorder",
            "POST",
            { ids: lIds },
            OWNER_EMAIL,
        );
        expect(lRes.status).toBe(200);
    });
});

// ── Toast notification wiring ───────────────────────────────────────────────
// Confirms the shared showToast() helper and its CSS reach every admin page,
// since each page's <script> is independently inlined (no shared bundle).

describe("admin pages include the toast helper", () => {
    const lPages = [
        "/requests",
        "/favicon",
        "/feedback",
        "/cv",
        "/content",
        "/banner",
    ];

    for (const lPage of lPages) {
        it(`${lPage} renders the showToast() helper and toast CSS`, async () => {
            const lRes = await pageReq(lPage);
            expect(lRes.status).toBe(200);
            const lHtml = await lRes.text();
            expect(lHtml).toContain("function showToast(");
            expect(lHtml).toContain(".toast-container");
            expect(lHtml).toContain(".toast--success");
            expect(lHtml).toContain(".toast--error");
        });
    }
});

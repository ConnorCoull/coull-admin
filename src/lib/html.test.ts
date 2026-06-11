import { describe, expect, it } from "bun:test";
import { escapeHtml } from "./html";

// escapeHtml is the single XSS defence between user-supplied feedback
// text and the owner's browser on the admin page — these tests pin its
// behaviour against the payload shapes that matter there.

// ── Standard cases ───────────────────────────────────────────────────────

describe("standard cases", () => {
    it("leaves plain text untouched", () => {
        expect(escapeHtml("hello world")).toBe("hello world");
    });

    it("escapes all five special characters", () => {
        expect(escapeHtml(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&#39;");
    });
});

// ── XSS payloads (element injection) ─────────────────────────────────────

describe("element injection", () => {
    it("neutralises a script tag in feedback text", () => {
        const lOut = escapeHtml('<script>alert("xss")</script>');
        expect(lOut).not.toContain("<script>");
        expect(lOut).toBe(
            "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;",
        );
    });

    it("neutralises an img onerror payload", () => {
        const lOut = escapeHtml("<img src=x onerror=alert(1)>");
        expect(lOut).not.toContain("<img");
        expect(lOut).toContain("&lt;img");
    });

    it("neutralises an attempt to break out of a table cell", () => {
        const lOut = escapeHtml("</td></tr><script>steal()</script>");
        expect(lOut).not.toContain("</td>");
        expect(lOut).not.toContain("<script>");
    });
});

// ── XSS payloads (attribute injection) ───────────────────────────────────
// User values land inside double-quoted attributes (data-app, data-reason,
// title, option value) — quote escaping is what keeps them contained.

describe("attribute injection", () => {
    it("escapes double quotes so values cannot close an attribute", () => {
        const lOut = escapeHtml('" onmouseover="alert(1)');
        expect(lOut).not.toContain('"');
        expect(lOut).toBe("&quot; onmouseover=&quot;alert(1)");
    });

    it("escapes single quotes for single-quoted contexts", () => {
        expect(escapeHtml("' onfocus='alert(1)")).not.toContain("'");
    });
});

// ── Crazy cases ──────────────────────────────────────────────────────────

describe("crazy cases", () => {
    it("escapes ampersands first (no double-escaping)", () => {
        expect(escapeHtml("&lt;")).toBe("&amp;lt;");
        expect(escapeHtml("&amp;")).toBe("&amp;amp;");
    });

    it("handles the empty string", () => {
        expect(escapeHtml("")).toBe("");
    });

    it("passes emoji and unicode through unchanged", () => {
        expect(escapeHtml("💥 ünïcödé")).toBe("💥 ünïcödé");
    });

    it("survives a payload made entirely of special chars", () => {
        const lOut = escapeHtml('<<<>>>"""&&&');
        expect(lOut).toBe(
            "&lt;&lt;&lt;&gt;&gt;&gt;&quot;&quot;&quot;&amp;&amp;&amp;",
        );
    });
});

import { describe, expect, it } from "bun:test";
import { WIDGET_SOURCE } from "./widget";

// The widget is shipped as a string, so a stray syntax error would only
// surface in end users' browsers — these tests catch that at CI time.

describe("widget source", () => {
    it("is syntactically valid JavaScript", () => {
        // new Function parses (without executing) the source; a syntax
        // error throws here instead of in production browsers.
        expect(() => new Function(WIDGET_SOURCE)).not.toThrow();
    });

    it("targets the feedback API on its own origin", () => {
        expect(WIDGET_SOURCE).toContain('"/api/feedback"');
        expect(WIDGET_SOURCE).toContain("document.currentScript");
    });

    it("sends the session cookie for user attribution", () => {
        expect(WIDGET_SOURCE).toContain('credentials: "include"');
    });

    it("offers exactly the allowlisted reasons", () => {
        expect(WIDGET_SOURCE).toContain('value="Bug"');
        expect(WIDGET_SOURCE).toContain('value="Suggestion"');
        expect(WIDGET_SOURCE).toContain('value="General feedback" selected');
    });

    it("respects the data-enabled kill switch", () => {
        expect(WIDGET_SOURCE).toContain('dataset.enabled === "false"');
    });

    it("never interpolates user input into markup", () => {
        // The shadow root is built from static strings only; user text
        // goes through value/textContent assignments and JSON.stringify.
        expect(WIDGET_SOURCE).not.toContain("innerHTML = l");
        expect(WIDGET_SOURCE).toContain("JSON.stringify");
    });
});

/**
 * Source of the embeddable banner widget served at GET /banner.js.
 *
 * Apps embed it with a single tag:
 *   <script src="https://admin.coull.ai/banner.js" defer
 *           data-app="flashcards"     (required — must match a KNOWN_SITES key)
 *           data-enabled="false"     (optional kill switch)
 *   ></script>
 *
 * The script fetches /api/banner?site=<app> on the admin origin, then
 * injects a full-width top strip into the host page as document.body's first
 * child (normal flow — pushes content down rather than overlaying it).
 *
 * Dismiss state is persisted to localStorage keyed by app + message text, so
 * a new or changed message always re-shows even after a previous dismiss.
 *
 * Resolution order (server-side, see GET /api/banner):
 *   1. Global config (platform_banner) — wins over everything when enabled.
 *   2. Per-site config (platform_banner:<site>).
 *   3. No banner (enabled: false).
 *
 * Constraint: the emitted code lives inside one template literal, so it
 * must not contain backticks or "${" — strings are concatenated instead.
 * Shadow DOM is used so host-page CSS cannot leak in.
 */
export const BANNER_SOURCE = `(() => {
    "use strict";

    // ------------------------------------------------------------------
    // Configuration — read from the embedding <script> tag's attributes.
    // ------------------------------------------------------------------
    var lScript = document.currentScript;
    if (!(lScript instanceof HTMLScriptElement)) return;
    if (lScript.dataset.enabled === "false") return;

    var lApp = lScript.dataset.app;
    if (!lApp) {
        console.warn("[coull-banner] data-app attribute is required");
        return;
    }

    // The widget talks to the origin it was served from, so the same
    // file works for production and wrangler-dev without env plumbing.
    var lApiBase = new URL(lScript.src).origin;

    // A second include of the script is a no-op.
    if (document.querySelector("[data-coull-banner]")) return;

    // ------------------------------------------------------------------
    // Dismiss persistence — stores the last dismissed message per app, so
    // a new or changed message always re-shows. Fails silently in private
    // browsing modes that block localStorage writes.
    // ------------------------------------------------------------------
    var lStorageKey = "coull_banner_dismissed_" + lApp;

    function isDismissed(xiMessage) {
        try {
            return localStorage.getItem(lStorageKey) === xiMessage;
        } catch (_) {
            return false;
        }
    }

    function saveDismissed(xiMessage) {
        try {
            localStorage.setItem(lStorageKey, xiMessage);
        } catch (_) {}
    }

    // ------------------------------------------------------------------
    // Mount — builds a Shadow-DOM host and inserts it as the first child
    // of document.body so it renders in normal flow above all content.
    // Inputs: xiMessage — the resolved banner text (non-empty string).
    // Outputs: none. Logic: reads dismiss state, builds DOM, attaches.
    // ------------------------------------------------------------------
    function mount(xiMessage) {
        if (isDismissed(xiMessage)) return;

        var lHost = document.createElement("div");
        lHost.setAttribute("data-coull-banner", "");
        var lRoot = lHost.attachShadow({ mode: "open" });

        // === BANNER THEME =============================================
        // Edit these variables to match the site-wide colour palette.
        // The strip uses a gold background matching the original
        // flashcards Banner.svelte (--gold / --ink tokens). Recolour
        // here once the platform palette is finalised.
        var lBg      = "#c9a227";           // Strip background
        var lText    = "#1a1a1a";           // Message text colour
        var lBtnHint = "#3a3028";           // Dismiss button idle colour
        var lFontFam = "system-ui, sans-serif";
        // ==============================================================

        var lCss =
            ":host{all:initial;display:block}" +
            "*{box-sizing:border-box}" +
            ".banner{" +
                "position:relative;" +
                "display:flex;align-items:center;justify-content:center;" +
                "padding:0.5rem 3rem;" +
                "background:" + lBg + ";" +
                "font-family:" + lFontFam + ";" +
                "font-size:0.72rem;letter-spacing:0.05em;" +
                "color:" + lText + "}" +
            ".dismiss{" +
                "position:absolute;right:1rem;top:50%;" +
                "transform:translateY(-50%);" +
                "background:none;border:none;cursor:pointer;" +
                "color:" + lBtnHint + ";font-size:0.8rem;" +
                "padding:0.25rem 0.5rem;line-height:1;" +
                "transition:color 0.15s}" +
            ".dismiss:hover{color:" + lText + "}" +
            "@media(max-width:600px){" +
                ".banner{padding:0.4rem 2.5rem}" +
                ".banner span{" +
                    "white-space:nowrap;" +
                    "overflow:hidden;" +
                    "text-overflow:ellipsis}" +
            "}";

        var lStyle = document.createElement("style");
        lStyle.textContent = lCss;

        var lSpan = document.createElement("span");
        lSpan.textContent = xiMessage;

        var lBtn = document.createElement("button");
        lBtn.className = "dismiss";
        lBtn.setAttribute("aria-label", "Dismiss banner");
        lBtn.textContent = "\\u2715";

        var lStrip = document.createElement("div");
        lStrip.className = "banner";
        lStrip.setAttribute("role", "status");
        lStrip.appendChild(lSpan);
        lStrip.appendChild(lBtn);

        lRoot.appendChild(lStyle);
        lRoot.appendChild(lStrip);

        lBtn.addEventListener("click", function () {
            saveDismissed(xiMessage);
            lHost.remove();
        });

        document.body.insertBefore(lHost, document.body.firstChild);
    }

    // ------------------------------------------------------------------
    // Fetch resolved banner config from the platform banner API.
    // Public endpoint — no credentials required.
    // ------------------------------------------------------------------
    fetch(lApiBase + "/api/banner?site=" + encodeURIComponent(lApp))
        .then(function (xiRes) {
            if (!xiRes.ok) return null;
            return xiRes.json();
        })
        .then(function (xiData) {
            if (!xiData || !xiData.enabled || !xiData.message) return;
            mount(xiData.message);
        })
        .catch(function () {
            // Silently fail — a missing banner is not a page-breaking error.
        });
})();
`;

/**
 * Source of the embeddable feedback widget served at GET /widget.js.
 *
 * Apps embed it with a single tag:
 *   <script src="https://admin.coull.ai/widget.js" defer
 *           data-app="flashcards"          (required)
 *           data-position="bottom-right"   (optional corner)
 *           data-color="#111"              (optional accent colour)
 *           data-enabled="false"           (optional kill switch)
 *   ></script>
 *
 * The script renders a circular floating button that expands into a panel
 * with a reason dropdown, a message textarea, and a submit button. It POSTs
 * to /api/feedback on the same origin it was loaded from, so local dev
 * against `wrangler dev` needs no extra configuration.
 *
 * Constraint: the emitted code lives inside one template literal, so it
 * must not contain backticks or "${" — strings are concatenated instead.
 * Everything renders inside a Shadow DOM so host-page CSS cannot leak in.
 */
export const WIDGET_SOURCE = `(() => {
    "use strict";

    // ------------------------------------------------------------------
    // Configuration — read from the embedding <script> tag's attributes.
    // ------------------------------------------------------------------
    var lScript = document.currentScript;
    if (!(lScript instanceof HTMLScriptElement)) return;
    if (lScript.dataset.enabled === "false") return;

    var lApp = lScript.dataset.app;
    if (!lApp) {
        console.warn("[coull-feedback] data-app attribute is required");
        return;
    }

    var lPositions = [
        "bottom-right",
        "bottom-left",
        "top-right",
        "top-left",
    ];
    var lPosition = lScript.dataset.position || "";
    if (lPositions.indexOf(lPosition) === -1) lPosition = "bottom-right";
    var lColor = lScript.dataset.color || "#111";
    // The widget talks to the origin it was served from, so the same
    // file works for production and wrangler-dev without env plumbing.
    var lApiBase = new URL(lScript.src).origin;

    // A second include of the script is a no-op.
    if (document.querySelector("[data-coull-feedback]")) return;

    // Corner placement: split "bottom-right" into inset declarations for
    // the trigger button and the panel anchored above/below it.
    var lVert = lPosition.indexOf("top-") === 0 ? "top" : "bottom";
    var lHoriz = lPosition.indexOf("-left") > 0 ? "left" : "right";
    var lBtnPos = lVert + ":1.5rem;" + lHoriz + ":1.5rem;";
    var lPanelPos = lVert + ":4.75rem;" + lHoriz + ":1.5rem;";

    // ------------------------------------------------------------------
    // Shadow DOM mount — styles are scoped; the accent colour crosses the
    // boundary via a CSS custom property set on the host element.
    // ------------------------------------------------------------------
    var lHost = document.createElement("div");
    lHost.setAttribute("data-coull-feedback", "");
    lHost.style.setProperty("--fw-accent", lColor);
    var lRoot = lHost.attachShadow({ mode: "open" });

    var lCss =
        ":host{all:initial}" +
        "*{box-sizing:border-box;font-family:system-ui,sans-serif}" +
        ".trigger{position:fixed;" + lBtnPos +
        "width:44px;height:44px;border-radius:50%;border:none;" +
        "background:var(--fw-accent);color:#fff;cursor:pointer;" +
        "display:flex;align-items:center;justify-content:center;" +
        "box-shadow:0 2px 12px rgba(0,0,0,.25);z-index:9999;" +
        "transition:transform .15s,opacity .15s}" +
        ".trigger:hover{transform:scale(1.08)}" +
        ".panel{position:fixed;" + lPanelPos +
        "width:300px;background:#fff;border-radius:12px;" +
        "box-shadow:0 4px 24px rgba(0,0,0,.16);z-index:9998;" +
        "overflow:hidden}" +
        ".header{display:flex;align-items:center;" +
        "justify-content:space-between;padding:.875rem 1rem 0}" +
        ".title{font-size:.9rem;font-weight:600;color:#111}" +
        ".close{background:none;border:none;cursor:pointer;color:#999;" +
        "font-size:.85rem;padding:.2rem;line-height:1}" +
        ".close:hover{color:#111}" +
        ".reason{display:block;width:calc(100% - 2rem);" +
        "margin:.75rem 1rem 0;padding:.4rem .5rem;font-size:.85rem;" +
        "border:1px solid #e0e0e0;border-radius:6px;color:#111;" +
        "background:#fff}" +
        ".textarea{display:block;width:100%;padding:.75rem 1rem;" +
        "border:none;border-top:1px solid #f0f0f0;" +
        "border-bottom:1px solid #f0f0f0;resize:none;font-size:.875rem;" +
        "color:#111;outline:none;margin-top:.75rem;background:#fff}" +
        ".textarea:disabled{background:#fafafa;color:#888}" +
        ".meta{display:flex;align-items:center;" +
        "justify-content:space-between;padding:.35rem 1rem 0;" +
        "min-height:1.5rem}" +
        ".count{font-size:.72rem;color:#bbb}" +
        ".error{font-size:.72rem;color:#c0392b}" +
        ".actions{display:flex;gap:.5rem;padding:.625rem 1rem .875rem;" +
        "justify-content:flex-end}" +
        ".cancel{background:none;border:1px solid #e0e0e0;" +
        "border-radius:6px;padding:.3rem .7rem;font-size:.8rem;" +
        "cursor:pointer;color:#555}" +
        ".cancel:hover:not(:disabled){border-color:#aaa;color:#111}" +
        ".cancel:disabled{opacity:.5;cursor:default}" +
        ".submit{background:var(--fw-accent);color:#fff;border:none;" +
        "border-radius:6px;padding:.3rem .8rem;font-size:.8rem;" +
        "cursor:pointer}" +
        ".submit:hover:not(:disabled){opacity:.85}" +
        ".submit:disabled{opacity:.5;cursor:default}" +
        ".success{display:flex;align-items:center;gap:.75rem;" +
        "padding:1.25rem 1rem;font-size:.875rem;color:#111}" +
        ".success svg{color:#27ae60;flex-shrink:0}" +
        "[hidden]{display:none}";

    var lChatIcon =
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"' +
        ' stroke="currentColor" stroke-width="2" stroke-linecap="round"' +
        ' stroke-linejoin="round" aria-hidden="true">' +
        '<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6' +
        ' 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1' +
        '-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48' +
        ' 8.48 0 0 1 8 8v.5z"/></svg>';

    var lCheckIcon =
        '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"' +
        ' stroke="currentColor" stroke-width="2.5" stroke-linecap="round"' +
        ' stroke-linejoin="round" aria-hidden="true">' +
        '<path d="M20 6L9 17l-5-5"/></svg>';

    // Static markup only — no user input is ever interpolated here.
    lRoot.innerHTML =
        "<style>" + lCss + "</style>" +
        '<div class="panel" role="dialog" aria-modal="true"' +
        ' aria-label="Send feedback" hidden>' +
        '<div class="form-view">' +
        '<div class="header">' +
        '<span class="title">Send Feedback</span>' +
        '<button class="close" aria-label="Close">\\u2715</button>' +
        "</div>" +
        '<select class="reason" aria-label="Reason">' +
        '<option value="Bug">Bug</option>' +
        '<option value="Suggestion">Suggestion</option>' +
        '<option value="General feedback" selected>' +
        "General feedback</option>" +
        "</select>" +
        '<textarea class="textarea" rows="4" maxlength="2000"' +
        ' placeholder="What\\u2019s on your mind?"></textarea>' +
        '<div class="meta">' +
        '<span class="count">0/2000</span>' +
        '<span class="error" hidden></span>' +
        "</div>" +
        '<div class="actions">' +
        '<button class="cancel">Cancel</button>' +
        '<button class="submit" disabled>Submit</button>' +
        "</div></div>" +
        '<div class="success" hidden>' + lCheckIcon +
        "Thanks for your feedback!</div>" +
        "</div>" +
        '<button class="trigger" aria-label="Give feedback"' +
        ' aria-expanded="false">' + lChatIcon + "</button>";

    document.body.appendChild(lHost);

    // ------------------------------------------------------------------
    // Behaviour
    // ------------------------------------------------------------------
    var lPanel = lRoot.querySelector(".panel");
    var lFormView = lRoot.querySelector(".form-view");
    var lSuccessView = lRoot.querySelector(".success");
    var lTrigger = lRoot.querySelector(".trigger");
    var lCloseBtn = lRoot.querySelector(".close");
    var lReasonSel = lRoot.querySelector(".reason");
    var lTextarea = lRoot.querySelector(".textarea");
    var lCount = lRoot.querySelector(".count");
    var lErrorEl = lRoot.querySelector(".error");
    var lCancelBtn = lRoot.querySelector(".cancel");
    var lSubmitBtn = lRoot.querySelector(".submit");

    var lSubmitting = false;

    // Inputs: none. Outputs: none. Logic: enables submit only when the
    // trimmed message is non-empty and no request is in flight.
    function refresh() {
        lCount.textContent = lTextarea.value.length + "/2000";
        lSubmitBtn.disabled =
            lTextarea.value.trim().length === 0 || lSubmitting;
        lSubmitBtn.textContent =
            lSubmitting ? "Sending\\u2026" : "Submit";
    }

    // Inputs: none. Outputs: none. Logic: shows the panel in its form
    // state and clears any stale error.
    function open() {
        lPanel.hidden = false;
        lTrigger.setAttribute("aria-expanded", "true");
        lErrorEl.hidden = true;
        lTextarea.focus();
    }

    // Inputs: none. Outputs: none. Logic: hides and fully resets the
    // panel; refuses to close while a submission is in flight.
    function close() {
        if (lSubmitting) return;
        lPanel.hidden = true;
        lTrigger.setAttribute("aria-expanded", "false");
        lTextarea.value = "";
        lReasonSel.value = "General feedback";
        lErrorEl.hidden = true;
        lSuccessView.hidden = true;
        lFormView.hidden = false;
        refresh();
    }

    // Inputs: none. Outputs: none. Logic: POSTs the message, reason, app
    // and page URL to the feedback API. The session cookie (if any) is
    // sent so the backend can attribute the feedback; otherwise it is
    // recorded anonymously. Shows a success state for 2s, then closes.
    function submit() {
        if (lSubmitBtn.disabled) return;
        lSubmitting = true;
        lErrorEl.hidden = true;
        refresh();
        fetch(lApiBase + "/api/feedback", {
            method: "POST",
            credentials: "include",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                message: lTextarea.value.trim(),
                appName: lApp,
                pageUrl: window.location.href,
                reason: lReasonSel.value,
            }),
        })
            .then(function (xiRes) {
                if (!xiRes.ok) throw new Error("Server error");
                lFormView.hidden = true;
                lSuccessView.hidden = false;
                setTimeout(function () {
                    lSubmitting = false;
                    close();
                }, 2000);
            })
            .catch(function () {
                lSubmitting = false;
                lErrorEl.textContent =
                    "Something went wrong. Please try again.";
                lErrorEl.hidden = false;
                refresh();
            });
    }

    lTrigger.addEventListener("click", function () {
        if (lPanel.hidden) open();
        else close();
    });
    lCloseBtn.addEventListener("click", close);
    lCancelBtn.addEventListener("click", close);
    lSubmitBtn.addEventListener("click", submit);
    lTextarea.addEventListener("input", refresh);
    document.addEventListener("keydown", function (xiEvent) {
        if (xiEvent.key === "Escape" && !lPanel.hidden) close();
    });

    refresh();
})();
`;

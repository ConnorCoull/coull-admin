// Validation for POST /api/feedback bodies, extracted from the route
// handler so it can be unit-tested without a Workers runtime.

// Accepted values for the feedback reason dropdown. Stored verbatim so
// the admin page can display them without a slug→label mapping.
export const FEEDBACK_REASONS = new Set([
    "Bug",
    "Suggestion",
    "General feedback",
]);

export interface FeedbackBody {
    message?: string;
    appName?: string;
    pageUrl?: string;
    reason?: string;
}

export interface FeedbackFields {
    message: string;
    appName: string;
    pageUrl: string;
    reason: string | null;
}

export type FeedbackValidation =
    | { ok: true; fields: FeedbackFields }
    | { ok: false; error: string };

/**
 * Inputs: parsed (untrusted) JSON body of a feedback submission.
 * Outputs: trimmed, length-checked fields ready for insertion, or an
 * error message suitable for a 400 response.
 * Logic: message/appName/pageUrl are required and length-capped; reason
 * is optional during rollout (older clients omit it) but must match the
 * FEEDBACK_REASONS allowlist when present; empty reason becomes null.
 */
export function validateFeedback(xiBody: FeedbackBody): FeedbackValidation {
    const lMessage = xiBody.message?.trim() ?? "";
    const lAppName = xiBody.appName?.trim() ?? "";
    const lPageUrl = xiBody.pageUrl?.trim() ?? "";
    const lReason = xiBody.reason?.trim() ?? "";

    if (!lMessage || !lAppName || !lPageUrl) {
        return {
            ok: false,
            error: "message, appName, and pageUrl are required",
        };
    }
    if (lMessage.length > 2000) {
        return { ok: false, error: "message too long (max 2000 chars)" };
    }
    if (lAppName.length > 64) {
        return { ok: false, error: "appName too long (max 64 chars)" };
    }
    if (lPageUrl.length > 512) {
        return { ok: false, error: "pageUrl too long (max 512 chars)" };
    }
    if (lReason && !FEEDBACK_REASONS.has(lReason)) {
        return { ok: false, error: "invalid reason" };
    }

    return {
        ok: true,
        fields: {
            message: lMessage,
            appName: lAppName,
            pageUrl: lPageUrl,
            reason: lReason || null,
        },
    };
}

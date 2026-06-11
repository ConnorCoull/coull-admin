/**
 * Inputs: raw string from untrusted source.
 * Outputs: HTML-safe string with &, <, >, ", ' escaped.
 * Logic: prevents XSS when interpolating user data into HTML templates.
 */
export function escapeHtml(xiStr: string): string {
    return xiStr
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

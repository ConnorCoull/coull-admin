/**
 * Drop-in Hono middleware for *.coull.ai consumer apps.
 *
 * Usage (in another Worker):
 *   import { authMiddleware } from "../../coull-auth/middleware/auth";
 *   app.use("*", authMiddleware);
 *   // Then in a route: const user = c.get("user");
 *
 * No dependencies beyond Hono.
 */

import type { MiddlewareHandler } from "hono";

const AUTH_VALIDATE_URL = "https://auth.coull.ai/validate";
const AUTH_LOGIN_URL = "https://auth.coull.ai/login";

export type User = {
    id: string;
    email: string;
    name: string;
};

// Extend Hono's context variable map so consumers get type-safe c.get("user").
declare module "hono" {
    interface ContextVariableMap {
        user: User;
    }
}

/**
 * Inputs: Hono context with incoming request cookies, next handler.
 * Outputs: attaches validated User to context, or redirects to /login.
 * Logic: forwards the raw Cookie header to auth.coull.ai/validate so it
 *   can parse the Better Auth session token without the middleware needing
 *   to know the cookie name.
 */
export const authMiddleware: MiddlewareHandler = async (c, next) => {
    const cookieHeader = c.req.header("cookie") ?? "";

    const res = await fetch(AUTH_VALIDATE_URL, {
        headers: { cookie: cookieHeader },
    });

    if (!res.ok) {
        // Preserve the current URL so auth can redirect back after sign-in.
        const returnURL = encodeURIComponent(c.req.url);
        return c.redirect(`${AUTH_LOGIN_URL}?callbackURL=${returnURL}`, 302);
    }

    const user = (await res.json()) as User;
    c.set("user", user);
    await next();
};

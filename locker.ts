import { Context, Next } from "@hono/hono";
import { getAuth, oidcAuthMiddleware, revokeSession } from "@hono/oidc-auth";

export const emailRegexpChecker = (allowedEmails: string[]) => (email: string) => {
  return allowedEmails.some((pattern) => {
    if (email === pattern) return true;
    try {
      return new RegExp(pattern).test(email);
    } catch {
      return false;
    }
  });
};

export const Locker = {
  checker: undefined as ((email: string) => boolean) | undefined,

  async init(
    { domain, secret, oidc_issuer, checker }: {
      domain: string;
      secret: string;
      oidc_issuer: string;
      checker?: (email: string) => boolean;
    },
  ) {
    Deno.env.set("OIDC_CLIENT_ID", `https://${domain}/auth`);

    const secretString = domain + secret;
    const secretData = new TextEncoder().encode(secretString);
    const hashBuffer = await crypto.subtle.digest("SHA-256", secretData);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    Deno.env.set("OIDC_AUTH_SECRET", hashHex);

    Deno.env.set("OIDC_CLIENT_SECRET", "this.isnt-used-by-lastlogin");
    Deno.env.set("OIDC_ISSUER", oidc_issuer);

    if (checker) this.checker = checker;

    return this;
  },

  oidcAuthMiddleware() {
    return oidcAuthMiddleware();
  },

  async revokeSession(c: Context) {
    return await revokeSession(c);
  },

  check(validator?: (email: string) => boolean) {
    return async (c: Context, next: Next) => {
      const auth = await getAuth(c);
      const email = auth?.email;
      const v = validator || this.checker;
      const isAllowed = typeof email === "string" && v && v(email);

      if (!isAllowed) {
        const err = `permission denied for <${email}>`;
        console.error(err);
        await revokeSession(c);
        return c.text(err, 403);
      }
      await next();
    };
  },
};

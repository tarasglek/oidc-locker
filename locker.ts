import { Context, Next } from "@hono/hono";
import { getAuth, oidcAuthMiddleware, revokeSession } from "@hono/oidc-auth";

export const Locker = {
  async init(
    { domain, secret, oidc_issuer }: {
      domain: string;
      secret: string;
      oidc_issuer: string;
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

    return this;
  },

  oidcAuthMiddleware() {
    return oidcAuthMiddleware();
  },

  check(validator: (email: string) => boolean) {
    return async (c: Context, next: Next) => {
      const auth = await getAuth(c);
      const email = auth?.email;
      const isAllowed = typeof email === "string" && validator(email);

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

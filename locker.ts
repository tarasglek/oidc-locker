import type { Context, Next } from "@hono/hono";
import {
  getAuth,
  initOidcAuthMiddleware,
  type OidcAuthEnv,
  oidcAuthMiddleware,
  revokeSession,
} from "@hono/oidc-auth";

export const getSecret = async (salt: string): Promise<string> => {
  // Calculate boot time floored to the hour to ensure stability across restarts
  // while still being specific to this boot instance (mostly).
  const bootTimeHour = Math.floor(
    (Date.now() - Deno.osUptime() * 1000) / 3600000,
  );
  // console.log("Boot time hour:", bootTimeHour);

  const secretString = salt + Deno.cwd() + Deno.hostname() + bootTimeHour;
  const secretData = new TextEncoder().encode(secretString);
  const hashBuffer = await crypto.subtle.digest("SHA-256", secretData);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hashHex;
};

export const emailRegexpChecker =
  (allowedEmails: string[]) => async (c: Context): Promise<boolean> => {
    const auth = await getAuth(c);
    const email = auth?.email;
    if (typeof email !== "string") return false;
    return allowedEmails.some((pattern) => {
      if (email === pattern) return true;
      try {
        return new RegExp(pattern).test(email);
      } catch {
        return false;
      }
    });
  };

export interface Locker {
  checker: ((c: Context) => Promise<boolean> | boolean) | undefined;
  oidcConfig: Partial<OidcAuthEnv> | undefined;
  getAuth(c: Context): ReturnType<typeof getAuth>;
  init(config: {
    domain: string;
    secret: string;
    oidc_issuer: string;
    checker?: (c: Context) => Promise<boolean> | boolean;
  }): Promise<Locker>;
  oidcAuthMiddleware(): (c: Context, next: Next) => Promise<Response | void>;
  revokeSession(c: Context): Promise<void>;
  check(
    validator?: (c: Context) => Promise<boolean> | boolean,
  ): (c: Context, next: Next) => Promise<Response | void>;
}

export const Locker: Locker = {
  checker: undefined,
  oidcConfig: undefined,

  async init(
    { domain, secret, oidc_issuer, checker }: {
      domain: string;
      secret: string;
      oidc_issuer: string;
      checker?: (c: Context) => Promise<boolean> | boolean;
    },
  ) {
    this.oidcConfig = {
      OIDC_CLIENT_ID: `https://${domain}/auth`,
      OIDC_AUTH_SECRET: secret,
      OIDC_CLIENT_SECRET: "this.isnt-used-by-lastlogin",
      OIDC_ISSUER: oidc_issuer,
    };

    if (checker) this.checker = checker;

    return this;
  },

  oidcAuthMiddleware() {
    return async (c: Context, next: Next) => {
      if (!c.get("oidcAuthEnv")) {
        await initOidcAuthMiddleware(this.oidcConfig!)(c, async () => {});
      }
      return await oidcAuthMiddleware()(c, next);
    };
  },

  async revokeSession(c: Context) {
    if (!c.get("oidcAuthEnv")) {
      await initOidcAuthMiddleware(this.oidcConfig!)(c, async () => {});
    }
    await revokeSession(c);
  },

  getAuth(c: Context) {
    return getAuth(c);
  },

  check(validator?: (c: Context) => Promise<boolean> | boolean) {
    return async (c: Context, next: Next) => {
      if (!c.get("oidcAuthEnv")) {
        await initOidcAuthMiddleware(this.oidcConfig!)(c, async () => {});
      }
      const v = validator || this.checker;
      const isAllowed = v ? await v(c) : false;

      if (!isAllowed) {
        const auth = await getAuth(c);
        const email = auth?.email;
        const err = `permission denied for <${email}>`;
        console.error(err);
        await revokeSession(c);
        return c.text(err, 403);
      }
      await next();
    };
  },
};

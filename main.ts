import { Hono } from "@hono/hono";
import { logger } from "@hono/hono/logger";
import { getAuth, oidcAuthMiddleware, revokeSession } from "@hono/oidc-auth";
import { serveStatic } from "@hono/hono/deno";

console.log(`main.ts path: ${import.meta.url}`);

const config = JSON.parse(await Deno.readTextFile("./config.json"));
const allowedEmails: string[] = config.allowedEmails;

const app = new Hono();

app.use("*", async (c, next) => {
  const host = c.req.header("x-forwarded-host");
  if (host) {
    console.log(`App domain: ${host}`);
    Deno.env.set("OIDC_CLIENT_ID", `https://${host}/auth`);

    const secretString = host + import.meta.url;
    const secretData = new TextEncoder().encode(secretString);
    const hashBuffer = await crypto.subtle.digest("SHA-256", secretData);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    Deno.env.set("OIDC_AUTH_SECRET", hashHex);

    Deno.env.set("OIDC_CLIENT_SECRET", "this.isnt-used-by-lastlogin");
    Deno.env.set("OIDC_ISSUER", "https://lastlogin.net/");
  }
  await next();
}).use(logger())
  .get("/logout", async (c) => {
    await revokeSession(c);
    return c.html(
      `You have been successfully logged out! <a href="/">home</a>`,
    );
  })
  .use("*", oidcAuthMiddleware())
  .use("*", async (c, next) => {
    const auth = await getAuth(c);
    const email = auth?.email;
    const isAllowed = typeof email === "string" &&
      allowedEmails.some((pattern) => {
        if (email === pattern) return true;
        try {
          return new RegExp(pattern).test(email);
        } catch {
          return false;
        }
      });

    if (!isAllowed) {
      const err = `permission denied for <${email}>`;
      console.error(err);
      await revokeSession(c);
      return c.text(err, 403);
    }
    await next();
  })
  .get(
    "/*",
    serveStatic({
      root: "dist/",
    }),
  );
// .get("/", async (c) => {
//   const auth = await getAuth(c);
//   console.log("auth:", auth);
//   return c.html(`Hello &lt;${auth?.email}&gt;! <a href="/logout">Logout</a>`);
// });

export default app;

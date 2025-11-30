import { Hono } from "@hono/hono";
import { logger } from "@hono/hono/logger";
import { revokeSession } from "@hono/oidc-auth";
import { serveDir } from "@std/http/file-server";
import { Locker } from "./locker.ts";
const config = JSON.parse(await Deno.readTextFile("./config.json"));
const allowedEmails: string[] = config.allowedEmails;

let locker: typeof Locker | undefined;

const app = new Hono();

app.use("*", async (c, next) => {
  const host = c.req.header("x-forwarded-host");
  if (host) {
    if (!locker) {
      locker = await Locker.init({
        domain: host,
        secret: import.meta.url,
        oidc_issuer: "https://lastlogin.net/",
      });
    }
  }
  await next();
}).use(logger())
  .get("/logout", async (c) => {
    await revokeSession(c);
    return c.html(
      `You have been successfully logged out! <a href="/">home</a>`,
    );
  })
  .use("*", (c, next) => locker!.oidcAuthMiddleware()(c, next))
  .use("*", (c, next) =>
    locker!.check((email) =>
      allowedEmails.some((pattern) => {
        if (email === pattern) return true;
        try {
          return new RegExp(pattern).test(email);
        } catch {
          return false;
        }
      })
    )(c, next))
  .get(
    "/*",
    (c) => {
      // this actually includes content-length unlike hono's serveStatic
      return serveDir(c.req.raw, {
        fsRoot: "dist",
      });
    },
  );
// .get("/", async (c) => {
//   const auth = await getAuth(c);
//   console.log("auth:", auth);
//   return c.html(`Hello &lt;${auth?.email}&gt;! <a href="/logout">Logout</a>`);
// });

export default app;

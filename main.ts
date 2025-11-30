import { Hono } from "@hono/hono";
import { logger } from "@hono/hono/logger";
import { getAuth, oidcAuthMiddleware, revokeSession } from "@hono/oidc-auth";
import { serveDir } from "@std/http/file-server";
import { Locker } from "./locker.ts";
const config = JSON.parse(await Deno.readTextFile("./config.json"));
const allowedEmails: string[] = config.allowedEmails;

const app = new Hono();

app.use("*", async (c, next) => {
  const host = c.req.header("x-forwarded-host");
  if (host) {
    await Locker.init({
      domain: host,
      secret: import.meta.url,
      oidc_issuer: "https://lastlogin.net/",
    });// should do let locker = undefined...then set it rval of Locker.init if its not defined. AI!
  }
  await next();
}).use(logger())
  .get("/logout", async (c) => {
    await revokeSession(c);
    return c.html(
      `You have been successfully logged out! <a href="/">home</a>`,
    );
  })
  .use("*", oidcAuthMiddleware())// move to locker.oidcAuthMiddleware() AI!
  .use("*", async (c, next) => {//shoild move this into locker.check() middleware that we pass validator(email) labmda to AI!
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

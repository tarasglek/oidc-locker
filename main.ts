import { Hono } from "@hono/hono";
import type { Context } from "@hono/hono";
import { logger } from "@hono/hono/logger";
import { serveDir } from "@std/http/file-server";
import { emailRegexpChecker, getSecret, Locker } from "./locker.ts"; // use jsr:@tarasglek/locker
const config = JSON.parse(await Deno.readTextFile("./config.json"));

export const getOidcIssuer = (getEnv = Deno.env.get): string =>
  getEnv("OIDC_ISSUER") ?? "https://lastlogin.net/";

export const getSessionSecretSalt = (
  host: string,
  moduleUrl = import.meta.url,
  oidcIssuer = getOidcIssuer(),
): string => host + moduleUrl + oidcIssuer;

let locker: typeof Locker | undefined;

const app = new Hono();

app.use("*", async (c, next) => {
  const host = c.req.header("x-forwarded-host");
  if (host) {
    if (!locker) {
      const oidcIssuer = getOidcIssuer();
      locker = await Locker.init({
        domain: host,
        secret: await getSecret(
          getSessionSecretSalt(host, import.meta.url, oidcIssuer),
        ),
        oidc_issuer: oidcIssuer,
        checker: emailRegexpChecker(config.allowedEmails as string[]),
      });
    }
  }
  await next();
}).use(logger())
  .get("/logout", async (c) => {
    await locker!.revokeSession(c as Context);
    return c.html(
      `You have been successfully logged out! <a href="/">home</a>`,
    );
  })
  .use("*", (c, next) => locker!.oidcAuthMiddleware()(c, next))
  .use("*", (c, next) => locker!.check()(c, next))
  .get("/", async (c) => {
    const auth = await locker!.getAuth(c);
    console.log("auth:", auth);
    return c.html(`Hello &lt;${auth?.email}&gt;! <a href="/logout">Logout</a>`);
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

export default app;

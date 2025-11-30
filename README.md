# Locker - OIDC Authentication for Deno/Hono Apps

A library to quickly add OIDC authentication to Deno/Hono applications. Uses LastLogin.net for authentication.

## Features
- Simple email-based access control with regex support
- Automatic session management
- Easy integration with Hono apps

## Usage Example

Here's how to use it in a Hono app:

```typescript
import { Hono } from "@hono/hono";
import { logger } from "@hono/hono/logger";
import { serveDir } from "@std/http/file-server";
import { Locker, emailRegexpChecker, getSecret } from "@tarasglek/locker";

const config = JSON.parse(await Deno.readTextFile("./config.json"));
let locker: typeof Locker | undefined;

const app = new Hono();

app.use("*", async (c, next) => {
  const host = c.req.header("x-forwarded-host");
  if (host && !locker) {
    locker = await Locker.init({
      domain: host,
      secret: await getSecret(host + import.meta.url),
      oidc_issuer: "https://lastlogin.net/",
      checker: emailRegexpChecker(config.allowedEmails as string[]),
    });
  }
  await next();
})
.use(logger())
.get("/logout", async (c) => {
  await locker!.revokeSession(c);
  return c.html(`You have been successfully logged out! <a href="/">home</a>`);
})
.use("*", (c, next) => locker!.oidcAuthMiddleware()(c, next))
.use("*", (c, next) => locker!.check()(c, next))
.get("/*", (c) => serveDir(c.req.raw, { fsRoot: "dist" }));

export default app;
```

## Configuration

1. Copy `sample_config.json` to `config.json`
2. Edit `config.json` and add your users' emails (supports regex)
3. Put your static files in `dist/`
4. Run with `deno task start` or deploy to SmallWeb

Designed for [smallweb.run](https://smallweb.run). Automatically figures out OIDC client ID and secret from the `x-forwarded-host` header.

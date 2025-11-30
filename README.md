# Locker - OIDC Authentication for Deno/Hono Apps

A library to quickly add OIDC authentication to Deno/Hono applications. Has defaults to use LastLogin.net for authentication, but should be usable with other oidc providers.

## Features
- Simple email-based access control with regex support
- Automatic session management
- Easy integration with Hono apps

## Usage Example

See [main.ts](./main.ts) for a complete example of how to use this library in a Hono app.

## Configuration

1. Copy `sample_config.json` to `config.json`
2. Edit `config.json` and add your users' emails (supports regex)
3. Put your static files in `dist/`
4. Run with `deno task start` or deploy to SmallWeb

Designed for [smallweb.run](https://smallweb.run). Automatically figures out OIDC client ID and secret from the `x-forwarded-host` header.

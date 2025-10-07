# oidc-gated-static-server

minimal webserver to gate access to static files via oidc.

uses lastlogin.net for auth.

## usage

1. copy `sample_config.json` to `config.json`
2. edit `config.json` and add your users' emails. you can use regex.
3. put your static files in `dist/`
4. run it with `deno task start` or just drop the files into a smallweb app.

designed for [smallweb.run](https://smallweb.run). it figures out the oidc client id and secret from the `x-forwarded-host` header.

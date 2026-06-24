import { assertEquals } from "jsr:@std/assert@^1.0.14";
import { getOidcIssuer, getSessionSecretSalt } from "./main.ts";

Deno.test("getOidcIssuer defaults to LastLogin", () => {
  assertEquals(getOidcIssuer(() => undefined), "https://lastlogin.net/");
});

Deno.test("getOidcIssuer uses OIDC_ISSUER env override", () => {
  assertEquals(
    getOidcIssuer((key: string) =>
      key === "OIDC_ISSUER" ? "https://issuer.example" : undefined
    ),
    "https://issuer.example",
  );
});

Deno.test("getSessionSecretSalt includes issuer", () => {
  assertEquals(
    getSessionSecretSalt(
      "app.example",
      "file:///app/main.ts",
      "https://issuer.example",
    ),
    "app.examplefile:///app/main.tshttps://issuer.example",
  );
});

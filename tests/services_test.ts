import { assert, assertEquals, assertRejects } from "jsr:@std/assert";
import { generateKeys, sign } from "paseto-ts/v4";

// Utility to (re)initialize env keys before importing the services module
async function loadServices() {
  const { publicKey, secretKey } = generateKeys("public");
  Deno.env.set("PASETO_PUBLIC_KEY", publicKey);
  Deno.env.set("PASETO_SECRET_KEY", secretKey);
  // Re-import to ensure it reads current env values (module cache busting via unique query)
  const mod = await import(`../src/services.ts?cache_bust=${crypto.randomUUID()}`);
  return { ...mod, publicKey, secretKey } as typeof import("../src/services.ts") & {
    publicKey: string;
    secretKey: string;
  };
}

Deno.test("generateToken returns both access and refresh tokens that are verifiable", async () => {
  const { generateToken, publicKey } = await loadServices();
  const { accessToken, refreshToken } = await generateToken({ id: 42, role: "admin" });

  assert(typeof accessToken === "string" && accessToken.length > 10);
  assert(typeof refreshToken === "string" && refreshToken.length > 10);

  // Verify using library to ensure tokens are well-formed and signed with the public key
  const { payload: accessPayload } = await (await import("paseto-ts/v4")).verify(publicKey, accessToken);
  const { payload: refreshPayload } = await (await import("paseto-ts/v4")).verify(publicKey, refreshToken);
  assertEquals(accessPayload.id, 42);
  assertEquals(accessPayload.role, "admin");
  assertEquals(refreshPayload.id, 42);
  assertEquals(refreshPayload.role, "admin");
});

Deno.test("verifyToken succeeds for valid, non-expired token", async () => {
  const { verifyToken, secretKey } = await loadServices();
  const now = Date.now();
  const token = await sign(secretKey, {
    sub: "user-1",
    iat: new Date(now).toISOString(),
    exp: new Date(now + 60_000).toISOString(),
  });
  const res = await verifyToken(token);
  assertEquals(res.payload.sub, "user-1");
  assert(typeof res.exp === "string");
  assert(typeof res.iat === "string");
});

Deno.test("verifyToken throws UnauthorizedError for expired token", async () => {
  const { verifyToken, secretKey } = await loadServices();
  const now = Date.now();
  // Create a token that expires almost immediately, then wait a bit to ensure expiry
  const soonExpiring = await sign(secretKey, {
    sub: "user-1",
    iat: new Date(now - 120_000).toISOString(),
    exp: new Date(now + 10).toISOString(),
  });
  // small delay to ensure token is expired by the time we verify
  await new Promise((r) => setTimeout(r, 15));
  await assertRejects(
    () => verifyToken(soonExpiring),
    Error,
    "Session expired",
  );
});

Deno.test("verifyToken rejects for invalid token (wrong key)", async () => {
  const { verifyToken } = await loadServices();
  const otherKeys = generateKeys("public");
  const badToken = await sign(otherKeys.secretKey, {
    foo: "bar",
    iat: new Date().toISOString(),
    exp: new Date(Date.now() + 60_000).toISOString(),
  });
  await assertRejects(() => verifyToken(badToken));
});

Deno.test("refreshToken issues new tokens based on valid refresh token", async () => {
  const { refreshToken, secretKey, publicKey } = await loadServices();
  // Create a refresh token that is valid for some time
  const now = Date.now();
  const refToken = await sign(secretKey, {
    uid: 7,
    iat: new Date(now).toISOString(),
    exp: new Date(now + 7 * 60 * 60 * 1000).toISOString(),
  });
  const { accessToken, refreshToken: newRefresh } = await refreshToken(refToken);
  assert(accessToken && newRefresh);
  // Ensure the new access token verifies with public key and contains payload
  const verified = await (await import("paseto-ts/v4")).verify(publicKey, accessToken);
  assertEquals(verified.payload.uid, 7);
});

Deno.test("getTokenResponse sets refresh cookie and returns response payload", async () => {
  const { getTokenResponse } = await loadServices();
  const headers: Record<string, string | string[]> = {};
  const fakeContext: any = {
    header: (name: string, value: string) => {
      const key = name.toLowerCase();
      const existing = headers[key];
      if (existing === undefined) {
        headers[key] = value;
      } else if (Array.isArray(existing)) {
        existing.push(value);
        headers[key] = existing;
      } else {
        headers[key] = [existing, value];
      }
    },
  };
  const result = getTokenResponse({
    context: fakeContext,
    accessToken: "access-abc",
    refreshToken: "refresh-xyz",
  });

  assertEquals(result.access_token, "access-abc");
  assertEquals(result.user.username, "admin");
  // hono/cookie sets cookie via context.header("Set-Cookie", ...)
  // Our mock stores header names in lowercase
  assert("set-cookie" in headers);
  const cookieVal = headers["set-cookie"];
  if (Array.isArray(cookieVal)) {
    const joined = cookieVal.join("\n");
    assert(joined.includes("refresh_token="));
  } else {
    assert(String(cookieVal).includes("refresh_token="));
  }
});

Deno.test("verifyToken throws BadRequestError when token is missing", async () => {
  const { verifyToken } = await loadServices();
  await assertRejects(() => verifyToken(""), Error, "Missing token");
});

Deno.test("refreshToken throws BadRequestError when refToken is missing", async () => {
  const { refreshToken } = await loadServices();
  // Expect the service to throw its own specific message for missing refresh token
  // @ts-ignore - testing runtime behavior with undefined param
  await assertRejects(() => refreshToken(undefined), Error, "Missing refresh token");
});

Deno.test("refreshToken rejects expired refresh token", async () => {
  const { refreshToken, secretKey } = await loadServices();
  const now = Date.now();
  const expSoon = await sign(secretKey, {
    sub: "u1",
    iat: new Date(now - 120_000).toISOString(),
    exp: new Date(now + 5).toISOString(),
  });
  await new Promise((r) => setTimeout(r, 10));
  await assertRejects(() => refreshToken(expSoon), Error, "Session expired");
});

Deno.test("refreshToken rejects invalid refresh token (wrong key)", async () => {
  const { refreshToken } = await loadServices();
  const other = generateKeys("public");
  const badRef = await sign(other.secretKey, {
    sub: "x",
    iat: new Date().toISOString(),
    exp: new Date(Date.now() + 60_000).toISOString(),
  });
  await assertRejects(() => refreshToken(badRef), Error, "Invalid token");
});

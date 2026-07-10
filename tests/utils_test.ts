import { assert, assertEquals, assertRejects } from "jsr:@std/assert";
import { generateKeys, sign, verify } from "paseto-ts/v4";

// PASETO_* and SUPABASE_* env vars are read once at module-eval time in
// src/utils.ts, so they must be set before the module is ever imported in
// this process. A single dynamic import (after env setup) keeps the module
// singleton consistent across every test in this file.
const { publicKey, secretKey } = generateKeys("public");
Deno.env.set("PASETO_PUBLIC_KEY", publicKey);
Deno.env.set("PASETO_SECRET_KEY", secretKey);
Deno.env.set("SUPABASE_URL", "https://test.supabase.co");
Deno.env.set("SUPABASE_PUBLISHABLE_KEY", "test-anon-key");

const { paseto, supabase } = await import("../src/utils.ts");
const { generateToken, refreshToken, verifyToken } = paseto;
const { sanitizeMetadata } = supabase;

Deno.test("generateToken returns both access and refresh tokens that are verifiable", async () => {
  const { accessToken, refreshToken: newRefresh } = await generateToken({
    id: 42,
    role: "admin",
  });

  assert(typeof accessToken === "string" && accessToken.length > 10);
  assert(typeof newRefresh === "string" && newRefresh.length > 10);

  const { payload: accessPayload } = await verify(publicKey, accessToken);
  const { payload: refreshPayload } = await verify(publicKey, newRefresh);
  assertEquals(accessPayload.id, 42);
  assertEquals(accessPayload.role, "admin");
  assertEquals(refreshPayload.id, 42);
  assertEquals(refreshPayload.role, "admin");
});

Deno.test("verifyToken succeeds for valid, non-expired token", async () => {
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
  const now = Date.now();
  const soonExpiring = await sign(secretKey, {
    sub: "user-1",
    iat: new Date(now - 120_000).toISOString(),
    exp: new Date(now + 10).toISOString(),
  });
  await new Promise((r) => setTimeout(r, 15));
  await assertRejects(
    () => verifyToken(soonExpiring),
    Error,
    "Session expired",
  );
});

Deno.test("verifyToken rejects for invalid token (wrong key)", async () => {
  const other = generateKeys("public");
  const badToken = await sign(other.secretKey, {
    foo: "bar",
    iat: new Date().toISOString(),
    exp: new Date(Date.now() + 60_000).toISOString(),
  });
  await assertRejects(() => verifyToken(badToken));
});

Deno.test("verifyToken throws BadRequestError when token is missing", async () => {
  await assertRejects(() => verifyToken(""), Error, "Missing token");
});

Deno.test("refreshToken issues new tokens based on valid refresh token", async () => {
  const now = Date.now();
  const refToken = await sign(secretKey, {
    uid: 7,
    iat: new Date(now).toISOString(),
    exp: new Date(now + 7 * 60 * 60 * 1000).toISOString(),
  });
  const { accessToken, refreshToken: newRefresh } = await refreshToken(
    refToken,
  );
  assert(accessToken && newRefresh);
  const verified = await verify(publicKey, accessToken);
  assertEquals(verified.payload.uid, 7);
});

Deno.test("refreshToken throws BadRequestError when refToken is missing", async () => {
  // @ts-ignore - testing runtime behavior with undefined param
  await assertRejects(
    () => refreshToken(""),
    Error,
    "Missing refresh token",
  );
});

Deno.test("refreshToken rejects expired refresh token", async () => {
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
  const other = generateKeys("public");
  const badRef = await sign(other.secretKey, {
    sub: "x",
    iat: new Date().toISOString(),
    exp: new Date(Date.now() + 60_000).toISOString(),
  });
  await assertRejects(() => refreshToken(badRef), Error, "Invalid token");
});

Deno.test("sanitizeMetadata strips unsafe keys/values and keeps safe primitives", () => {
  const clean = sanitizeMetadata({
    full_name: "Jane Doe",
    age: 30,
    verified: true,
    empty: null,
    nested: { a: 1 },
    "bad-key": "value",
  });

  assertEquals(clean, {
    full_name: "Jane Doe",
    age: 30,
    verified: true,
    empty: null,
  });
});

Deno.test("sanitizeMetadata returns empty object when metadata is undefined", () => {
  assertEquals(sanitizeMetadata(undefined), {});
});

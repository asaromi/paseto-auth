import type { Context, Next } from "hono";
import { assert, assertEquals } from "jsr:@std/assert";
import { generateKeys, sign } from "paseto-ts/v4";

type FakeJsonResponse = {
  body: unknown;
  status?: number;
  headers: Record<string, string | string[]>;
};

type FakeContextOptions = {
  reqHeaders?: Record<string, string>;
  onHeaderThrow?: boolean;
  routePath?: string;
  jsonBody?: unknown;
  jsonThrows?: boolean;
};

function createFakeContext(opts: FakeContextOptions = {}) {
  const respHeaders: Record<string, string | string[]> = {};

  const reqHeaders = new Headers();
  for (const [key, value] of Object.entries(opts.reqHeaders ?? {})) {
    reqHeaders.set(key, value);
  }

  const rawRequest = new Request("http://localhost/test", {
    headers: reqHeaders,
  });

  let nextCalled = false;
  let nextCallCount = 0;

  const next: Next = async () => {
    nextCalled = true;
    nextCallCount += 1;
  };

  const c = {
    req: {
      header: (name: string) => reqHeaders.get(name) ?? undefined,
      json: async () => {
        if (opts.jsonThrows) throw new Error("invalid json");
        return opts.jsonBody ?? {};
      },
      raw: rawRequest,
      routePath: opts.routePath ?? "",
    },

    header: (name: string, value: string) => {
      if (opts.onHeaderThrow) {
        throw new Error("header failed");
      }

      const key = name.toLowerCase();
      const existing = respHeaders[key];

      if (existing === undefined) {
        respHeaders[key] = value;
      } else if (Array.isArray(existing)) {
        existing.push(value);
      } else {
        respHeaders[key] = [existing, value];
      }
    },

    json: (
      body: unknown,
      init?: number | ResponseInit,
    ): FakeJsonResponse => {
      const status = typeof init === "number" ? init : init?.status;

      return {
        body,
        status,
        headers: respHeaders,
      };
    },
  } as any;

  return {
    c: c as Context,
    next,
    respHeaders,
    get nextCalled() {
      return nextCalled;
    },
    get nextCallCount() {
      return nextCallCount;
    },
  } as const;
}

function mockSupabaseAuthFetch(
  matchPath: string,
  responseBody: unknown,
  status = 200,
) {
  return async (input: string | URL | Request) => {
    const url = String(input);
    if (url.includes(matchPath)) {
      return new Response(JSON.stringify(responseBody), {
        status,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ message: "not found" }), {
      status: 404,
    });
  };
}

// PASETO_* and SUPABASE_* env vars are read once at module-eval time in
// src/utils.ts, so they must be set before src/controllers.ts (and its
// transitive imports) are ever imported in this process.
const { publicKey, secretKey } = generateKeys("public");
Deno.env.set("PASETO_PUBLIC_KEY", publicKey);
Deno.env.set("PASETO_SECRET_KEY", secretKey);
Deno.env.set("SUPABASE_URL", "https://test.supabase.co");
Deno.env.set("SUPABASE_PUBLISHABLE_KEY", "test-anon-key");

const { login, register, verify, refresh, logout } = await import(
  "../src/controllers.ts"
);

const VALID_PASSWORD = "Password123!";
const VALID_FULL_NAME = "New User";

Deno.test("login returns token response and sets cookie", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = mockSupabaseAuthFetch("/auth/v1/token", {
      access_token: "supabase-access-token",
      token_type: "bearer",
      expires_in: 3600,
      refresh_token: "supabase-refresh-token",
      user: { id: "user-1", email: "admin@example.com" },
    });

    const { c, respHeaders } = createFakeContext({
      jsonBody: { email: "admin@example.com", password: VALID_PASSWORD },
    });
    const res = await login(c as any);
    const body = (res as any).body as any;
    assert(
      typeof body.access_token === "string" && body.access_token.length > 10,
    );
    assertEquals(body.user.id, "user-1");
    assert("set-cookie" in respHeaders);
    const sc = respHeaders["set-cookie"]!;
    const cookieStr = Array.isArray(sc) ? sc.join("\n") : sc;
    assert(String(cookieStr).includes("refresh_token="));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("login error path when response header setting fails", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = mockSupabaseAuthFetch("/auth/v1/token", {
      access_token: "supabase-access-token",
      token_type: "bearer",
      expires_in: 3600,
      refresh_token: "supabase-refresh-token",
      user: { id: "user-2", email: "admin@example.com" },
    });

    const { c } = createFakeContext({
      onHeaderThrow: true,
      jsonBody: { email: "admin@example.com", password: VALID_PASSWORD },
    });
    const res = await login(c as any);
    assertEquals((res as any).status, 500);
    const body = (res as any).body as any;
    assertEquals(body.error, "INTERNAL_SERVER_ERROR");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("login returns 400 when email/password are missing", async () => {
  const { c } = createFakeContext({ jsonBody: {} });
  const res = await login(c as any);
  assertEquals((res as any).status, 400);
  const body = (res as any).body as any;
  assertEquals(body.error, "BAD_REQUEST");
});

Deno.test("register returns 400 when profile.full_name is missing", async () => {
  const { c } = createFakeContext({
    jsonBody: { email: "new@example.com", password: VALID_PASSWORD },
  });
  const res = await register(c as any);
  assertEquals((res as any).status, 400);
  const body = (res as any).body as any;
  assertEquals(body.error, "BAD_REQUEST");
});

Deno.test("register returns token response with profile_synced true on success", async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  try {
    globalThis.fetch = async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      return await mockSupabaseAuthFetch("/auth/v1/signup", {
        access_token: "supabase-access-token",
        token_type: "bearer",
        expires_in: 3600,
        refresh_token: "supabase-refresh-token",
        user: { id: "user-3", email: "new@example.com" },
      })(input);
    };

    const { c } = createFakeContext({
      jsonBody: {
        email: "new@example.com",
        password: VALID_PASSWORD,
        profile: { full_name: VALID_FULL_NAME },
      },
    });
    const res = await register(c as any);
    const body = (res as any).body as any;
    assert(
      typeof body.access_token === "string" && body.access_token.length > 10,
    );
    assertEquals(body.user.id, "user-3");
    assertEquals(body.profile_synced, true);
    assert(calls.some((url) => url.includes("/auth/v1/signup")));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("verify succeeds with valid Authorization token", async () => {
  const now = Date.now();
  const token = await sign(secretKey, {
    uid: 99,
    iat: new Date(now).toISOString(),
    exp: new Date(now + 60_000).toISOString(),
  });
  const { c, next } = createFakeContext({
    reqHeaders: { Authorization: token },
    routePath: "/verify",
  });
  const res = await verify(c, next);
  assertEquals((res as any).status, undefined); // default status not set on success
  const body = (res as any).body as any;
  assertEquals(body.user.uid, 99);
  assertEquals(body.token, token);
});

Deno.test("verify returns 401 for expired token", async () => {
  const now = Date.now();
  const token = await sign(secretKey, {
    sub: "u1",
    iat: new Date(now - 120_000).toISOString(),
    exp: new Date(now + 5).toISOString(),
  });
  // wait to ensure expiration
  await new Promise((r) => setTimeout(r, 10));
  const { c, next } = createFakeContext({
    reqHeaders: { Authorization: token },
  });
  const res = await verify(c, next);
  const payload = (res as any).body as any;
  assertEquals((res as any).status, 401);
  assertEquals(payload.error, "EXPIRED_SESSION");
});

Deno.test("verify returns 401 for invalid token signed by wrong key", async () => {
  const other = generateKeys("public");
  const token = await sign(other.secretKey, {
    foo: "bar",
    iat: new Date().toISOString(),
    exp: new Date(Date.now() + 60_000).toISOString(),
  });
  const { c, next } = createFakeContext({
    reqHeaders: { Authorization: token },
  });
  const res = await verify(c, next);
  const payload = (res as any).body as any;
  assertEquals((res as any).status, 401);
  assertEquals(payload.error, "INVALID_CREDENTIALS");
});

Deno.test("refresh issues new tokens when refresh cookie is valid", async () => {
  const now = Date.now();
  const refToken = await sign(secretKey, {
    uid: 7,
    iat: new Date(now).toISOString(),
    exp: new Date(now + 7 * 60 * 60 * 1000).toISOString(),
  });
  const cookieHeader = `refresh_token=${refToken}; Path=/; HttpOnly`;
  const { c, respHeaders } = createFakeContext({
    reqHeaders: { Cookie: cookieHeader },
  });
  const res = await refresh(c as any);
  const body = (res as any).body as any;
  assert(
    typeof body.access_token === "string" && body.access_token.length > 10,
  );
  assert("set-cookie" in respHeaders);
});

Deno.test("refresh returns 401 when refresh cookie is missing", async () => {
  const { c } = createFakeContext();
  const res = await refresh(c as any);
  const payload = (res as any).body as any;
  assertEquals((res as any).status, 401);
  assertEquals(payload.error, "INVALID_CREDENTIALS");
});

Deno.test("refresh returns 401 when refresh token is invalid", async () => {
  const other = generateKeys("public");
  const badRef = await sign(other.secretKey, {
    sub: "x",
    iat: new Date().toISOString(),
    exp: new Date(Date.now() + 60_000).toISOString(),
  });
  const cookieHeader = `refresh_token=${badRef}; Path=/; HttpOnly`;
  const { c } = createFakeContext({ reqHeaders: { Cookie: cookieHeader } });
  const res = await refresh(c as any);
  const payload = (res as any).body as any;
  assertEquals((res as any).status, 401);
  assertEquals(payload.error, "INVALID_CREDENTIALS");
});

Deno.test("logout returns 401 not implemented", () => {
  const { c } = createFakeContext();
  const res = logout(c as any);
  const payload = (res as any).body as any;
  assertEquals((res as any).status, 401);
  assertEquals(payload.error, "EXPIRED_SESSION");
});

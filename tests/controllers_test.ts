import type { Context, Next } from "https://esm.sh/hono@4.4.7";
import { assert, assertEquals } from "jsr:@std/assert";
import { generateKeys, sign } from "paseto-ts/v4";

type FakeJsonResponse = {
  body: unknown;
  status?: number;
  headers: Record<string, string | string[]>;
};

type FakeContextOptions = {
  params?: Record<string, string>;
  reqHeaders?: Record<string, string>;
  onHeaderThrow?: boolean;
  routePath?: string;
  jsonBody?: unknown;
  jsonThrows?: boolean;
};

function createFakeContext(opts: FakeContextOptions = {}) {
  const respHeaders: Record<string, string | string[]> = {};
  const params = opts.params ?? {};

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
      param: (name: string) => params[name],
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


async function loadControllersWithFreshEnv() {
  const { publicKey, secretKey } = generateKeys("public");
  Deno.env.set("PASETO_PUBLIC_KEY", publicKey);
  Deno.env.set("PASETO_SECRET_KEY", secretKey);
  Deno.env.set("SUPABASE_URL", "https://test.supabase.co");
  Deno.env.set("SUPABASE_ANON_KEY", "anon-key");
  const mod = await import(`../src/controllers.ts?cache_bust=${crypto.randomUUID()}`);

  return { ...mod, publicKey, secretKey } as typeof import("../src/controllers.ts") & {
    publicKey: string;
    secretKey: string;
  };
}

Deno.test("generateKeysAuth returns keys and sets env", async () => {
  // No need to pre-seed env; controller generates and sets
  const { generateKeysAuth } = await import(
    `../src/controllers.ts?cache_bust=${crypto.randomUUID()}`
  );
  const { c } = createFakeContext({ params: { is_public: "true" } });
  const res = await generateKeysAuth(c as any);
  const body = (res as any).body as any;
  assert(typeof body.public_key === "string" && body.public_key.length > 10);
  assert(typeof body.secret_key === "string" && body.secret_key.length > 10);
  // Ensure env updated
  assertEquals(Deno.env.get("PASETO_PUBLIC_KEY"), body.public_key);
  assertEquals(Deno.env.get("PASETO_SECRET_KEY"), body.secret_key);
});

Deno.test("generateKeysAuth error path handled when env.set fails", async () => {
  const { generateKeysAuth } = await import(
    `../src/controllers.ts?cache_bust=${crypto.randomUUID()}`
  );
  const origSet = Deno.env.set.bind(Deno.env);
  try {
    // Make env.set throw to trigger catch -> errorHandler
    // @ts-ignore
    Deno.env.set = () => {
      throw new Error("env set blocked");
    };
    const { c } = createFakeContext({ params: { is_public: "true" } });
    const res = await generateKeysAuth(c as any);
    const payload = (res as any).body as any;
    assertEquals((res as any).status, 500);
    assertEquals(payload.error, "INTERNAL_SERVER_ERROR");
  } finally {
    // restore
    // @ts-ignore
    Deno.env.set = origSet;
  }
});

Deno.test("login returns token response and sets cookie", async () => {
  const { login } = await loadControllersWithFreshEnv();
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({
        user: { id: "user-1", email: "admin@example.com" },
        session: { access_token: "supabase-token" },
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    const { c, respHeaders } = createFakeContext({
      jsonBody: {
        email: "admin@example.com",
        password: "password123",
      },
    });
    const res = await login(c as any);
    const body = (res as any).body as any;
    assert(typeof body.access_token === "string" && body.access_token.length > 10);
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
  const { login } = await loadControllersWithFreshEnv();
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({
        user: { id: "user-2", email: "admin@example.com" },
        session: { access_token: "supabase-token" },
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    const { c } = createFakeContext({
      onHeaderThrow: true,
      jsonBody: {
        email: "admin@example.com",
        password: "password123",
      },
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
  const { login } = await loadControllersWithFreshEnv();
  const { c } = createFakeContext({ jsonBody: {} });
  const res = await login(c as any);
  assertEquals((res as any).status, 400);
  const body = (res as any).body as any;
  assertEquals(body.error, "BAD_REQUEST");
});

Deno.test("register returns token response with profile_synced false when metadata is absent", async () => {
  const { register } = await loadControllersWithFreshEnv();
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () =>
      new Response(JSON.stringify({
        user: { id: "user-3", email: "new@example.com" },
        session: { access_token: "supabase-token" },
      }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });

    const { c } = createFakeContext({
      jsonBody: {
        email: "new@example.com",
        password: "password123",
      },
    });
    const res = await register(c as any);
    const body = (res as any).body as any;
    assert(typeof body.access_token === "string" && body.access_token.length > 10);
    assertEquals(body.user.id, "user-3");
    assertEquals(body.profile_synced, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("register saves profile metadata when metadata is provided", async () => {
  const { register } = await loadControllersWithFreshEnv();
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  let profileRequestBody = "";
  try {
    globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      calls.push(url);
      if (url.includes("/auth/v1/signup")) {
        return new Response(JSON.stringify({
          user: { id: "user-4", email: "new2@example.com" },
          session: { access_token: "supabase-token" },
        }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      if (url.includes("/rest/v1/profile")) {
        profileRequestBody = String(init?.body || "");
        return new Response(JSON.stringify([{ id: "user-4" }]), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }

      return new Response(JSON.stringify({ message: "not found" }), {
        status: 404,
        headers: { "content-type": "application/json" },
      });
    };

    const { c } = createFakeContext({
      jsonBody: {
        email: "new2@example.com",
        password: "password123",
        metadata: { full_name: "New User", unsafe: { nested: true } },
      },
    });
    const res = await register(c as any);
    const body = (res as any).body as any;
    assertEquals(body.profile_synced, true);
    assert(calls.some((url) => url.includes("/auth/v1/signup")));
    assert(calls.some((url) => url.includes("/rest/v1/profile")));
    assert(profileRequestBody.includes("full_name"));
    assertEquals(profileRequestBody.includes("unsafe"), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("verify succeeds with valid Authorization token", async () => {
  const { verify, secretKey } = await loadControllersWithFreshEnv();
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
  const { verify, secretKey } = await loadControllersWithFreshEnv();
  const now = Date.now();
  const token = await sign(secretKey, {
    sub: "u1",
    iat: new Date(now - 120_000).toISOString(),
    exp: new Date(now + 5).toISOString(),
  });
  // wait to ensure expiration
  await new Promise((r) => setTimeout(r, 10));
  const { c, next } = createFakeContext({ reqHeaders: { Authorization: token } });
  const res = await verify(c, next);
  const payload = (res as any).body as any;
  assertEquals((res as any).status, 401);
  assertEquals(payload.error, "EXPIRED_SESSION");
});

Deno.test("verify returns 401 for invalid token signed by wrong key", async () => {
  const { verify } = await loadControllersWithFreshEnv();
  const other = generateKeys("public");
  const token = await sign(other.secretKey, {
    foo: "bar",
    iat: new Date().toISOString(),
    exp: new Date(Date.now() + 60_000).toISOString(),
  });
  const { c, next } = createFakeContext({ reqHeaders: { Authorization: token } });
  const res = await verify(c, next);
  const payload = (res as any).body as any;
  assertEquals((res as any).status, 401);
  assertEquals(payload.error, "INVALID_CREDENTIALS");
});

Deno.test("refresh issues new tokens when refresh cookie is valid", async () => {
  const { refresh, secretKey } = await loadControllersWithFreshEnv();
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
  assert(typeof body.access_token === "string" && body.access_token.length > 10);
  assert("set-cookie" in respHeaders);
});

Deno.test("refresh returns 401 when refresh cookie is missing", async () => {
  const { refresh } = await loadControllersWithFreshEnv();
  const { c } = createFakeContext();
  const res = await refresh(c as any);
  const payload = (res as any).body as any;
  assertEquals((res as any).status, 401);
  assertEquals(payload.error, "INVALID_CREDENTIALS");
});

Deno.test("refresh returns 401 when refresh token is invalid", async () => {
  const { refresh } = await loadControllersWithFreshEnv();
  const { secretKey } = generateKeys("public");
  const badRef = await sign(secretKey, {
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

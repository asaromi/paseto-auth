import { assert, assertEquals, assertRejects } from "jsr:@std/assert";

// SUPABASE_* env vars are read once at module-eval time (src/utils.ts), so
// they must be set before src/services.ts is ever imported in this process.
Deno.env.set("SUPABASE_URL", "https://test.supabase.co");
Deno.env.set("SUPABASE_PUBLISHABLE_KEY", "test-anon-key");
Deno.env.set("PASETO_PUBLIC_KEY", "unused-in-these-tests");
Deno.env.set("PASETO_SECRET_KEY", "unused-in-these-tests");

const { loginWithSupabase, registerWithSupabase, getTokenResponse } =
  await import(
    "../src/services.ts"
  );

const VALID_PASSWORD = "Password123!";
const VALID_FULL_NAME = "Jane Doe";

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

Deno.test("getTokenResponse sets refresh cookie and returns response payload", () => {
  const headers: Record<string, string | string[]> = {};
  const fakeContext: any = {
    header: (name: string, value: string) => {
      const key = name.toLowerCase();
      const existing = headers[key];
      if (existing === undefined) {
        headers[key] = value;
      } else if (Array.isArray(existing)) {
        existing.push(value);
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
  assert("set-cookie" in headers);
  const cookieVal = headers["set-cookie"];
  const cookieStr = Array.isArray(cookieVal)
    ? cookieVal.join("\n")
    : String(cookieVal);
  assert(cookieStr.includes("refresh_token="));
});

Deno.test("loginWithSupabase throws BadRequestError when email/password are missing", async () => {
  await assertRejects(
    // @ts-ignore - testing runtime behavior with an incomplete payload
    () => loginWithSupabase({ email: "", password: "" }),
    Error,
    "email and password are required",
  );
});

Deno.test("loginWithSupabase returns the Supabase user on success", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = mockSupabaseAuthFetch("/auth/v1/token", {
      access_token: "supabase-access-token",
      token_type: "bearer",
      expires_in: 3600,
      refresh_token: "supabase-refresh-token",
      user: { id: "user-1", email: "admin@example.com" },
    });

    const user = await loginWithSupabase({
      email: "admin@example.com",
      password: VALID_PASSWORD,
    });
    assertEquals(user.id, "user-1");
    assertEquals(user.email, "admin@example.com");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("loginWithSupabase throws BadRequestError when Supabase returns an error", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = mockSupabaseAuthFetch(
      "/auth/v1/token",
      {
        error: "invalid_grant",
        error_description: "Invalid login credentials",
      },
      400,
    );

    await assertRejects(
      () =>
        loginWithSupabase({
          email: "admin@example.com",
          password: "wrong-password",
        }),
      Error,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("registerWithSupabase throws BadRequestError when email is missing", async () => {
  await assertRejects(
    () =>
      registerWithSupabase({
        email: "",
        password: VALID_PASSWORD,
        metadata: { full_name: VALID_FULL_NAME },
      }),
    Error,
    "Email is required",
  );
});

Deno.test("registerWithSupabase throws BadRequestError when password is missing", async () => {
  await assertRejects(
    () =>
      registerWithSupabase({
        email: "new@example.com",
        password: "",
        metadata: { full_name: VALID_FULL_NAME },
      }),
    Error,
    "Password is required",
  );
});

Deno.test("registerWithSupabase throws BadRequestError when full_name is missing", async () => {
  await assertRejects(
    () =>
      registerWithSupabase({
        email: "new@example.com",
        password: VALID_PASSWORD,
      }),
    Error,
    "Invalid full name format",
  );
});

Deno.test("registerWithSupabase returns user with isSyncedMetadata on success", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = mockSupabaseAuthFetch("/auth/v1/signup", {
      access_token: "supabase-access-token",
      token_type: "bearer",
      expires_in: 3600,
      refresh_token: "supabase-refresh-token",
      user: { id: "user-2", email: "new@example.com" },
    });

    const result = await registerWithSupabase({
      email: "new@example.com",
      password: VALID_PASSWORD,
      metadata: { full_name: VALID_FULL_NAME },
    });
    assertEquals(result.id, "user-2");
    assertEquals(result.isSyncedMetadata, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("registerWithSupabase throws BadRequestError when Supabase returns an error", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = mockSupabaseAuthFetch(
      "/auth/v1/signup",
      { error: "email_exists", error_description: "Email already registered" },
      400,
    );

    await assertRejects(
      () =>
        registerWithSupabase({
          email: "existing@example.com",
          password: VALID_PASSWORD,
          metadata: { full_name: VALID_FULL_NAME },
        }),
      Error,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

import { assertEquals } from "jsr:@std/assert";
import { handleAuthLibError, errorHandler } from "../src/helpers.ts";
import { UnauthorizedError } from "../src/exceptions.ts";

Deno.test("handleAuthLibError maps expired and invalid errors and formats message", () => {
  const expiredErr = new Error("Token expired: signature ok");
  // @ts-ignore - simulate custom code and name fields like from libraries
  expiredErr.code = 401;
  // @ts-ignore
  expiredErr.name = "PASETO_ERROR";

  const resExpired = handleAuthLibError(expiredErr as unknown as Error);
  assertEquals(resExpired.code, 401);
  assertEquals(resExpired.error, "EXPIRED_SESSION");
  // Colons should be replaced with commas
  assertEquals(resExpired.message.includes(":"), false);

  const invalidErr = new Error("Invalid token provided");
  const resInvalid = handleAuthLibError(invalidErr as unknown as Error);
  assertEquals(resInvalid.code, 401);
  assertEquals(resInvalid.error, "INVALID_CREDENTIALS");

  const genericErr = new Error("Some other error");
  const resGeneric = handleAuthLibError(genericErr as unknown as Error);
  assertEquals(resGeneric.code, 401);
  assertEquals(resGeneric.error, "UNAUTHORIZED");
});

Deno.test("errorHandler returns structured response for ErrorResponse", () => {
  // Fake minimal Hono Context with json method
  const captured: { body?: unknown; status?: number } = {};
  const fakeContext: any = {
    json: (body: unknown, init?: { status?: number }) => {
      captured.body = body;
      captured.status = init?.status;
      return { body, status: init?.status };
    },
  };

  const err = new UnauthorizedError("No auth provided", "INVALID_CREDENTIALS");
  const result = errorHandler(fakeContext, err);
  // Ensure our fake context's json was called and result echoes it
  assertEquals((result as any).status, 401);
  const payload = (result as any).body as any;
  assertEquals(payload.code, 401);
  assertEquals(payload.error, "INVALID_CREDENTIALS");
  assertEquals(payload.message, "No auth provided");
});

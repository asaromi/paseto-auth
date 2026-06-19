import { Context } from "hono";
import { ErrorCode, ErrorResponse } from "./exceptions.ts";

export const isDebug = Deno.env.get("DEBUG") === "true";

export const handleAuthLibError = (error: any): { code: number; error: ErrorCode; message: string } => {
  try {
    const response: { code: number; error: ErrorCode; message: string } = {
      code: 401,
      error: "UNAUTHORIZED",
      message: "",
    };

    const code = (error && (error as any).code) as number | undefined;
    const name = (error && (error as any).name) as string | undefined;
    const message = (error && (error as any).message) as string | undefined;

    response.message = code ? `[${code}] ` : "";
    response.message += name ? `${name}: ` : "";
    response.message += (message || "");
    // Normalize colons out of the whole assembled message
    response.message = response.message.replaceAll(":", ",");

    const lower = response.message.toLowerCase();
    if (lower.includes("expired")) {
      response.error = "EXPIRED_SESSION";
    } else if (lower.includes("invalid")) {
      response.error = "INVALID_CREDENTIALS";
    }

    return response;
  } catch (err) {
    throw err;
  }
};

export const errorHandler = (
  c: Context,
  error: unknown,
) => {
  if (isDebug) {
    console.error(error);
  }

  let response: { code: number; error: ErrorCode; message: string } = {
    code: 500,
    error: "INTERNAL_SERVER_ERROR",
    message: "Internal Server Error",
  };

  if (error instanceof ErrorResponse) {
    response = {
      code: error.code || 500,
      error: error.name,
      message: error.message || "Internal Server Error",
    };
  } else if (
    typeof error === "object" && error !== null &&
    typeof (error as any).name === "string" &&
    (String((error as any).name).toLowerCase().includes("paseto"))
  ) {
    response = handleAuthLibError(error as any);
  }

  return c.json(
    response,
    { status: response.code },
  );
};

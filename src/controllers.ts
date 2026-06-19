import { Context, Next } from "hono";
import { getCookie } from "hono/cookie";
import { generateKeys } from "paseto-ts/v4";
import { BadRequestError, UnauthorizedError } from "./exceptions.ts";
import { errorHandler } from "./helpers.ts";
import {
  generateToken,
  getTokenResponse,
  refreshToken,
  verifyToken,
} from "./services.ts";

export const generateKeysAuth = (c: Context) => {
  try {
    // paseto-ts/v4 typings only expose 'public' purpose; use public keypair
    const { publicKey, secretKey } = generateKeys("public");

    Deno.env.set("PASETO_PUBLIC_KEY", publicKey);
    Deno.env.set("PASETO_SECRET_KEY", secretKey);

    return c.json({ public_key: publicKey, secret_key: secretKey });
  } catch (error) {
    return errorHandler(c, error);
  }
};

export const login = async (c: Context) => {
  try {
    const tokens = await generateToken({
      id: 1,
      username: "admin",
    });

    return c.json(getTokenResponse({ context: c, ...tokens }));
  } catch (error) {
    return errorHandler(c, error);
  }
};

export const verify = async (c: Context, next: Next) => {
  try {
    const token = c?.req?.header ? (c.req.header("Authorization") ?? "") : "";

    const { payload } = await verifyToken(token);
    if (c.req.routePath === "/verify") {
      return c.json({ access_token: token, token, user: payload });
    }

    next();
  } catch (error) {
    return errorHandler(c, error);
  }
};

export const refresh = async (c: Context) => {
  try {
    const refToken = getCookie(c, "refresh_token");
    if (!refToken) {
      // Align with service and tests: treat missing refresh cookie as unauthorized
      throw new UnauthorizedError("Invalid credentials", "INVALID_CREDENTIALS");
    }

    const tokens = await refreshToken(refToken);
    return c.json(getTokenResponse({ context: c, ...tokens }));
  } catch (error) {
    return errorHandler(c, error);
  }
};

export const logout = (c: Context) => {
  try {
    throw new UnauthorizedError("Not implemented", "EXPIRED_SESSION");
  } catch (error) {
    return errorHandler(c, error);
  }
};

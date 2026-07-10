import { Context, Next } from "hono";
import { getCookie } from "hono/cookie";
import { UnauthorizedError } from "./exceptions.ts";
import { errorHandler } from "./helpers.ts";
import {
  getTokenResponse,
  loginWithSupabase,
  registerWithSupabase,
} from "./services.ts";
import { paseto } from "./utils.ts";

const { generateToken, refreshToken, verifyToken } = paseto;

export const login = async (c: Context) => {
  try {
    const body = await c.req.json();
    const authResult = await loginWithSupabase(body);
    const tokens = await generateToken({
      id: authResult.id,
      email: authResult.email,
    });

    return c.json(
      getTokenResponse({
        context: c,
        ...tokens,
        user: authResult as unknown as Record<string, unknown>,
      }),
    );
  } catch (error) {
    return errorHandler(c, error);
  }
};

export const register = async (c: Context) => {
  try {
    const { email, password, profile: metadata } = await c.req.json();
    const authResult = await registerWithSupabase({
      email,
      password,
      metadata,
    });
    const tokens = await generateToken({
      id: authResult.id,
      email: authResult.email,
    });

    return c.json({
      ...getTokenResponse({ context: c, ...tokens, user: authResult }),
      profile_synced: authResult.isSyncedMetadata,
    });
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

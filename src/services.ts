import { setCookie } from "hono/cookie";
import { sign, verify } from "paseto-ts/v4";
import { isDebug } from "./helpers.ts";
import { BadRequestError, UnauthorizedError } from './exceptions.ts'
import { Context } from "https://esm.sh/hono@4.4.7/dist/types/index.d.ts";

const getPublicKey = (): string => {
  const k = Deno.env.get("PASETO_PUBLIC_KEY");
  if (!k) throw new Error("PASETO_PUBLIC_KEY is not set");
  return k;
};
const getSecretKey = (): string => {
  const k = Deno.env.get("PASETO_SECRET_KEY");
  if (!k) throw new Error("PASETO_SECRET_KEY is not set");
  return k;
};

export type TTokenPayload = {
  iat: string;
  exp: string;
};

export type TTokenResponse = {
  access_token: string;
  user: Record<string, unknown>;
  timestamp: string;
};

export const generateToken = async (
  payload: Record<string, unknown>,
  refreshPayload: (Partial<TTokenPayload> & Record<string, unknown>) = {},
) => {
  try {
    if (isDebug) console.log("payload", { payload, secretKey: getSecretKey() });

    const currTime = Math.floor(Date.now());

    const [accessToken, refreshToken] = await Promise.all([
      sign(getSecretKey(), {
        ...payload,
        iat: new Date(currTime).toISOString(),
        exp: new Date(currTime + (1000 * 60 * 60)).toISOString(),
      }),
      sign(getSecretKey(), {
        ...payload,
        iat: refreshPayload?.iat || new Date(currTime).toISOString(),
        exp: refreshPayload?.exp ||
          new Date(currTime + (1000 * 7 * 60 * 60)).toISOString(),
      }),
    ]);

    return { accessToken, refreshToken };
  } catch (error) {
    throw error;
  }
};

export const verifyToken = async (token: string) => {
  try {
    if (!token) {
      throw new BadRequestError("Missing token");
    }

    const decode = await verify(getPublicKey(), token);
    if (!decode || !decode?.payload) {
      throw new UnauthorizedError("Invalid token", "INVALID_CREDENTIALS");
    }

    const { exp, iat, ...payload } = decode.payload as
      & TTokenPayload
      & Record<string, unknown>;
    if (Date.parse(exp as string) < Date.now()) {
      throw new UnauthorizedError("Session expired", "EXPIRED_SESSION");
    }

    return { payload, exp, iat };
  } catch (error) {
    const msg = String((error as any)?.message || "").toLowerCase();
    if (msg.includes("expired")) {
      throw new UnauthorizedError("Session expired", "EXPIRED_SESSION");
    }
    if (msg.includes("invalid")) {
      throw new UnauthorizedError("Invalid token", "INVALID_CREDENTIALS");
    }
    throw error;
  }
};

export const refreshToken = async (refToken: string) => {
  try {
    if (!refToken) {
      throw new BadRequestError("Missing refresh token");
    }

    const verified = await verifyToken(refToken);
    if (!verified) {
      throw new UnauthorizedError(
        "Failed to verify invalid refresh token",
        "INVALID_CREDENTIALS",
      );
    }

    return await generateToken(verified.payload, {
      iat: verified.iat,
      exp: verified.exp,
      ...verified.payload,
    });
  } catch (error) {
    throw error;
  }
};

export const getTokenResponse = ({
  context,
  accessToken,
  refreshToken,
}: { context: Context; accessToken: string; refreshToken: string }) => {
  try {
    setCookie(context, "refresh_token", refreshToken, {
      httpOnly: true,
      sameSite: "strict",
      // secure: true,
      maxAge: 60 * 60 * 24 * 7,
    });

    return {
      access_token: accessToken,
      user: { id: 1, username: "admin" },
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    throw error;
  }
};

import { sign, verify } from "paseto-ts/v4";
import { createClient } from "@supabase/supabase-js";
import {
  BadRequestError,
  ErrorResponse,
  UnauthorizedError,
} from "./exceptions.ts";
import { TTokenPayload } from "./services.ts";
import { debug, isDebug } from "./helpers.ts";
import {
  validateEmail,
  validateFullName,
  validatePassword,
} from "./validators.ts";

export type TSupabaseAuthPayload = {
  email: string;
  password: string;
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") || "";
const SUPABASE_PUBLISHABLE_KEY = Deno.env.get("SUPABASE_PUBLISHABLE_KEY") || "";
const SUPABASE_SECRET_KEY = Deno.env.get("SUPABASE_SECRET_KEY") || "";
const SupabaseClient = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY);

const sanitizeMetadata = (
  metadata?: Record<string, unknown>,
): Record<string, string | number | boolean | null> => {
  if (!metadata) return {};

  const clean: Record<string, string | number | boolean | null> = {};
  for (const [key, value] of Object.entries(metadata)) {
    const isSafeKey = /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key);
    const isSafeValue = value === null ||
      ["string", "number", "boolean"].includes(typeof value);
    if (isSafeKey && isSafeValue) {
      clean[key] = value as string | number | boolean | null;
    }
  }

  return clean;
};

const loginAuth = async (payload: TSupabaseAuthPayload) => {
  try {
    if (!payload?.email || !payload?.password) {
      throw new BadRequestError("email and password are required");
    }

    const { data, error } = await SupabaseClient.auth.signInWithPassword(
      payload,
    );

    debug("utils.supabase.loginAuth:", { response: { data, error } });

    return { data, error };
  } catch (e) {
    throw e instanceof Error
      ? e
      : new ErrorResponse(500, "An unknown error occurred");
  }
};

const registerAuth = async (
  { email, password, metadata }: TSupabaseAuthPayload & {
    metadata?: Record<string, unknown>;
  },
) => {
  try {
    if (!email || !password) {
      throw new BadRequestError("email and password are required");
    }

    const { data, error } = await SupabaseClient.auth.signUp({
      email,
      password,
      options: { data: metadata },
    });

    debug("utils.supabase.registerAuth:", { response: { data, error } });

    return { data, error };
  } catch (e) {
    throw e instanceof Error
      ? e
      : new ErrorResponse(500, "An unknown error occurred");
  }
};

export const supabase = {
  SUPABASE_PUBLISHABLE_KEY,
  SUPABASE_SECRET_KEY,
  SUPABASE_URL,
  SupabaseClient,
  loginAuth,
  registerAuth,
  sanitizeMetadata,
};

const PASETO_SECRET_KEY = Deno.env.get("PASETO_SECRET_KEY") || "";
const PASETO_PUBLIC_KEY = Deno.env.get("PASETO_PUBLIC_KEY") || "";

const generateToken = async (
  payload: Record<string, unknown>,
  refreshPayload: Partial<TTokenPayload> & Record<string, unknown> = {},
) => {
  try {
    if (isDebug) {
      console.log("payload", { payload, secretKey: PASETO_SECRET_KEY });
    }

    const currTime = Math.floor(Date.now());

    const [accessToken, refreshToken] = await Promise.all([
      sign(PASETO_SECRET_KEY, {
        ...payload,
        iat: new Date(currTime).toISOString(),
        exp: new Date(currTime + (1000 * 60 * 60)).toISOString(),
      }),
      sign(PASETO_SECRET_KEY, {
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

const refreshToken = async (refToken: string) => {
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

const verifyToken = async (token: string) => {
  try {
    if (!token) {
      throw new BadRequestError("Missing token");
    }

    const decode = await verify(PASETO_PUBLIC_KEY, token);
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

export const paseto = {
  PASETO_PUBLIC_KEY,
  PASETO_SECRET_KEY,
  generateToken,
	refreshToken,
  verifyToken,
};

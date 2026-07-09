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

type SupabaseAuthPayload = {
  email: string;
  password: string;
};

type SupabaseAuthResult = {
  user: Record<string, unknown>;
  session: Record<string, unknown>;
};

const getSupabaseUrl = (): string => {
  const url = Deno.env.get("SUPABASE_URL");
  if (!url) throw new Error("SUPABASE_URL is not set");
  return url;
};

const getSupabaseAnonKey = (): string => {
  const key = Deno.env.get("SUPABASE_ANON_KEY");
  if (!key) throw new Error("SUPABASE_ANON_KEY is not set");
  return key;
};

const supabaseErrorMessage = async (res: Response): Promise<string> => {
  try {
    const payload = await res.json();
    return payload?.msg || payload?.error_description || payload?.error || payload?.message ||
      `Supabase request failed (${res.status})`;
  } catch {
    return `Supabase request failed (${res.status})`;
  }
};

const supabaseAuthRequest = async (
  endpoint: string,
  body: Record<string, unknown>,
  options?: { invalidCredentialsOn400?: boolean },
): Promise<SupabaseAuthResult> => {
  const response = await fetch(`${getSupabaseUrl()}${endpoint}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "apikey": getSupabaseAnonKey(),
      "Authorization": "Bearer " + getSupabaseAnonKey(),
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const message = await supabaseErrorMessage(response);
    if (options?.invalidCredentialsOn400 && (response.status === 400 || response.status === 401)) {
      throw new UnauthorizedError(message, "INVALID_CREDENTIALS");
    }
    throw new BadRequestError(message);
  }

  const data = await response.json();
  return {
    user: (data?.user || {}) as Record<string, unknown>,
    session: (data?.session || {}) as Record<string, unknown>,
  };
};

export const loginWithSupabase = async (
  payload: SupabaseAuthPayload,
): Promise<SupabaseAuthResult> => {
  if (!payload?.email || !payload?.password) {
    throw new BadRequestError("email and password are required");
  }

  return await supabaseAuthRequest(
    "/auth/v1/token?grant_type=password",
    payload,
    { invalidCredentialsOn400: true },
  );
};

export const saveProfileMetadata = async ({
  userId,
  metadata,
  accessToken,
}: {
  userId: string;
  metadata: Record<string, unknown>;
  accessToken: string;
}) => {
  if (!metadata || Object.keys(metadata).length === 0) return;

  const response = await fetch(`${getSupabaseUrl()}/rest/v1/profile?on_conflict=id`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "apikey": getSupabaseAnonKey(),
      "Authorization": "Bearer " + accessToken,
      "Prefer": "resolution=merge-duplicates,return=representation",
    },
    body: JSON.stringify([{ id: userId, ...metadata }]),
  });

  if (!response.ok) {
    throw new BadRequestError(await supabaseErrorMessage(response));
  }
};

export const registerWithSupabase = async ({
  email,
  password,
  metadata,
}: SupabaseAuthPayload & { metadata?: Record<string, unknown> }): Promise<SupabaseAuthResult & { profileSynced: boolean }> => {
  if (!email || !password) {
    throw new BadRequestError("email and password are required");
  }

  const authResult = await supabaseAuthRequest("/auth/v1/signup", {
    email,
    password,
    options: metadata && Object.keys(metadata).length > 0 ? { data: metadata } : undefined,
  });

  const userId = String(authResult.user?.id || "");
  const accessToken = String(authResult.session?.access_token || "");
  const shouldSyncProfile = !!(metadata && Object.keys(metadata).length > 0 && userId && accessToken);

  if (shouldSyncProfile) {
    await saveProfileMetadata({
      userId,
      metadata: metadata as Record<string, unknown>,
      accessToken,
    });
  }

  return {
    ...authResult,
    profileSynced: shouldSyncProfile,
  };
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
  user,
}: { context: Context; accessToken: string; refreshToken: string; user?: Record<string, unknown> }) => {
  try {
    setCookie(context, "refresh_token", refreshToken, {
      httpOnly: true,
      sameSite: "strict",
      // secure: true,
      maxAge: 60 * 60 * 24 * 7,
    });

    return {
      access_token: accessToken,
      user: user || { id: 1, username: "admin" },
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    throw error;
  }
};

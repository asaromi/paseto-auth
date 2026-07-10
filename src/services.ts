import { Context } from "hono";
import { setCookie } from "hono/cookie";
import { BadRequestError, ErrorResponse, UnauthorizedError } from './exceptions.ts'
import { paseto, supabase, TSupabaseAuthPayload } from './utils.ts'
import { validateEmail, validateFullName, validatePassword } from './validators.ts'

const { loginAuth, registerAuth, sanitizeMetadata, SupabaseClient } = supabase;
const { generateToken, refreshToken, verifyToken } = paseto;

export type TTokenPayload = {
  iat: string;
  exp: string;
};

export type TTokenResponse = {
  access_token: string;
  user: Record<string, unknown>;
  timestamp: string;
};

export const loginWithSupabase = async (payload: TSupabaseAuthPayload) => {
	try {
		const { data, error } = await loginAuth(payload);

		if (error || !data?.user) {
			throw new BadRequestError(
				error?.message ||
				error?.toJSON()?.message ||
				"An unknown error occurred when logging in to supabase",
			);
		} else if (data?.weakPassword) {
			const { message = "", reasons = [] } = data.weakPassword;
			throw new BadRequestError(
				message || (reasons.length && JSON.stringify(reasons)) ||
				"Weak Password",
			);
		}

		return data.user;
	} catch (e) {
		throw e instanceof Error
			? e
			: new ErrorResponse(500, "An unknown error occurred");
	}
};

export const registerWithSupabase = async (payload: TSupabaseAuthPayload & { metadata?: Record<string, unknown> }) => {
	try {
		const validated = {
			email: validateEmail(payload.email),
			password: validatePassword(payload.password),
			metadata: sanitizeMetadata({
				...payload?.metadata,
				full_name: validateFullName(payload?.metadata?.full_name as string),
			}),
		};

		const { data, error } = await registerAuth(validated);
		if (error || !data?.user) {
			throw new BadRequestError(
				error?.message ||
				error?.toJSON()?.message ||
				"An unknown error occured when registering to supabase",
			);
		}

		// const isSyncedMetadata =
		// 	!!(Object.keys(validated.metadata).length && data?.user?.id &&
		// 		data?.session?.access_token);
		// if (!isSyncedMetadata) {
		// 	const { error: errUpdate } = await SupabaseClient.auth.updateUser({
		// 		data: validated.metadata,
		// 	});
		//
		// 	if (errUpdate) {
		// 		throw new BadRequestError(
		// 			errUpdate?.message ||
		// 			errUpdate?.toJSON()?.message ||
		// 			"An unknown error occurred when updating user metadata",
		// 		);
		// 	}
		// }

		return { ...data.user, isSyncedMetadata: true };
	} catch (e) {
		throw e instanceof Error
			? e
			: new ErrorResponse(500, "An unknown error occurred");
	}
}

export const getTokenResponse = ({
  context,
  accessToken,
  refreshToken,
  user,
}: {
  context: Context;
  accessToken: string;
  refreshToken: string;
  user?: Record<string, unknown>;
}) => {
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
    } satisfies TTokenResponse;
  } catch (error) {
    throw error;
  }
};

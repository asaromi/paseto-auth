export type ErrorCode = 'EXPIRED_SESSION' | 'INVALID_CREDENTIALS' | 'USER_NOT_FOUND' | 'BAD_REQUEST' | 'INTERNAL_SERVER_ERROR' | 'UNAUTHORIZED' | 'FORBIDDEN' | 'NOT_FOUND'

export class ErrorResponse extends Error {
	public readonly code: number
	public override readonly name: ErrorCode

	constructor(code: number, message: string, name?: ErrorCode) {
		super(message)
		this.code = code
		this.name = name || 'INTERNAL_SERVER_ERROR'
	}
}

export class BadRequestError extends ErrorResponse {
	constructor(message: string) {
		super(400, message, 'BAD_REQUEST')
	}
}

export class UnauthorizedError extends ErrorResponse {
	constructor(message: string, name?: ErrorCode) {
		super(401, message, name ?? 'UNAUTHORIZED')
	}
}

export class ForbiddenError extends ErrorResponse {
	constructor(message: string) {
		super(403, message, 'FORBIDDEN')
	}
}

export class NotFoundError extends ErrorResponse {
	constructor(message: string, name?: ErrorCode) {
		super(404, message, name ?? 'NOT_FOUND')
	}
}


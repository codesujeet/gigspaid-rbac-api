/** Error that is safe to show to clients: status + stable machine code + message. */
export class HttpError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

export const unauthorized = (message = 'Authentication required') => new HttpError(401, 'unauthorized', message);
export const forbidden = (message = 'You do not have permission to perform this action') =>
  new HttpError(403, 'forbidden', message);
export const notFound = (message = 'Resource not found') => new HttpError(404, 'not_found', message);
export const conflict = (message: string) => new HttpError(409, 'conflict', message);
export const validationError = (details: unknown) =>
  new HttpError(422, 'validation_error', 'Request validation failed', details);

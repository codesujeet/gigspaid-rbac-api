import type { ErrorRequestHandler, RequestHandler } from 'express';
import { HttpError, notFound } from '../errors';

export interface ErrorBody {
  error: { code: string; message: string; details?: unknown };
}

export const notFoundHandler: RequestHandler = (_req, _res, next) => next(notFound('Route not found'));

export function createErrorHandler(logErrors: boolean): ErrorRequestHandler {
  // Express identifies error handlers by arity (4 params).
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return (err, _req, res, _next) => {
    let status = 500;
    let body: ErrorBody = { error: { code: 'internal_error', message: 'Internal server error' } };

    if (err instanceof HttpError) {
      status = err.status;
      body = { error: { code: err.code, message: err.message, ...(err.details !== undefined && { details: err.details }) } };
    } else if (isBodyParserError(err)) {
      status = err.status;
      body =
        err.type === 'entity.too.large'
          ? { error: { code: 'payload_too_large', message: 'Request body too large' } }
          : { error: { code: 'bad_request', message: 'Malformed request body' } };
    } else if (logErrors) {
      // Log server-side only; never send stack traces or messages to the client.
      console.error('Unhandled error:', err);
    }

    res.status(status).json(body);
  };
}

function isBodyParserError(err: unknown): err is { status: number; type: string } {
  return (
    typeof err === 'object' &&
    err !== null &&
    typeof (err as { type?: unknown }).type === 'string' &&
    (err as { type: string }).type.startsWith('entity.') &&
    typeof (err as { status?: unknown }).status === 'number'
  );
}

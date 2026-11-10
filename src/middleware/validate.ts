import type { z } from 'zod';
import { validationError } from '../errors';

/** Parses untrusted input with a zod schema or throws a 422 HttpError with field-level details. */
export function parse<S extends z.ZodType>(schema: S, data: unknown): z.output<S> {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw validationError(
      result.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    );
  }
  return result.data;
}

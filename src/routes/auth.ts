import bcrypt from 'bcryptjs';
import { Router, type NextFunction, type Request, type RequestHandler, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import type { Config } from '../config';
import { signToken } from '../middleware/auth';
import { parse } from '../middleware/validate';
import { unauthorized } from '../errors';
import type { Store } from '../store';

const loginSchema = z.strictObject({
  email: z.string().trim().email().max(254),
  // bcrypt ignores everything past 72 bytes, so longer inputs are rejected rather than silently truncated.
  password: z.string().min(1).refine((p) => Buffer.byteLength(p) <= 72, 'Password must be at most 72 bytes'),
});

/** Public routes (no authentication). Mounted BEFORE the authenticate gate. */
export function createPublicRouter(config: Config, store: Store): Router {
  const router = Router();

  router.get('/health', (_req, res) => {
    res.json({ status: 'ok' });
  });

  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: config.loginRateLimitMax,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (_req, res) => {
      res.status(429).json({ error: { code: 'too_many_requests', message: 'Too many login attempts, try again later' } });
    },
  });

  // Compared against when the email is unknown so response time does not reveal which emails exist.
  const dummyHash = bcrypt.hashSync('not-a-real-password', config.bcryptRounds);

  const login: RequestHandler = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = parse(loginSchema, req.body);
      const user = store.findUserByEmail(email);
      const ok = await bcrypt.compare(password, user?.passwordHash ?? dummyHash);
      if (!user || !ok) throw unauthorized('Invalid email or password');
      const token = signToken(config, user);
      res.json({
        token,
        tokenType: 'Bearer',
        expiresIn: config.jwtExpiresIn,
        user: { id: user.id, email: user.email, role: user.role },
      });
    } catch (err) {
      next(err);
    }
  };
  router.post('/auth/login', limiter, login);

  return router;
}

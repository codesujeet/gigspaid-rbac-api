import express, { Router, type Express } from 'express';
import helmet from 'helmet';
import type { Config } from './config';
import { createAuthenticate, requireRole } from './middleware/auth';
import { createErrorHandler, notFoundHandler } from './middleware/errorHandler';
import { ROLES } from './rbac';
import { createPublicRouter } from './routes/auth';
import { createArticlesRouter } from './routes/articles';
import { createUsersRouter } from './routes/users';
import type { Store } from './store';

/**
 * Everything mounted here sits behind the authenticate gate (deny-by-default):
 * a route added to this router is 401 for anonymous callers even if its author forgets a guard,
 * and every route must additionally declare its own requirePermission/requireRole guard
 * (enforced by a test that walks this router's stack).
 */
export function createProtectedRouter(config: Config, store: Store): Router {
  const router = Router();
  router.use(createAuthenticate(config, store));

  // Any authenticated, known role may see its own identity.
  router.get('/auth/me', requireRole(...ROLES), (req, res) => {
    res.json({ data: req.user });
  });
  router.use('/articles', createArticlesRouter(store));
  router.use('/users', createUsersRouter(store));
  return router;
}

/** Builds the Express app without listening, so tests can import it directly. */
export function createApp(config: Config, store: Store): Express {
  const app = express();
  app.disable('x-powered-by');
  // Only trust X-Forwarded-For when explicitly told how many proxies sit in front (rate limiting keys on the client IP).
  if (config.trustProxyHops > 0) app.set('trust proxy', config.trustProxyHops);
  app.use(helmet());
  app.use(express.json({ limit: '100kb' }));

  app.use(createPublicRouter(config, store));
  app.use(createProtectedRouter(config, store));

  app.use(notFoundHandler);
  app.use(createErrorHandler(config.logErrors));
  return app;
}

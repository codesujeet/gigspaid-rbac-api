import type { NextFunction, Request, RequestHandler, Response } from 'express';
import jwt from 'jsonwebtoken';
import type { Config } from '../config';
import { forbidden, unauthorized } from '../errors';
import { hasPermission, isRole, type Permission, type Role } from '../rbac';
import type { Store } from '../store';

export const JWT_ISSUER = 'gigspaid-rbac-api';

export interface AuthUser {
  id: string;
  email: string;
  role: Role;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}

export function signToken(config: Pick<Config, 'jwtSecret' | 'jwtExpiresIn'>, user: AuthUser): string {
  return jwt.sign({ role: user.role }, config.jwtSecret, {
    algorithm: 'HS256',
    subject: user.id,
    issuer: JWT_ISSUER,
    expiresIn: config.jwtExpiresIn as jwt.SignOptions['expiresIn'],
  });
}

/**
 * Verifies the Bearer token and establishes req.user.
 *
 * The token is only a claim of identity: the user is re-loaded from the store and the
 * role used for authorization is the STORE's role. A token whose role claim no longer
 * matches (user demoted/promoted) or whose user was deleted is rejected with 401.
 */
export function createAuthenticate(config: Pick<Config, 'jwtSecret'>, store: Store): RequestHandler {
  return function authenticate(req: Request, _res: Response, next: NextFunction): void {
    const header = req.headers.authorization;
    if (!header) return next(unauthorized('Missing Authorization header'));
    const match = /^Bearer ([^\s]+)$/.exec(header);
    if (!match || !match[1]) return next(unauthorized('Authorization header must be "Bearer <token>"'));

    let payload: jwt.JwtPayload;
    try {
      const decoded = jwt.verify(match[1], config.jwtSecret, {
        algorithms: ['HS256'], // pins the algorithm: rejects "none" and algorithm confusion
        issuer: JWT_ISSUER,
      });
      if (typeof decoded === 'string') return next(unauthorized('Invalid token'));
      payload = decoded;
    } catch (err) {
      const expired = err instanceof jwt.TokenExpiredError;
      return next(unauthorized(expired ? 'Token expired' : 'Invalid token'));
    }

    if (typeof payload.sub !== 'string' || !isRole(payload.role)) return next(unauthorized('Invalid token'));
    const user = store.findUserById(payload.sub);
    if (!user) return next(unauthorized('Invalid token'));
    if (user.role !== payload.role) return next(unauthorized('Token is stale; please log in again'));

    req.user = { id: user.id, email: user.email, role: user.role };
    next();
  };
}

/**
 * Authorization guard: allow only if the authenticated user's role holds ALL listed permissions.
 * Fails closed: no user on the request (guard used without authenticate) => 401, never pass-through.
 */
export function requirePermission(...permissions: Permission[]): RequestHandler {
  if (permissions.length === 0) throw new Error('requirePermission needs at least one permission');
  return function rbacGuard(req: Request, _res: Response, next: NextFunction): void {
    if (!req.user) return next(unauthorized());
    const allowed = permissions.every((p) => hasPermission(req.user!.role, p));
    return allowed ? next() : next(forbidden());
  };
}

/** Role-based variant: allow only the listed roles. Prefer requirePermission for resource routes. */
export function requireRole(...roles: Role[]): RequestHandler {
  if (roles.length === 0) throw new Error('requireRole needs at least one role');
  return function rbacGuard(req: Request, _res: Response, next: NextFunction): void {
    if (!req.user) return next(unauthorized());
    return roles.includes(req.user.role) ? next() : next(forbidden());
  };
}

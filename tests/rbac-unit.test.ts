import type { Request, Response } from 'express';
import { describe, expect, it, vi } from 'vitest';
import { createProtectedRouter } from '../src/app';
import { requirePermission, requireRole } from '../src/middleware/auth';
import { hasPermission, isRole, PERMISSIONS, ROLE_PERMISSIONS, ROLES, type Permission, type Role } from '../src/rbac';
import { buildCtx } from './helpers';

describe('permission map', () => {
  const expected: Record<Role, Permission[]> = {
    viewer: ['articles:read'],
    editor: ['articles:read', 'articles:create', 'articles:update'],
    admin: [...PERMISSIONS],
  };

  it.each(ROLES.map((r) => [r] as const))('%s has exactly the documented permissions', (role) => {
    expect([...ROLE_PERMISSIONS[role]].sort()).toEqual([...expected[role]].sort());
  });

  it('only admin holds delete and user-management permissions', () => {
    for (const p of ['articles:delete', 'users:read', 'users:manage'] as const) {
      expect(ROLES.filter((r) => hasPermission(r, p))).toEqual(['admin']);
    }
  });

  it('deny-by-default: unknown roles and prototype keys hold nothing', () => {
    for (const bad of ['superuser', '', '__proto__', 'constructor', 'toString']) {
      expect(isRole(bad)).toBe(false);
      expect(hasPermission(bad as Role, 'articles:read')).toBe(false);
    }
  });

  it('the map is frozen (cannot be mutated at runtime)', () => {
    expect(Object.isFrozen(ROLE_PERMISSIONS)).toBe(true);
    expect(Object.isFrozen(ROLE_PERMISSIONS.viewer)).toBe(true);
  });
});

describe('guards fail closed', () => {
  const run = (guard: ReturnType<typeof requirePermission>, user?: { role: Role }) => {
    const next = vi.fn();
    guard({ user } as unknown as Request, {} as Response, next);
    return next.mock.calls[0]?.[0] as { status: number } | undefined;
  };

  it('no req.user => 401, never pass-through', () => {
    expect(run(requirePermission('articles:read'))?.status).toBe(401);
    expect(run(requireRole('admin'))?.status).toBe(401);
  });

  it('requireRole allows listed roles only', () => {
    expect(run(requireRole('admin', 'editor'), { role: 'editor' })).toBeUndefined();
    expect(run(requireRole('admin', 'editor'), { role: 'viewer' })?.status).toBe(403);
  });

  it('requirePermission requires ALL listed permissions', () => {
    expect(run(requirePermission('articles:read', 'articles:update'), { role: 'editor' })).toBeUndefined();
    expect(run(requirePermission('articles:read', 'articles:delete'), { role: 'editor' })?.status).toBe(403);
  });

  it('guards refuse to be constructed with no rules', () => {
    expect(() => requirePermission()).toThrow();
    expect(() => requireRole()).toThrow();
  });
});

interface Layer {
  name: string;
  handle: { name: string; stack?: Layer[] };
  route?: { path: string; methods: Record<string, boolean>; stack: Array<{ name: string }> };
}

function collectRoutes(stack: Layer[], prefix = ''): Array<{ id: string; handlers: string[] }> {
  const out: Array<{ id: string; handlers: string[] }> = [];
  for (const layer of stack) {
    if (layer.route) {
      const method = Object.keys(layer.route.methods)[0]!.toUpperCase();
      out.push({ id: `${method} ${prefix}${layer.route.path}`, handlers: layer.route.stack.map((s) => s.name) });
    } else if (layer.handle.stack) {
      // Sub-router mount path is not exposed by Express 4 directly; use the regexp-free route paths only.
      out.push(...collectRoutes(layer.handle.stack, prefix));
    }
  }
  return out;
}

describe('structural guarantee: every protected route declares an RBAC guard', () => {
  it('walks the protected router and finds a guard on each route handler chain', async () => {
    const ctx = await buildCtx();
    const router = createProtectedRouter(ctx.config, ctx.store) as unknown as { stack: Layer[] };
    const routes = collectRoutes(router.stack);

    expect(routes.length).toBe(9); // update this number when you add a route: forces a conscious review
    for (const r of routes) {
      expect(r.handlers, `${r.id} has no RBAC guard`).toContain('rbacGuard');
    }
    // and the very first layer is the authenticate gate
    expect(router.stack[0]!.handle.name).toBe('authenticate');
  });
});

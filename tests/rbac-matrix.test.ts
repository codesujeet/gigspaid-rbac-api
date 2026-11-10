import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { ROLES, type Role } from '../src/rbac';
import { bearer, buildCtx, type Ctx } from './helpers';

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';

interface Case {
  name: string;
  method: Method;
  path: (c: Ctx) => string;
  body?: unknown;
  expected: Record<Role, number>;
}

/**
 * Full role x route matrix. Every route in the API appears here, with the exact status each
 * role must receive. Any status of 403 is additionally proven to have had NO side effects.
 */
const CASES: Case[] = [
  { name: 'GET /auth/me', method: 'get', path: () => '/auth/me', expected: { admin: 200, editor: 200, viewer: 200 } },
  { name: 'GET /articles', method: 'get', path: () => '/articles', expected: { admin: 200, editor: 200, viewer: 200 } },
  {
    name: 'GET /articles/:id',
    method: 'get',
    path: (c) => `/articles/${c.article.id}`,
    expected: { admin: 200, editor: 200, viewer: 200 },
  },
  {
    name: 'POST /articles',
    method: 'post',
    path: () => '/articles',
    body: { title: 'New', body: 'Body text' },
    expected: { admin: 201, editor: 201, viewer: 403 },
  },
  {
    name: 'PUT /articles/:id',
    method: 'put',
    path: (c) => `/articles/${c.article.id}`,
    body: { title: 'Edited', body: 'Edited body' },
    expected: { admin: 200, editor: 200, viewer: 403 },
  },
  {
    name: 'DELETE /articles/:id',
    method: 'delete',
    path: (c) => `/articles/${c.article.id}`,
    expected: { admin: 204, editor: 403, viewer: 403 },
  },
  { name: 'GET /users', method: 'get', path: () => '/users', expected: { admin: 200, editor: 403, viewer: 403 } },
  {
    name: 'PATCH /users/:id/role',
    method: 'patch',
    path: (c) => `/users/${c.user.viewer.id}/role`,
    body: { role: 'editor' },
    expected: { admin: 200, editor: 403, viewer: 403 },
  },
  {
    name: 'DELETE /users/:id',
    method: 'delete',
    path: (c) => `/users/${c.user.viewer.id}`,
    expected: { admin: 204, editor: 403, viewer: 403 },
  },
];

const snapshot = (c: Ctx) =>
  JSON.stringify({
    articles: c.store.listArticles(),
    users: c.store.listUsers().map((u) => ({ id: u.id, role: u.role })),
  });

describe('RBAC matrix: role x route', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await buildCtx();
  });

  const rows = CASES.flatMap((c) => ROLES.map((role) => [c.name, role, c.expected[role], c] as const));

  it.each(rows)('%s as %s => %i', async (_name, role, status, c) => {
    const before = snapshot(ctx);
    let req = request(ctx.app)[c.method](c.path(ctx)).set(bearer(ctx.token[role]));
    if (c.body !== undefined) req = req.send(c.body as object);
    const res = await req;

    expect(res.status).toBe(status);
    if (status === 403) {
      expect(res.body).toEqual({
        error: { code: 'forbidden', message: expect.any(String) },
      });
      // Proof that a forbidden action did nothing.
      expect(snapshot(ctx)).toBe(before);
    }
  });

  it.each(CASES.map((c) => [c.name, c] as const))('%s without a token => 401', async (_name, c) => {
    let req = request(ctx.app)[c.method](c.path(ctx));
    if (c.body !== undefined) req = req.send(c.body as object);
    const res = await req;
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('unauthorized');
  });

  it('matrix covers every role for every case (no gaps)', () => {
    for (const c of CASES) expect(Object.keys(c.expected).sort()).toEqual([...ROLES].sort());
  });
});

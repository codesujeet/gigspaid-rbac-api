import jwt from 'jsonwebtoken';
import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { JWT_ISSUER } from '../src/middleware/auth';
import { DEMO_USERS } from '../src/seed';
import { b64url, bearer, buildCtx, TEST_SECRET, type Ctx } from './helpers';

describe('POST /auth/login', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await buildCtx();
  });

  it.each(DEMO_USERS.map((u) => [u.role, u] as const))('seed user %s can log in and gets a working token', async (role, u) => {
    const res = await request(ctx.app).post('/auth/login').send({ email: u.email, password: u.password });
    expect(res.status).toBe(200);
    expect(res.body.user).toEqual({ id: expect.any(String), email: u.email, role });
    expect(res.body.tokenType).toBe('Bearer');
    expect(res.body.user.passwordHash).toBeUndefined();

    const claims = jwt.verify(res.body.token, TEST_SECRET) as jwt.JwtPayload;
    expect(claims.role).toBe(role);
    expect(claims.iss).toBe(JWT_ISSUER);
    expect(claims.exp).toBeGreaterThan(claims.iat!);

    const me = await request(ctx.app).get('/auth/me').set(bearer(res.body.token));
    expect(me.status).toBe(200);
    expect(me.body.data.role).toBe(role);
  });

  it('email lookup is case-insensitive', async () => {
    const res = await request(ctx.app).post('/auth/login').send({ email: 'ADMIN@Example.com', password: 'Admin#12345' });
    expect(res.status).toBe(200);
  });

  it('wrong password and unknown user give the same 401', async () => {
    const wrong = await request(ctx.app).post('/auth/login').send({ email: 'admin@example.com', password: 'nope' });
    const unknown = await request(ctx.app).post('/auth/login').send({ email: 'ghost@example.com', password: 'nope' });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual(unknown.body);
  });

  it.each([
    ['missing body', {}],
    ['missing password', { email: 'admin@example.com' }],
    ['bad email', { email: 'not-an-email', password: 'x' }],
    ['non-string password', { email: 'admin@example.com', password: 123 }],
    ['unknown field (role smuggling)', { email: 'admin@example.com', password: 'Admin#12345', role: 'admin' }],
  ])('rejects invalid login payload: %s => 422', async (_n, body) => {
    const res = await request(ctx.app).post('/auth/login').send(body);
    expect(res.status).toBe(422);
    expect(res.body.error.code).toBe('validation_error');
  });

  it('is rate limited (429 with the standard error shape)', async () => {
    const limited = await buildCtx({ LOGIN_RATE_LIMIT_MAX: '3' });
    const statuses: number[] = [];
    for (let i = 0; i < 5; i++) {
      const r = await request(limited.app).post('/auth/login').send({ email: 'admin@example.com', password: 'bad' });
      statuses.push(r.status);
    }
    expect(statuses).toEqual([401, 401, 401, 429, 429]);
  });
});

describe('401: authentication failures on a protected route', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await buildCtx();
  });
  const get = (headers: Record<string, string> = {}) => request(ctx.app).get('/articles').set(headers);

  it('no Authorization header', async () => {
    const res = await get();
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: { code: 'unauthorized', message: expect.any(String) } });
  });

  it.each([
    ['not a Bearer scheme', 'Basic YWRtaW46cGFzcw=='],
    ['Bearer with no token', 'Bearer '],
    ['token only, no scheme', 'abc.def.ghi'],
    ['malformed token', 'Bearer not-a-jwt'],
    ['garbage three segments', 'Bearer aaa.bbb.ccc'],
  ])('%s', async (_n, header) => {
    const res = await get({ Authorization: header });
    expect(res.status).toBe(401);
  });

  it('expired token', async () => {
    const expired = jwt.sign({ role: 'admin' }, TEST_SECRET, {
      subject: ctx.user.admin.id,
      issuer: JWT_ISSUER,
      expiresIn: -60,
    });
    const res = await get(bearer(expired));
    expect(res.status).toBe(401);
    expect(res.body.error.message).toBe('Token expired');
  });

  it('tampered payload (role escalated, original signature kept)', async () => {
    const [h, , sig] = ctx.token.viewer.split('.');
    const forgedPayload = b64url({
      sub: ctx.user.viewer.id,
      role: 'admin',
      iss: JWT_ISSUER,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const res = await request(ctx.app).get('/users').set(bearer(`${h}.${forgedPayload}.${sig}`));
    expect(res.status).toBe(401);
  });

  it('tampered signature', async () => {
    const t = ctx.token.admin;
    const flipped = t.slice(0, -2) + (t.endsWith('AA') ? 'BB' : 'AA');
    const res = await get(bearer(flipped));
    expect(res.status).toBe(401);
  });

  it('signed with the wrong secret', async () => {
    const forged = jwt.sign({ role: 'admin' }, 'some-other-secret-some-other-secret!', {
      subject: ctx.user.admin.id,
      issuer: JWT_ISSUER,
      expiresIn: '1h',
    });
    const res = await get(bearer(forged));
    expect(res.status).toBe(401);
  });

  it('alg: none (unsigned token)', async () => {
    const header = b64url({ alg: 'none', typ: 'JWT' });
    const payload = b64url({
      sub: ctx.user.admin.id,
      role: 'admin',
      iss: JWT_ISSUER,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    for (const t of [`${header}.${payload}.`, `${header}.${payload}`]) {
      const res = await request(ctx.app).get('/users').set(bearer(t));
      expect(res.status).toBe(401);
    }
  });

  it('a different HMAC algorithm (HS512) with the right secret is rejected (algorithm pinned to HS256)', async () => {
    const t = jwt.sign({ role: 'admin' }, TEST_SECRET, {
      algorithm: 'HS512',
      subject: ctx.user.admin.id,
      issuer: JWT_ISSUER,
      expiresIn: '1h',
    });
    const res = await get(bearer(t));
    expect(res.status).toBe(401);
  });

  it('wrong issuer', async () => {
    const t = jwt.sign({ role: 'admin' }, TEST_SECRET, { subject: ctx.user.admin.id, issuer: 'someone-else', expiresIn: '1h' });
    expect((await get(bearer(t))).status).toBe(401);
  });

  it('valid signature but missing / invalid role claim', async () => {
    const noRole = jwt.sign({}, TEST_SECRET, { subject: ctx.user.admin.id, issuer: JWT_ISSUER, expiresIn: '1h' });
    const badRole = jwt.sign({ role: 'superuser' }, TEST_SECRET, { subject: ctx.user.admin.id, issuer: JWT_ISSUER, expiresIn: '1h' });
    expect((await get(bearer(noRole))).status).toBe(401);
    expect((await get(bearer(badRole))).status).toBe(401);
  });

  it('valid signature but the subject does not exist (deleted user)', async () => {
    const ghost = jwt.sign({ role: 'admin' }, TEST_SECRET, { subject: 'no-such-user', issuer: JWT_ISSUER, expiresIn: '1h' });
    expect((await get(bearer(ghost))).status).toBe(401);
  });

  it('token of a user who was later deleted stops working', async () => {
    expect((await get(bearer(ctx.token.editor))).status).toBe(200);
    ctx.store.deleteUser(ctx.user.editor.id);
    expect((await get(bearer(ctx.token.editor))).status).toBe(401);
  });

  it('role in the token must match the store: demoted admin token is rejected (token is not the source of truth)', async () => {
    expect((await request(ctx.app).get('/users').set(bearer(ctx.token.admin))).status).toBe(200);
    ctx.store.setUserRole(ctx.user.admin.id, 'viewer');
    const res = await request(ctx.app).get('/users').set(bearer(ctx.token.admin));
    expect(res.status).toBe(401);
  });

  it('unknown routes: 401 without a token (no route enumeration), 404 with one', async () => {
    expect((await request(ctx.app).get('/nope')).status).toBe(401);
    const res = await request(ctx.app).get('/nope').set(bearer(ctx.token.viewer));
    expect(res.status).toBe(404);
    expect(res.body.error.code).toBe('not_found');
  });
});

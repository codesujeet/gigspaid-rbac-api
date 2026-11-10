import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config';
import { DEMO_USERS, seed } from '../src/seed';
import { Store } from '../src/store';
import { bearer, buildCtx, type Ctx } from './helpers';

describe('config', () => {
  const secret = 'Q7vLm2Xp9RtK4wZ8aBn3Yc6Hd1Fs5GjU';

  it('refuses to start in production without JWT_SECRET', () => {
    expect(() => loadConfig({ NODE_ENV: 'production' })).toThrow(/JWT_SECRET/);
    expect(() => loadConfig({ NODE_ENV: 'production', JWT_SECRET: '   ' })).toThrow(/JWT_SECRET/);
  });

  it('refuses a short production secret', () => {
    expect(() => loadConfig({ NODE_ENV: 'production', JWT_SECRET: 'short' })).toThrow(/at least 32/);
  });

  it('accepts a strong production secret; demo users are off by default there', () => {
    const c = loadConfig({ NODE_ENV: 'production', JWT_SECRET: secret });
    expect(c.jwtSecret).toBe(secret);
    expect(c.seedDemoUsers).toBe(false);
    expect(loadConfig({ NODE_ENV: 'production', JWT_SECRET: secret, SEED_DEMO_USERS: 'true' }).seedDemoUsers).toBe(true);
  });

  it('refuses placeholder / repetitive production secrets', () => {
    expect(() => loadConfig({ NODE_ENV: 'production', JWT_SECRET: 'x'.repeat(40) })).toThrow(/placeholder|repetitive/);
    expect(() => loadConfig({ NODE_ENV: 'production', JWT_SECRET: 'please-change-me-to-something-long-1234567' })).toThrow(/placeholder|repetitive/);
  });

  it('validates JWT_EXPIRES_IN and TRUST_PROXY_HOPS', () => {
    for (const bad of ['0', '0h', 'forever', '-5m', '1y']) {
      expect(() => loadConfig({ JWT_EXPIRES_IN: bad })).toThrow(/JWT_EXPIRES_IN/);
    }
    expect(loadConfig({ JWT_EXPIRES_IN: '15m' }).jwtExpiresIn).toBe('15m');
    expect(() => loadConfig({ TRUST_PROXY_HOPS: '-1' })).toThrow(/TRUST_PROXY_HOPS/);
    expect(loadConfig({ TRUST_PROXY_HOPS: '1' }).trustProxyHops).toBe(1);
  });

  it('dev without a secret gets a random ephemeral one (different each time)', () => {
    const a = loadConfig({ NODE_ENV: 'development' });
    const b = loadConfig({ NODE_ENV: 'development' });
    expect(a.jwtSecret.length).toBeGreaterThanOrEqual(32);
    expect(a.jwtSecret).not.toBe(b.jwtSecret);
    expect(a.seedDemoUsers).toBe(true);
  });

  it('validates NODE_ENV, PORT and BCRYPT_ROUNDS', () => {
    expect(() => loadConfig({ NODE_ENV: 'staging' })).toThrow(/NODE_ENV/);
    expect(() => loadConfig({ PORT: 'abc' })).toThrow(/PORT/);
    expect(() => loadConfig({ BCRYPT_ROUNDS: '2' })).toThrow(/BCRYPT_ROUNDS/);
    expect(loadConfig({ PORT: '8080' }).port).toBe(8080);
  });
});

describe('seed', () => {
  it('creates one user per role with hashed passwords, and is idempotent', async () => {
    const store = new Store();
    await seed(store, 4);
    await seed(store, 4);
    expect(store.listUsers()).toHaveLength(3);
    expect(store.listUsers().map((u) => u.role).sort()).toEqual(['admin', 'editor', 'viewer']);
    for (const d of DEMO_USERS) {
      const u = store.findUserByEmail(d.email)!;
      expect(u.passwordHash).not.toContain(d.password);
      expect(u.passwordHash).toMatch(/^\$2[aby]\$/);
    }
    expect(store.listArticles()).toHaveLength(1);
  });

  it('store rejects duplicate emails', async () => {
    const store = new Store();
    await seed(store, 4);
    expect(() => store.createUser({ email: 'ADMIN@example.com', passwordHash: 'x', role: 'viewer' })).toThrow();
  });
});

describe('HTTP hygiene', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await buildCtx();
  });

  it('GET /health is public', async () => {
    const res = await request(ctx.app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('sets helmet security headers and hides x-powered-by', async () => {
    const res = await request(ctx.app).get('/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['strict-transport-security']).toBeDefined();
    expect(res.headers['content-security-policy']).toBeDefined();
  });

  it('sends no CORS headers (browsers on other origins are not granted access)', async () => {
    const res = await request(ctx.app).get('/health').set('Origin', 'https://evil.example');
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    const preflight = await request(ctx.app).options('/articles').set('Origin', 'https://evil.example').set('Access-Control-Request-Method', 'DELETE');
    expect(preflight.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('malformed JSON => 400 in the standard shape, no stack trace', async () => {
    const res = await request(ctx.app)
      .post('/auth/login')
      .set('Content-Type', 'application/json')
      .send('{"email": "a@b.c", ');
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: { code: 'bad_request', message: 'Malformed request body' } });
    expect(JSON.stringify(res.body)).not.toMatch(/at .*\.(js|ts)|node_modules|SyntaxError/);
  });

  it('oversized body => 413', async () => {
    const res = await request(ctx.app)
      .post('/auth/login')
      .send({ email: 'a@b.co', password: 'x'.repeat(200_000) });
    expect(res.status).toBe(413);
    expect(res.body.error.code).toBe('payload_too_large');
  });

  it('unexpected server errors => generic 500 without internals', async () => {
    ctx.store.listArticles = () => {
      throw new Error('secret database password leaked: hunter2');
    };
    const res = await request(ctx.app).get('/articles').set(bearer(ctx.token.admin));
    expect(res.status).toBe(500);
    expect(res.body).toEqual({ error: { code: 'internal_error', message: 'Internal server error' } });
    expect(JSON.stringify(res.body)).not.toContain('hunter2');
  });

  it('every error response uses the { error: { code, message } } shape', async () => {
    const responses = await Promise.all([
      request(ctx.app).get('/articles'),
      request(ctx.app).get('/users').set(bearer(ctx.token.viewer)),
      request(ctx.app).get('/nope').set(bearer(ctx.token.viewer)),
      request(ctx.app).post('/articles').set(bearer(ctx.token.editor)).send({}),
    ]);
    expect(responses.map((r) => r.status)).toEqual([401, 403, 404, 422]);
    for (const r of responses) {
      expect(r.body.error).toEqual(expect.objectContaining({ code: expect.any(String), message: expect.any(String) }));
    }
  });
});

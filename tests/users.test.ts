import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { bearer, buildCtx, type Ctx } from './helpers';

describe('privilege escalation attempts', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await buildCtx();
  });

  it('editor cannot promote themselves to admin => 403 and role unchanged', async () => {
    const res = await request(ctx.app)
      .patch(`/users/${ctx.user.editor.id}/role`)
      .set(bearer(ctx.token.editor))
      .send({ role: 'admin' });
    expect(res.status).toBe(403);
    expect(ctx.store.findUserById(ctx.user.editor.id)!.role).toBe('editor');
  });

  it('viewer cannot promote themselves or anyone else => 403', async () => {
    for (const target of [ctx.user.viewer, ctx.user.editor]) {
      const res = await request(ctx.app).patch(`/users/${target.id}/role`).set(bearer(ctx.token.viewer)).send({ role: 'admin' });
      expect(res.status).toBe(403);
    }
    expect(ctx.store.findUserById(ctx.user.viewer.id)!.role).toBe('viewer');
  });

  it('the old editor token keeps editor power only: after a failed self-promotion it still cannot reach admin routes', async () => {
    await request(ctx.app).patch(`/users/${ctx.user.editor.id}/role`).set(bearer(ctx.token.editor)).send({ role: 'admin' });
    expect((await request(ctx.app).get('/users').set(bearer(ctx.token.editor))).status).toBe(403);
  });

  it('role claims in request bodies / headers / query are ignored', async () => {
    const res = await request(ctx.app)
      .get('/users?role=admin')
      .set({ ...bearer(ctx.token.viewer), 'X-Role': 'admin', 'X-User-Role': 'admin' });
    expect(res.status).toBe(403);

    const post = await request(ctx.app).post('/articles').set(bearer(ctx.token.viewer)).send({ title: 'a', body: 'b', role: 'admin' });
    expect(post.status).toBe(403);
  });

  it('admin promoting a user takes effect: the user then needs a NEW token (old one is stale => 401)', async () => {
    const res = await request(ctx.app)
      .patch(`/users/${ctx.user.editor.id}/role`)
      .set(bearer(ctx.token.admin))
      .send({ role: 'admin' });
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ id: ctx.user.editor.id, role: 'admin' });
    expect(res.body.data.passwordHash).toBeUndefined();

    expect((await request(ctx.app).get('/users').set(bearer(ctx.token.editor))).status).toBe(401);

    const login = await request(ctx.app).post('/auth/login').send({ email: 'editor@example.com', password: 'Editor#12345' });
    expect(login.body.user.role).toBe('admin');
    expect((await request(ctx.app).get('/users').set(bearer(login.body.token))).status).toBe(200);
  });

  it('role change validation: unknown role / missing / extra fields => 422', async () => {
    for (const body of [{ role: 'root' }, {}, { role: 'admin', extra: 1 }, { role: ['admin'] }, { role: '__proto__' }]) {
      const res = await request(ctx.app).patch(`/users/${ctx.user.viewer.id}/role`).set(bearer(ctx.token.admin)).send(body);
      expect(res.status).toBe(422);
    }
    expect(ctx.store.findUserById(ctx.user.viewer.id)!.role).toBe('viewer');
  });

  it('unknown user id => 404 on role change and delete', async () => {
    expect((await request(ctx.app).patch('/users/nope/role').set(bearer(ctx.token.admin)).send({ role: 'viewer' })).status).toBe(404);
    expect((await request(ctx.app).delete('/users/nope').set(bearer(ctx.token.admin))).status).toBe(404);
  });
});

describe('last-admin protection', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await buildCtx();
  });

  it('the sole admin cannot demote themselves => 409', async () => {
    const res = await request(ctx.app).patch(`/users/${ctx.user.admin.id}/role`).set(bearer(ctx.token.admin)).send({ role: 'editor' });
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('conflict');
    expect(ctx.store.findUserById(ctx.user.admin.id)!.role).toBe('admin');
  });

  it('the sole admin cannot delete themselves => 409', async () => {
    const res = await request(ctx.app).delete(`/users/${ctx.user.admin.id}`).set(bearer(ctx.token.admin));
    expect(res.status).toBe(409);
    expect(ctx.store.findUserById(ctx.user.admin.id)).toBeDefined();
  });

  it('re-asserting admin on the sole admin is a harmless no-op (200)', async () => {
    const res = await request(ctx.app).patch(`/users/${ctx.user.admin.id}/role`).set(bearer(ctx.token.admin)).send({ role: 'admin' });
    expect(res.status).toBe(200);
  });

  it('with two admins, one may be demoted; then the remaining one is protected', async () => {
    // promote editor to admin, then fetch fresh tokens
    await request(ctx.app).patch(`/users/${ctx.user.editor.id}/role`).set(bearer(ctx.token.admin)).send({ role: 'admin' });
    const second = await request(ctx.app).post('/auth/login').send({ email: 'editor@example.com', password: 'Editor#12345' });
    expect(ctx.store.countAdmins()).toBe(2);

    const demote = await request(ctx.app)
      .patch(`/users/${ctx.user.admin.id}/role`)
      .set(bearer(second.body.token))
      .send({ role: 'viewer' });
    expect(demote.status).toBe(200);
    expect(ctx.store.countAdmins()).toBe(1);

    const last = await request(ctx.app).delete(`/users/${ctx.user.editor.id}`).set(bearer(second.body.token));
    expect(last.status).toBe(409);
    const lastDemote = await request(ctx.app).patch(`/users/${ctx.user.editor.id}/role`).set(bearer(second.body.token)).send({ role: 'editor' });
    expect(lastDemote.status).toBe(409);
  });

  it('GET /users never leaks password hashes', async () => {
    const res = await request(ctx.app).get('/users').set(bearer(ctx.token.admin));
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(3);
    expect(JSON.stringify(res.body)).not.toMatch(/passwordHash|\$2[aby]\$/);
  });
});

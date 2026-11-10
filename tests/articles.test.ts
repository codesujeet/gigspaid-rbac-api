import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import { bearer, buildCtx, type Ctx } from './helpers';

describe('articles: behaviour, validation, 404s', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await buildCtx();
  });

  it('create sets authorId from the token, ignoring any authorId in the body (strict schema => 422)', async () => {
    const ok = await request(ctx.app).post('/articles').set(bearer(ctx.token.editor)).send({ title: ' Hi ', body: 'There' });
    expect(ok.status).toBe(201);
    expect(ok.body.data).toMatchObject({ title: 'Hi', body: 'There', authorId: ctx.user.editor.id });

    const spoof = await request(ctx.app)
      .post('/articles')
      .set(bearer(ctx.token.editor))
      .send({ title: 'x', body: 'y', authorId: ctx.user.admin.id });
    expect(spoof.status).toBe(422);
  });

  it('a created article can be read back and updated; delete removes it', async () => {
    const created = await request(ctx.app).post('/articles').set(bearer(ctx.token.editor)).send({ title: 'A', body: 'B' });
    const id = created.body.data.id as string;

    const upd = await request(ctx.app).put(`/articles/${id}`).set(bearer(ctx.token.editor)).send({ title: 'A2', body: 'B2' });
    expect(upd.status).toBe(200);
    expect(upd.body.data).toMatchObject({ id, title: 'A2', body: 'B2' });

    expect((await request(ctx.app).get(`/articles/${id}`).set(bearer(ctx.token.viewer))).body.data.title).toBe('A2');
    expect((await request(ctx.app).delete(`/articles/${id}`).set(bearer(ctx.token.admin))).status).toBe(204);
    expect((await request(ctx.app).get(`/articles/${id}`).set(bearer(ctx.token.viewer))).status).toBe(404);
  });

  it.each([
    ['empty object', {}],
    ['missing body', { title: 'x' }],
    ['empty title', { title: '', body: 'x' }],
    ['whitespace-only title', { title: '   ', body: 'x' }],
    ['title too long', { title: 'a'.repeat(201), body: 'x' }],
    ['wrong types', { title: 5, body: ['x'] }],
  ])('invalid payload (%s) => 422 with field details', async (_n, body) => {
    for (const [method, path] of [
      ['post', '/articles'],
      ['put', `/articles/${ctx.article.id}`],
    ] as const) {
      const res = await request(ctx.app)[method](path).set(bearer(ctx.token.editor)).send(body);
      expect(res.status).toBe(422);
      expect(res.body.error.code).toBe('validation_error');
      expect(Array.isArray(res.body.error.details)).toBe(true);
    }
  });

  it('unknown article id => 404 on get / put / delete', async () => {
    const id = 'does-not-exist';
    expect((await request(ctx.app).get(`/articles/${id}`).set(bearer(ctx.token.viewer))).status).toBe(404);
    expect((await request(ctx.app).put(`/articles/${id}`).set(bearer(ctx.token.editor)).send({ title: 'a', body: 'b' })).status).toBe(404);
    expect((await request(ctx.app).delete(`/articles/${id}`).set(bearer(ctx.token.admin))).status).toBe(404);
  });

  it('authorization is checked BEFORE the resource lookup: viewer deleting a missing id gets 403, not 404', async () => {
    const res = await request(ctx.app).delete('/articles/does-not-exist').set(bearer(ctx.token.viewer));
    expect(res.status).toBe(403);
  });

  it('authorization is checked BEFORE validation: viewer posting garbage gets 403, not 422', async () => {
    const res = await request(ctx.app).post('/articles').set(bearer(ctx.token.viewer)).send({});
    expect(res.status).toBe(403);
  });
});

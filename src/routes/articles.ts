import { Router } from 'express';
import { z } from 'zod';
import { notFound } from '../errors';
import { requirePermission } from '../middleware/auth';
import { parse } from '../middleware/validate';
import type { Store } from '../store';

const articleSchema = z.strictObject({
  title: z.string().trim().min(1).max(200),
  body: z.string().min(1).max(20000),
});

export function createArticlesRouter(store: Store): Router {
  const router = Router();

  router.get('/', requirePermission('articles:read'), (_req, res) => {
    res.json({ data: store.listArticles() });
  });

  router.get('/:id', requirePermission('articles:read'), (req, res) => {
    const article = store.findArticle(req.params.id ?? '');
    if (!article) throw notFound('Article not found');
    res.json({ data: article });
  });

  router.post('/', requirePermission('articles:create'), (req, res) => {
    const input = parse(articleSchema, req.body);
    // authorId always comes from the verified identity, never from the body.
    const article = store.createArticle({ ...input, authorId: req.user!.id });
    res.status(201).json({ data: article });
  });

  router.put('/:id', requirePermission('articles:update'), (req, res) => {
    const input = parse(articleSchema, req.body);
    const article = store.updateArticle(req.params.id ?? '', input);
    if (!article) throw notFound('Article not found');
    res.json({ data: article });
  });

  router.delete('/:id', requirePermission('articles:delete'), (req, res) => {
    if (!store.deleteArticle(req.params.id ?? '')) throw notFound('Article not found');
    res.status(204).end();
  });

  return router;
}

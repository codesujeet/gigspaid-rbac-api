import { Router } from 'express';
import { z } from 'zod';
import { conflict, notFound } from '../errors';
import { requirePermission } from '../middleware/auth';
import { parse } from '../middleware/validate';
import { ROLES } from '../rbac';
import { LastAdminError, toPublicUser, type Store } from '../store';

const roleChangeSchema = z.strictObject({ role: z.enum(ROLES) });

export function createUsersRouter(store: Store): Router {
  const router = Router();

  router.get('/', requirePermission('users:read'), (_req, res) => {
    res.json({ data: store.listUsers().map(toPublicUser) });
  });

  // Lock-out protection (the system always keeps at least one admin) is enforced inside the store,
  // so no route can bypass it.
  router.patch('/:id/role', requirePermission('users:manage'), (req, res) => {
    const { role } = parse(roleChangeSchema, req.body);
    try {
      const updated = store.setUserRole(req.params.id ?? '', role);
      if (!updated) throw notFound('User not found');
      res.json({ data: toPublicUser(updated) });
    } catch (err) {
      if (err instanceof LastAdminError) throw conflict('Cannot demote the last remaining admin');
      throw err;
    }
  });

  router.delete('/:id', requirePermission('users:manage'), (req, res) => {
    try {
      if (!store.deleteUser(req.params.id ?? '')) throw notFound('User not found');
      res.status(204).end();
    } catch (err) {
      if (err instanceof LastAdminError) throw conflict('Cannot delete the last remaining admin');
      throw err;
    }
  });

  return router;
}

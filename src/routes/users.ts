import { Router } from 'express';
import { z } from 'zod';
import { conflict, notFound } from '../errors';
import { requirePermission } from '../middleware/auth';
import { parse } from '../middleware/validate';
import { ROLES } from '../rbac';
import { toPublicUser, type Store } from '../store';

const roleChangeSchema = z.strictObject({ role: z.enum(ROLES) });

export function createUsersRouter(store: Store): Router {
  const router = Router();

  router.get('/', requirePermission('users:read'), (_req, res) => {
    res.json({ data: store.listUsers().map(toPublicUser) });
  });

  router.patch('/:id/role', requirePermission('users:manage'), (req, res) => {
    const { role } = parse(roleChangeSchema, req.body);
    const target = store.findUserById(req.params.id ?? '');
    if (!target) throw notFound('User not found');
    // Lock-out protection: the system must always keep at least one admin.
    if (target.role === 'admin' && role !== 'admin' && store.countAdmins() <= 1) {
      throw conflict('Cannot demote the last remaining admin');
    }
    const updated = store.setUserRole(target.id, role)!;
    res.json({ data: toPublicUser(updated) });
  });

  router.delete('/:id', requirePermission('users:manage'), (req, res) => {
    const target = store.findUserById(req.params.id ?? '');
    if (!target) throw notFound('User not found');
    if (target.role === 'admin' && store.countAdmins() <= 1) {
      throw conflict('Cannot delete the last remaining admin');
    }
    store.deleteUser(target.id);
    res.status(204).end();
  });

  return router;
}

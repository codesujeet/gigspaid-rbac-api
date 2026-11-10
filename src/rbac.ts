/**
 * Single, declarative source of truth for authorization.
 * Roles map to permissions; routes only ever ask "does this user hold permission X?".
 * Anything not listed here is denied (deny-by-default).
 */
export const ROLES = ['admin', 'editor', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

export const PERMISSIONS = [
  'articles:read',
  'articles:create',
  'articles:update',
  'articles:delete',
  'users:read',
  'users:manage',
] as const;
export type Permission = (typeof PERMISSIONS)[number];

export const ROLE_PERMISSIONS: Readonly<Record<Role, readonly Permission[]>> = Object.freeze({
  viewer: Object.freeze(['articles:read'] as const),
  editor: Object.freeze(['articles:read', 'articles:create', 'articles:update'] as const),
  admin: Object.freeze([
    'articles:read',
    'articles:create',
    'articles:update',
    'articles:delete',
    'users:read',
    'users:manage',
  ] as const),
});

export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (ROLES as readonly string[]).includes(value);
}

export function hasPermission(role: Role, permission: Permission): boolean {
  // Own-property lookup so a hostile value can never resolve via the prototype chain.
  if (!Object.prototype.hasOwnProperty.call(ROLE_PERMISSIONS, role)) return false;
  return ROLE_PERMISSIONS[role].includes(permission);
}

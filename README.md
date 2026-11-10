# gigspaid-rbac-api

A small, security-focused REST API with **admin**, **editor** and **viewer** roles, built with Node 22, TypeScript (strict), Express, JWT and zod. Authorization is a single declarative permission map enforced by middleware on every protected route, and the test suite proves that every forbidden action returns **403**.

> Storage is **in-memory** (see [Known limitations](#known-limitations)). This is a reference implementation of the access-control layer, not a production datastore.

## Requirements checklist

| # | Requirement | Where it is implemented | How to verify |
| - | ----------- | ----------------------- | ------------- |
| 1 | Three roles: admin, editor, viewer | [`src/rbac.ts`](src/rbac.ts) (`ROLES`, `ROLE_PERMISSIONS`) | `npx vitest run tests/rbac-unit.test.ts` |
| 2 | Middleware checks the role on every protected route | [`src/middleware/auth.ts`](src/middleware/auth.ts) (`authenticate`, `requirePermission`, `requireRole`); mounted in [`src/app.ts`](src/app.ts); guards declared in [`src/routes/`](src/routes) | `npx vitest run tests/rbac-unit.test.ts` (a test walks the router stack and fails if any route has no guard) |
| 3 | Tests prove forbidden actions return 403 | [`tests/rbac-matrix.test.ts`](tests/rbac-matrix.test.ts) (every route x every role), [`tests/users.test.ts`](tests/users.test.ts) (escalation attempts) | `npm test` (or `npx vitest run tests/rbac-matrix.test.ts --reporter=verbose` to see each `=> 403`) |
| 4 | Seed users for each role | [`src/seed.ts`](src/seed.ts), credentials in [Seed users](#seed-users) | `npm run seed`, or start the server and log in via `POST /auth/login` |
| 5 | README with setup and run steps | [Setup and run](#setup-and-run) below | `npm ci && npm run build && npm test`, then `npm run dev` |
| 6 | Public GitHub repository | https://github.com/codesujeet/gigspaid-rbac-api | open the link |

## Roles and permissions

| Permission         | viewer | editor | admin |
| ------------------ | :----: | :----: | :---: |
| `articles:read`    |   yes  |   yes  |  yes  |
| `articles:create`  |   no   |   yes  |  yes  |
| `articles:update`  |   no   |   yes  |  yes  |
| `articles:delete`  |   no   |   no   |  yes  |
| `users:read`       |   no   |   no   |  yes  |
| `users:manage`     |   no   |   no   |  yes  |

Defined once in [`src/rbac.ts`](src/rbac.ts).

## Routes

| Method | Path                | Auth        | Required permission (roles)                  | Success |
| ------ | ------------------- | ----------- | -------------------------------------------- | ------- |
| GET    | `/health`           | public      | none                                         | 200     |
| POST   | `/auth/login`       | public      | none (rate limited)                          | 200     |
| GET    | `/auth/me`          | token       | any role                                     | 200     |
| GET    | `/articles`         | token       | `articles:read` (viewer, editor, admin)      | 200     |
| GET    | `/articles/:id`     | token       | `articles:read` (viewer, editor, admin)      | 200     |
| POST   | `/articles`         | token       | `articles:create` (editor, admin)            | 201     |
| PUT    | `/articles/:id`     | token       | `articles:update` (editor, admin)            | 200     |
| DELETE | `/articles/:id`     | token       | `articles:delete` (admin)                    | 204     |
| GET    | `/users`            | token       | `users:read` (admin)                         | 200     |
| PATCH  | `/users/:id/role`   | token       | `users:manage` (admin)                       | 200     |
| DELETE | `/users/:id`        | token       | `users:manage` (admin)                       | 204     |

Login is rate limited per client IP (`LOGIN_RATE_LIMIT_MAX` attempts per 15 minutes, default 20; failed and successful attempts both count). Status codes: `401` missing/invalid/expired token, `403` authenticated but not allowed, `404` unknown resource, `409` last-admin protection, `400` malformed JSON, `413` body too large, `422` validation failure, `429` login rate limit. All errors share one shape:

```json
{ "error": { "code": "forbidden", "message": "You do not have permission to perform this action" } }
```

## Seed users

Created on server startup (and verified by `npm run seed`) when `SEED_DEMO_USERS` is enabled. **Demo credentials only: they are disabled by default when `NODE_ENV=production`.**

| Role   | Email                | Password       |
| ------ | -------------------- | -------------- |
| admin  | `admin@example.com`  | `Admin#12345`  |
| editor | `editor@example.com` | `Editor#12345` |
| viewer | `viewer@example.com` | `Viewer#12345` |

A sample article ("Welcome") is also seeded. Passwords are stored as bcrypt hashes.

## Setup and run

Requires Node 20+ (developed and tested on Node 22).

Quick check from a fresh clone: `npm ci && npm run build && npm test`.

```bash
npm ci
cp .env.example .env     # on PowerShell: Copy-Item .env.example .env
npm run dev              # http://localhost:3000, restarts on change
```

Production-style:

```bash
npm run build
NODE_ENV=production JWT_SECRET="$(node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))")" SEED_DEMO_USERS=true npm start
```

In production the server **refuses to start** unless `JWT_SECRET` is set to at least 32 characters. In development/test, an unset secret becomes a random per-process secret (tokens stop working after a restart).

Scripts: `dev`, `build`, `start`, `seed`, `test`, `test:coverage`, `typecheck`.

Environment variables are documented in [`.env.example`](.env.example).

## Try it with curl

```bash
# 1. log in as the viewer and keep the token
TOKEN=$(curl -s -X POST http://localhost:3000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"viewer@example.com","password":"Viewer#12345"}' | node -pe "JSON.parse(require('fs').readFileSync(0,'utf8')).token")

# 2. allowed: viewers can read
curl -i http://localhost:3000/articles -H "Authorization: Bearer $TOKEN"
# HTTP/1.1 200 OK

# 3. forbidden: viewers cannot delete
curl -i -X DELETE http://localhost:3000/articles/any-id -H "Authorization: Bearer $TOKEN"
# HTTP/1.1 403 Forbidden
# {"error":{"code":"forbidden","message":"You do not have permission to perform this action"}}

# 4. no token at all
curl -i http://localhost:3000/users
# HTTP/1.1 401 Unauthorized
# {"error":{"code":"unauthorized","message":"Missing Authorization header"}}
```

The 200 / 403 / 401 responses above are real output from running the built server (`npm run build` + `node dist/server.js`) and curl during development.

## Tests

```bash
npm test                 # vitest + supertest
npm run test:coverage    # with v8 coverage
npm run typecheck
```

What is covered (122 tests):

- **Role x route matrix** (`tests/rbac-matrix.test.ts`): every route for every role with its exact expected status (200/201/204/403). Every 403 case also asserts that the store was left untouched. Every route additionally returns 401 without a token.
- **Authentication failures** (`tests/auth.test.ts`): missing header, wrong scheme, malformed token, expired token, wrong or missing audience, tampered payload (role escalated), tampered signature, wrong secret, `alg: none`, wrong algorithm (HS512), wrong issuer, missing/invalid role claim, deleted user, demoted user (stale role). Login success per seed user, bad credentials, validation, rate limiting (including behind a trusted proxy).
- **Privilege escalation and last-admin protection** (`tests/users.test.ts`): editor/viewer self-promotion, role smuggled in headers/query/body, admin promotion needs a fresh token, sole admin cannot demote or delete themselves (409).
- **Validation, 404s and ordering** (`tests/articles.test.ts`): 422 payloads, unknown ids, authorization evaluated before validation and before resource lookup.
- **Permission map and guards** (`tests/rbac-unit.test.ts`): exact permission sets, deny-by-default for unknown roles and prototype keys, guards fail closed, and a structural test that walks the protected router and fails if any route lacks an RBAC guard.
- **Platform** (`tests/platform.test.ts`): production refuses to start without a strong, non-placeholder `JWT_SECRET`, `JWT_EXPIRES_IN` validation, no CORS headers, seed idempotency, helmet headers, malformed JSON, oversized body, no stack/internals in 500s, uniform error shape.

Real output from `npm test` (Node 22.13.1, Windows 11):

```text
 RUN  v5.1.0

 Test Files  6 passed (6)
      Tests  122 passed (122)
   Duration  2.70s
```

Excerpt of the verbose run showing the 403 proofs from the matrix (`npx vitest run tests/rbac-matrix.test.ts --reporter=verbose`):

```text
✓ POST /articles as viewer => 403
✓ PUT /articles/:id as viewer => 403
✓ DELETE /articles/:id as editor => 403
✓ DELETE /articles/:id as viewer => 403
✓ GET /users as editor => 403
✓ GET /users as viewer => 403
✓ PATCH /users/:id/role as editor => 403
✓ PATCH /users/:id/role as viewer => 403
✓ DELETE /users/:id as editor => 403
✓ DELETE /users/:id as viewer => 403
```

Coverage (`npm run test:coverage`): statements 99.2%, branches 94.66%, functions 100%, lines 99.53%.

As a sanity check of the tests themselves, temporarily granting `articles:delete` to the editor made 4 tests fail (the matrix 403 case and three permission-map tests); the change was reverted.

## Design notes

- **Deny-by-default.** The app is `public router` (health, login) then `authenticate` gate then protected routers. A route added to the protected router is 401 for anonymous callers even if its author forgets to add a guard. Unknown paths return 401 without a token (no route enumeration) and 404 with one. Guards also fail closed: a guard that runs without `req.user` returns 401, never passes through, and `requirePermission()` / `requireRole()` with no arguments throw at startup.
- **Declarative permission map.** Roles map to permissions in one frozen object (`src/rbac.ts`). Routes ask `requirePermission('articles:delete')`; they never compare role strings. Lookups use own-property checks so odd values cannot resolve via the prototype chain.
- **The token is not the source of truth for the role.** The JWT carries only `sub` and a `role` claim. On every request the user is re-loaded from the store and the **store's** role is what authorization uses. If the user was deleted, or their role changed since the token was issued, the request is rejected with 401 and the client must log in again. Roles are never read from the request body, headers or query.
- **JWT hardening.** Algorithm pinned to HS256 (blocks `alg: none` and algorithm confusion), issuer and audience checked, short validated expiry (`JWT_EXPIRES_IN`, default 1h), secret from the environment; in production the server refuses to start with a missing, short (under 32 chars), repetitive or placeholder-looking secret.
- **Privilege escalation.** Only `users:manage` (admin) can change roles. The last remaining admin can neither be demoted nor deleted (409), so the system cannot lock itself out. The rule is enforced inside the store in the same synchronous step as the write, so concurrent requests cannot both pass the check (and no route can bypass it). Request schemas are `strict` so unexpected fields (for example a `role` or `authorId`) are rejected with 422 instead of silently ignored.
- **Authorization before validation.** The guard runs before body validation and resource lookup, so a forbidden caller learns nothing (a viewer deleting a nonexistent id gets 403, not 404).
- **Credentials.** bcrypt (`bcryptjs`, pure JS so it installs everywhere), a dummy-hash comparison for unknown emails to reduce user-enumeration via timing, identical 401 for unknown user and wrong password, login rate limiting, passwords limited to bcrypt's 72 bytes (rejected, not truncated).
- **CORS.** No CORS headers are sent, so browsers on other origins cannot call the API with credentials; add an explicit allow-list (for example the `cors` package) only if a browser front end on another origin is introduced. Tokens travel in the `Authorization` header, not cookies, so CSRF does not apply.
- **Hygiene.** helmet, `x-powered-by` disabled, 100 kb body limit, zod validation, uniform error JSON, 500s return a generic message and log details server-side only.
- **Structure.** `src/app.ts` builds the app without listening; `src/server.ts` starts it. Tests import the app directly and use a fresh store per test.

```
src/
  app.ts            app factory (public router -> authenticate -> protected routers)
  server.ts         entry point (loads .env, seeds, listens)
  config.ts         env parsing and production safety checks
  rbac.ts           roles, permissions, permission map
  seed.ts           demo users/article; seed-cli.ts = `npm run seed`
  errors.ts         HttpError + helpers
  middleware/       auth (authenticate, requirePermission, requireRole), validate, errorHandler
  routes/           auth (public), articles, users
  store/            in-memory store
tests/              vitest + supertest suites
```

## Known limitations

- **In-memory store**: all users, role changes and articles are lost on restart (and are not shared across multiple instances). Replace `src/store` with a real database for production. `npm run seed` therefore only demonstrates the seed module; the running server seeds itself on startup.
- **No token revocation list or refresh tokens.** Tokens are short-lived, and role changes / user deletion invalidate them via the store check, but a logged-out token stays valid until it expires.
- **No user registration or password change endpoints**; users come from the seed module. Role changes are admin-only.
- The login rate limiter is per-process and per-IP (behind a reverse proxy set `TRUST_PROXY_HOPS` to the number of proxies, otherwise all clients share one budget).
- Demo passwords are public. Disable demo seeding (`SEED_DEMO_USERS=false`, the default in production) for any real deployment.

## License

MIT

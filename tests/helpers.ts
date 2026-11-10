import type { Express } from 'express';
import { createApp } from '../src/app';
import { loadConfig, type Config } from '../src/config';
import { signToken } from '../src/middleware/auth';
import type { Role } from '../src/rbac';
import { DEMO_USERS, seed } from '../src/seed';
import { Store, type Article, type User } from '../src/store';

export const TEST_SECRET = 'test-secret-test-secret-test-secret-0123456789';

export interface Ctx {
  app: Express;
  store: Store;
  config: Config;
  user: Record<Role, User>;
  token: Record<Role, string>;
  article: Article;
}

/** Fresh app + store per call so tests never share state. */
export async function buildCtx(overrides: Record<string, string> = {}): Promise<Ctx> {
  const config = loadConfig({
    NODE_ENV: 'test',
    JWT_SECRET: TEST_SECRET,
    BCRYPT_ROUNDS: '4',
    LOGIN_RATE_LIMIT_MAX: '1000',
    ...overrides,
  });
  const store = new Store();
  await seed(store, config.bcryptRounds);
  const app = createApp(config, store);

  const user = {} as Record<Role, User>;
  const token = {} as Record<Role, string>;
  for (const demo of DEMO_USERS) {
    const u = store.findUserByEmail(demo.email)!;
    user[demo.role] = u;
    token[demo.role] = signToken(config, u);
  }
  const article = store.listArticles()[0]!;
  return { app, store, config, user, token, article };
}

export const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });

export const b64url = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');

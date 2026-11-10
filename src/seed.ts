import bcrypt from 'bcryptjs';
import type { Role } from './rbac';
import type { Store } from './store';

/** Demo credentials. Documented in the README. NEVER use in production. */
export const DEMO_USERS: ReadonlyArray<{ email: string; password: string; role: Role }> = [
  { email: 'admin@example.com', password: 'Admin#12345', role: 'admin' },
  { email: 'editor@example.com', password: 'Editor#12345', role: 'editor' },
  { email: 'viewer@example.com', password: 'Viewer#12345', role: 'viewer' },
];

/** Idempotently creates one demo user per role (plus a sample article). */
export async function seed(store: Store, bcryptRounds: number): Promise<void> {
  for (const demo of DEMO_USERS) {
    if (store.findUserByEmail(demo.email)) continue;
    const passwordHash = await bcrypt.hash(demo.password, bcryptRounds);
    store.createUser({ email: demo.email, passwordHash, role: demo.role });
  }
  if (store.listArticles().length === 0) {
    const author = store.findUserByEmail('editor@example.com');
    if (author) {
      store.createArticle({
        title: 'Welcome',
        body: 'Sample article created by the seed module.',
        authorId: author.id,
      });
    }
  }
}

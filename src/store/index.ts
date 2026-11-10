import { randomUUID } from 'node:crypto';
import type { Role } from '../rbac';

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  role: Role;
  createdAt: string;
}

export type PublicUser = Omit<User, 'passwordHash'>;

export interface Article {
  id: string;
  title: string;
  body: string;
  authorId: string;
  createdAt: string;
  updatedAt: string;
}

export const toPublicUser = ({ passwordHash: _omit, ...rest }: User): PublicUser => rest;

/**
 * In-memory data store. Data is lost on restart. Swap this module for a real
 * database layer in production; routes depend only on these methods.
 */
export class Store {
  private readonly users = new Map<string, User>();
  private readonly articles = new Map<string, Article>();

  // ---- users ----
  createUser(input: { email: string; passwordHash: string; role: Role }): User {
    const email = input.email.toLowerCase();
    if (this.findUserByEmail(email)) throw new Error(`User ${email} already exists`);
    const user: User = { id: randomUUID(), createdAt: new Date().toISOString(), ...input, email };
    this.users.set(user.id, user);
    return user;
  }
  findUserById(id: string): User | undefined {
    return this.users.get(id);
  }
  findUserByEmail(email: string): User | undefined {
    const needle = email.toLowerCase();
    for (const u of this.users.values()) if (u.email === needle) return u;
    return undefined;
  }
  listUsers(): User[] {
    return [...this.users.values()];
  }
  countAdmins(): number {
    return this.listUsers().filter((u) => u.role === 'admin').length;
  }
  setUserRole(id: string, role: Role): User | undefined {
    const u = this.users.get(id);
    if (!u) return undefined;
    u.role = role;
    return u;
  }
  deleteUser(id: string): boolean {
    return this.users.delete(id);
  }

  // ---- articles ----
  createArticle(input: { title: string; body: string; authorId: string }): Article {
    const now = new Date().toISOString();
    const article: Article = { id: randomUUID(), createdAt: now, updatedAt: now, ...input };
    this.articles.set(article.id, article);
    return article;
  }
  listArticles(): Article[] {
    return [...this.articles.values()];
  }
  findArticle(id: string): Article | undefined {
    return this.articles.get(id);
  }
  updateArticle(id: string, patch: { title: string; body: string }): Article | undefined {
    const a = this.articles.get(id);
    if (!a) return undefined;
    a.title = patch.title;
    a.body = patch.body;
    a.updatedAt = new Date().toISOString();
    return a;
  }
  deleteArticle(id: string): boolean {
    return this.articles.delete(id);
  }
}

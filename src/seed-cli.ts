import { seed, DEMO_USERS } from './seed';
import { Store } from './store';

// The store is in-memory, so this script seeds a throwaway store and prints what the
// server creates on startup. Useful to verify the seed module and see the demo credentials.
async function main(): Promise<void> {
  const store = new Store();
  await seed(store, 4);
  console.log('Seed module OK. Demo users created on server startup (when SEED_DEMO_USERS is enabled):');
  for (const u of DEMO_USERS) {
    console.log(`  ${u.role.padEnd(6)} ${u.email}  /  ${u.password}`);
  }
  console.log(`Users in throwaway store: ${store.listUsers().length}`);
}

void main();

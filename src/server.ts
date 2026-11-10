import 'dotenv/config';
import { createApp } from './app';
import { loadConfig } from './config';
import { seed } from './seed';
import { Store } from './store';

async function main(): Promise<void> {
  const config = loadConfig(); // throws on unsafe production config => process exits non-zero
  const store = new Store();
  if (config.seedDemoUsers) {
    await seed(store, config.bcryptRounds);
    console.log('Seeded demo users (admin@example.com, editor@example.com, viewer@example.com)');
  }
  const app = createApp(config, store);
  app.listen(config.port, () => {
    console.log(`API listening on http://localhost:${config.port} (${config.nodeEnv})`);
  });
}

main().catch((err: unknown) => {
  console.error('Failed to start:', err instanceof Error ? err.message : err);
  process.exit(1);
});

import { randomBytes } from 'node:crypto';

export interface Config {
  nodeEnv: 'development' | 'test' | 'production';
  port: number;
  jwtSecret: string;
  jwtExpiresIn: string;
  bcryptRounds: number;
  loginRateLimitMax: number;
  seedDemoUsers: boolean;
  logErrors: boolean;
}

const MIN_PROD_SECRET_LENGTH = 32;

function intFromEnv(value: string | undefined, fallback: number, name: string, min: number, max: number): number {
  if (value === undefined || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return n;
}

/**
 * Builds the runtime configuration from environment variables.
 * Throws (so the process refuses to start) on unsafe production configuration.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const rawEnv = env.NODE_ENV ?? 'development';
  if (rawEnv !== 'development' && rawEnv !== 'test' && rawEnv !== 'production') {
    throw new Error(`NODE_ENV must be development, test or production (got "${rawEnv}")`);
  }
  const nodeEnv = rawEnv;

  let jwtSecret = env.JWT_SECRET?.trim() ?? '';
  if (nodeEnv === 'production') {
    if (jwtSecret.length < MIN_PROD_SECRET_LENGTH) {
      throw new Error(
        `JWT_SECRET must be set to a random value of at least ${MIN_PROD_SECRET_LENGTH} characters in production`,
      );
    }
  } else if (jwtSecret === '') {
    // Ephemeral secret: safe default for dev/test, tokens die with the process.
    jwtSecret = randomBytes(48).toString('base64url');
  }

  const seedFlag = env.SEED_DEMO_USERS;
  const seedDemoUsers = seedFlag === undefined || seedFlag === '' ? nodeEnv !== 'production' : seedFlag === 'true';

  return {
    nodeEnv,
    port: intFromEnv(env.PORT, 3000, 'PORT', 0, 65535),
    jwtSecret,
    jwtExpiresIn: env.JWT_EXPIRES_IN?.trim() || '1h',
    bcryptRounds: intFromEnv(env.BCRYPT_ROUNDS, 10, 'BCRYPT_ROUNDS', 4, 15),
    loginRateLimitMax: intFromEnv(env.LOGIN_RATE_LIMIT_MAX, 20, 'LOGIN_RATE_LIMIT_MAX', 1, 100000),
    seedDemoUsers,
    logErrors: nodeEnv !== 'test',
  };
}

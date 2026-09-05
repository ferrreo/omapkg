import type { Env } from './lib/server/env';
import type { Actor } from './lib/model';

declare global {
  namespace App {
    interface Locals {
      user: { id: string; name: string; image?: string | null; githubUsername?: string | null } | null;
      actor: Actor | null;
      authReady: boolean;
    }
    interface Platform { env: Env; context: ExecutionContext; caches: CacheStorage }
  }
}
export {};

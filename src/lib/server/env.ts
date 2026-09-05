import type { GitHubEnv } from './github';

export interface Env extends GitHubEnv {
  DB: D1Database;
  ARTIFACTS: R2Bucket;
  PIPELINE?: Fetcher;
  REGISTRY_ACCOUNT_ID?: string;
  REGISTRY_API_TOKEN?: string;
  CLOUDFLARE_ACCOUNT_ID?: string;
  PUBLIC_ORIGIN: string;
  BETTER_AUTH_SECRET?: string;
  GITHUB_CLIENT_ID?: string;
  GITHUB_CLIENT_SECRET?: string;
  GITHUB_REPO_TOKEN?: string;
  GITHUB_REPOSITORY?: string;
  MAINTAINER_GITHUB_IDS?: string;
  SECURITY_GITHUB_IDS?: string;
  QUARANTINE_HOURS: string;
  CRASH_THRESHOLD?: string;
  SIGNER?: Fetcher;
  SIGNER_URL?: string;
  SIGNER_TOKEN?: string;
  PACKAGE_SIGNING_FINGERPRINT?: string;
  SIGNING_FINGERPRINT?: string;
  PACKAGE_SIGNING_PUBLIC_KEY_R2_KEY?: string;
}

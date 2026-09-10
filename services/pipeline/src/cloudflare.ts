import { Sandbox as CloudflareSandbox } from '@cloudflare/sandbox';
import { runScheduledChecks } from '../schedule';
import { requeuePublications } from '../publication';
import { expireCrashReports, processCrashQuarantines } from '../../../src/lib/server/crashes';
import type { FactoryEnv, PipelineEnv } from '../types';
import type { Env } from '../../../src/lib/server/env';
import { resolveDependencyBlockers } from '../../../src/lib/server/dependency-blockers';

export { ContainerProxy } from '@cloudflare/sandbox';

export class Sandbox extends CloudflareSandbox {
  enableInternet = false;
  interceptHttps = true;
  allowedHosts: string[] = [];
}

export { FactoryWorkflow } from './workflow';

export { PublicationWorkflow } from '../publication';

export { CatalogImportWorkflow } from '../catalog-import';

export default {
  async scheduled(_controller: ScheduledController, env: PipelineEnv) {
    await expireCrashReports(env as unknown as Env);
    await processCrashQuarantines(env as unknown as Env);
    await requeuePublications(env as unknown as Env);
    await resolveDependencyBlockers(env);
    await runScheduledChecks(env as unknown as FactoryEnv);
  },
};

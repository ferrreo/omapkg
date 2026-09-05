import { Sandbox as CloudflareSandbox } from '@cloudflare/sandbox';
import { runScheduledChecks } from '../schedule';
import { requeuePublications } from '../publication';
import { expireCrashReports, processCrashQuarantines } from '../../../src/lib/server/crashes';
import type { FactoryEnv, PipelineEnv } from '../types';
import type { Env } from '../../../src/lib/server/env';
export { ContainerProxy } from '@cloudflare/sandbox';

export class Sandbox extends CloudflareSandbox {
  enableInternet = false;
  interceptHttps = true;
  allowedHosts: string[] = [];
}

export { FactoryWorkflow } from './workflow';
export { PublicationWorkflow } from '../publication';

export default {
  async scheduled(_controller: ScheduledController, env: PipelineEnv) {
    await expireCrashReports(env as unknown as Env);
    await processCrashQuarantines(env as unknown as Env);
    await requeuePublications(env as unknown as Env);
    await runScheduledChecks(env as unknown as FactoryEnv);
  },
};

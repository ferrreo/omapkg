import { getSandbox, type Sandbox as CloudflareSandbox } from '@cloudflare/sandbox';
import { cloudflareSandbox } from '@flue/runtime/cloudflare';
import type { Sandbox as FlueSandbox } from '@flue/runtime';
import { audit, now } from '../../src/lib/server/db';
import type { FactoryEnv, FactoryRequest, FactoryWorkflowBinding } from './types';
import { detectUpstreamRelease, dispatchUpstreamFactory, trackedUpstreamRequests, type UpstreamRequestRow } from './release';
import { normalizeRedirectSourceUrl, normalizeSourceUrl, redactText } from './security';
import type { SourceHostAuthorizer } from './source-fetch';
import { checkSourceOfTruth, type SourceTruthCheckResult } from './integrity';

const MAX_REQUESTS = 50;

type ScheduleEnv = Pick<FactoryEnv, 'DB' | 'Sandbox'> & { FACTORY?: FactoryWorkflowBinding };

function requestFromRow(row: UpstreamRequestRow): FactoryRequest {
  return {
    id: row.id,
    name: row.name,
    upstreamUrl: normalizeSourceUrl(row.upstream_url).toString(),
    sourceKind: row.source_kind,
    area: row.area,
    declaredLicense: row.declared_license,
    upstreamRef: row.upstream_ref,
  };
}

async function recordCheckError(env: Pick<FactoryEnv, 'DB'>, requestId: string, cause: unknown): Promise<void> {
  const message = redactText(cause instanceof Error ? cause.message : 'upstream check failed').slice(0, 1_000);
  await env.DB.batch([
    env.DB.prepare(`INSERT INTO upstream_checks(request_id,last_checked_at,error)
      VALUES(?,?,?) ON CONFLICT(request_id) DO UPDATE SET last_checked_at=excluded.last_checked_at,error=excluded.error`)
      .bind(requestId, now(), message),
    audit(env.DB, 'system:upstream-check', 'upstream.release_check_failed', requestId, { error: message }),
  ]);
}

export async function checkUpstreams(env: ScheduleEnv, limit = MAX_REQUESTS): Promise<{ checked: number; failed: number; pendingRequestIds: string[] }> {
  const rows = await trackedUpstreamRequests(env, limit);
  let failed = 0;
  const pendingRequestIds: string[] = [];
  for (const row of rows) {
    const request = requestFromRow(row);
    try {
      let sandbox: FlueSandbox | undefined;
      let allowHost: SourceHostAuthorizer | undefined;
      let createSandbox: (() => Promise<{ sandbox: FlueSandbox; allowHost: SourceHostAuthorizer }>) | undefined;
      if (request.sourceKind === 'git' || request.sourceKind === 'archive') {
        if (!env.Sandbox) {
          if (request.sourceKind === 'git') throw new Error('upstream Git checks require Sandbox binding');
        } else {
          const allowedHosts = new Set([new URL(request.upstreamUrl).hostname]);
          const stub = getSandbox(env.Sandbox as DurableObjectNamespace<CloudflareSandbox>, `release-check-${request.id}`, {
            sleepAfter: '15m',
            labels: { requestId: request.id, phase: 'upstream-release-check' },
          });
          const create = async () => {
            await stub.setAllowedHosts([...allowedHosts]);
            const authorize: SourceHostAuthorizer = async (hostname) => {
              const host = normalizeRedirectSourceUrl(`https://${hostname}/`).hostname;
              if (allowedHosts.has(host)) return;
              allowedHosts.add(host);
              await stub.setAllowedHosts([...allowedHosts]);
            };
            return {
              sandbox: await cloudflareSandbox(stub, { cwd: '/workspace' }).createSandbox({ id: `release-check-${request.id}` }),
              allowHost: authorize,
            };
          };
          if (request.sourceKind === 'git') {
            ({ sandbox, allowHost } = await create());
          } else {
            createSandbox = create;
          }
        }
      }
      const result = await detectUpstreamRelease(env, request, { sandbox, allowHost, createSandbox, currentVersion: row.published_version });
      if (result.pendingRequestId) {
        pendingRequestIds.push(result.pendingRequestId);
        await dispatchUpstreamFactory(env, result.pendingRequestId);
      }
    } catch (cause) {
      failed += 1;
      await recordCheckError(env, request.id, cause);
    }
  }
  return { checked: rows.length, failed, pendingRequestIds };
}

export async function runScheduledChecks(env: FactoryEnv): Promise<{
  upstream: { checked: number; failed: number; pendingRequestIds: string[] };
  integrity: SourceTruthCheckResult;
}> {
  const upstream = await checkUpstreams(env as unknown as ScheduleEnv);
  const integrity = await checkSourceOfTruth(env);
  return { upstream, integrity };
}

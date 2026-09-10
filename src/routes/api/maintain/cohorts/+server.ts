import { json } from '@sveltejs/kit';
import { cohortMemberCount, cohortPageSize } from '$lib/cohorts';
import { humanMaintainer } from '$lib/server/catalog-ownership';
import { beginCohortScope, appendCohortScope, sealCohortScope } from '$lib/server/cohort-scope-uploads';
import { checkCohortPage, cohortEventPageProofs, cohortPageProgress } from '$lib/server/cohort-gate-pages';
import { cohortChangePage } from '$lib/server/cohort-changelogs';
import { cohortMembers, readCohortManifest } from '$lib/server/cohort-members';
import { getCohort } from '$lib/server/cohorts';
import { environment, jsonBody, sameOrigin } from '$lib/server/http';
import { PolicyError } from '$lib/server/policy';
import { sha256 } from '$lib/server/db';
import type { RequestHandler } from './$types';

const headers = { 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };

export const GET: RequestHandler = async (event) => {
  try {
    humanMaintainer(event.locals.actor);
    const env = environment(event); const record = await getCohort(env.DB, event.url.searchParams.get('cohortId') ?? '');
    const manifest = await readCohortManifest(record);
    const expected = event.url.searchParams.get('manifestSha256');

    if (expected && expected !== record.manifest_sha256) throw new PolicyError(409, 'Cohort scope changed. Restart from the current revision.');

    if (event.url.searchParams.get('operation') === 'proofs') return json(await cohortEventPageProofs(env.DB, record.id,
      Number(event.url.searchParams.get('sequence')), Number(event.url.searchParams.get('after') ?? '-1')), { headers });

    if (event.url.searchParams.get('operation') === 'report') {
      const digest = event.url.searchParams.get('digest') ?? '';

      if (!/^[a-f0-9]{64}$/.test(digest)) throw new PolicyError(400, 'Choose an exact verification report.');
      const row = await env.DB.prepare('SELECT report_json FROM cohort_gate_pages WHERE cohort_id=? AND digest=?').bind(record.id, digest).first<{ report_json: string }>();

      if (!row || await sha256(row.report_json) !== digest) throw new PolicyError(404, 'Verified cohort report not found.');

      return new Response(row.report_json, { headers: { ...headers, 'Content-Type': 'application/json' } });
    }

    if (event.url.searchParams.get('operation') === 'changes') return json(await cohortChangePage(env.DB, record, event.url.searchParams.get('after') ?? ''), { headers });

    if (event.url.searchParams.get('operation') === 'progress') return json(await cohortPageProgress(env.DB, record), { headers });
    const page = Number(event.url.searchParams.get('page') ?? '0');

    if (!Number.isSafeInteger(page) || page < 0 || page * cohortPageSize >= cohortMemberCount(manifest)) throw new PolicyError(400, 'Choose an existing member page.');
    const members = await cohortMembers(env.DB, record, page * cohortPageSize);

    return json({ record, manifest, page, memberCount: cohortMemberCount(manifest), members,
      nextPage: (page + 1) * cohortPageSize < cohortMemberCount(manifest) ? page + 1 : null }, { headers });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};

export const POST: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin); humanMaintainer(event.locals.actor);
    const input = await jsonBody(event.request, 1024 * 1024) as Record<string, unknown>;

    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PolicyError(400, 'Send a cohort operation.');
    const env = environment(event); const actor = event.locals.actor;

    if (input.operation === 'begin') return json(await beginCohortScope(env.DB, actor, String(input.cohortId ?? ''), input.expectedRevision as number | null,
      input.metadata, input.memberCount as number, input.proposalId as string), { headers });

    if (input.operation === 'check') {
      if (typeof input.phase !== 'string') throw new PolicyError(400, 'Select the cohort phase being checked.');
      const result = await checkCohortPage(env, actor, String(input.cohortId ?? ''), input.revision as number, String(input.manifestSha256 ?? ''), input.page as number, input.phase);

      return json(result, { headers });
    }

    if (typeof input.uploadId !== 'string' || !/^[a-f0-9]{64}$/.test(input.uploadId)) throw new PolicyError(400, 'Choose an exact scope upload.');

    if (input.operation === 'append') return json(await appendCohortScope(env.DB, actor, input.uploadId, input.index as number, input.members), { headers });

    if (input.operation === 'seal') {
      const result = await sealCohortScope(env.DB, actor, input.uploadId, input.reason as string);

      return json(result, { headers });
    }

    throw new PolicyError(400, 'Unknown cohort operation.');
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};

import { json, type RequestHandler } from '@sveltejs/kit';
import { addQualificationException, createQualificationPlan, qualificationEvidencePage, reviewQualificationPlan } from '$lib/server/native-qualification';
import { environment, jsonBody, sameOrigin } from '$lib/server/http';
import { humanMaintainer } from '$lib/server/catalog-ownership';
import { PolicyError } from '$lib/server/policy';

const headers = { 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };

export const GET: RequestHandler = async (event) => {
  try {
    const actor = event.locals.actor; humanMaintainer(actor); const env = environment(event);
    const cohortId = event.url.searchParams.get('cohortId') ?? ''; const revision = Number(event.url.searchParams.get('revision') ?? '0');
    if (!cohortId || !Number.isSafeInteger(revision) || revision < 1) throw new PolicyError(400, 'Choose a cohort candidate.');
    return json(await qualificationEvidencePage(env.DB, cohortId, revision), { headers });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};

export const POST: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin); const actor = event.locals.actor; humanMaintainer(actor); const env = environment(event);
    const input = await jsonBody(event.request, 1024 * 1024);
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new PolicyError(400, 'Send a qualification operation.');
    const value = input as Record<string, unknown>;
    if (value.operation === 'create-plan') return json(await createQualificationPlan(env, actor, value.plan), { headers });
    if (value.operation === 'review-plan') return json(await reviewQualificationPlan(env, actor, String(value.planId ?? ''), value.kind as 'area' | 'security', String(value.reason ?? '')), { headers });
    if (value.operation === 'exception') return json(await addQualificationException(env, actor, {
      evidenceId: String(value.evidenceId ?? ''), subjectSha256: String(value.subjectSha256 ?? ''), reason: String(value.reason ?? ''), expiresAt: Number(value.expiresAt)
    }), { headers });
    throw new PolicyError(400, 'Unknown qualification operation.');
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};

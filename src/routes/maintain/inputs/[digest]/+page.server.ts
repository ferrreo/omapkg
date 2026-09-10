import type { FrozenManifest, FrozenPackage } from '$lib/frozen-inputs';
import { getInputLock, reviewInputLock, revokeInputReview, selectInputLock } from '$lib/server/input-locks';
import { inputAuthority } from '$lib/server/input-objects';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { query } from '$lib/server/db';
import { assembleOwnedInputLock, ownedInputChoices } from '$lib/server/input-assembly';
import { redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async (event) => {
  const env = environment(event); const actor = maintainer(event); const lock = await getInputLock(env.DB, event.params.digest);
  const offset = Math.max(0, Math.min(65536, Math.floor(Number(event.url.searchParams.get('offset')) || 0)));
  const search = (event.url.searchParams.get('search') ?? '').slice(0, 128);
  const reviews = await query<{ id: string; kind: string; actor: string; reason: string; created_at: number; revoked_at: number | null; revoke_reason: string | null }>(env.DB,
    'SELECT * FROM input_lock_reviews WHERE lock_sha256=? ORDER BY created_at,id', lock.sha256);
  const records = await query<{ package_json: string }>(env.DB, `SELECT package_json FROM input_lock_packages WHERE lock_sha256=?
    AND json_extract(package_json,'$.name') LIKE ? ORDER BY json_extract(package_json,'$.name'),package_sha256,origin_evidence LIMIT 101 OFFSET ?`, lock.sha256, `%${search}%`, offset);
  let canManage = false; try { await inputAuthority(env.DB, actor); canManage = true; } catch { /* Read access remains available. */ }
  const recipe = await env.DB.prepare(`SELECT q.name,r.request_id,c.title FROM revisions r JOIN requests q ON q.id=r.request_id
    JOIN cohort_revisions c ON c.cohort_id=? AND c.revision=? WHERE r.id=?`).bind(lock.cohort_id, lock.cohort_revision, lock.recipe_revision_id)
    .first<{ name: string; request_id: string; title: string }>();
  const choices = lock.status === 'ready' ? await ownedInputChoices(env.DB, lock.sha256) : [];
  return { lock, manifest: JSON.parse(lock.manifest_json) as FrozenManifest, recipe, canManage, reviews, offset, search, actorId: actor.id,
    ownedRequired: choices.length, ownedAvailable: choices.filter((choice) => choice.candidates.length > 0).length,
    ownedMissing: choices.filter((choice) => !choice.candidates.length).slice(0, 100).map(({ source }) => ({ name: source.name, version: source.version, architecture: source.architecture })),
    ownedConflicts: choices.filter((choice) => choice.candidates.length > 1).map(({ source, candidates }) => ({ name: source.name, version: source.version,
      key: source.package.sha256, candidates: candidates.map((candidate) => ({ buildId: candidate.buildId, attempt: candidate.attempt, origin: candidate.package.originEvidence, sha256: candidate.package.package.sha256 })) })),
    packages: records.slice(0, 100).map((row) => JSON.parse(row.package_json) as FrozenPackage), hasMore: records.length > 100,
    current: !!await env.DB.prepare('SELECT 1 FROM current_input_locks WHERE sha256=?').bind(lock.sha256).first(),
    selected: !!await env.DB.prepare('SELECT 1 FROM build_input_selections WHERE lock_sha256=?').bind(lock.sha256).first(),
  };
};
export const actions: Actions = {
  assemble: (event) => formAction(event, async (form) => {
    const choices = Object.fromEntries([...form.entries()].filter(([key]) => key.startsWith('provider:')).map(([key, value]) => [key.slice(9), String(value)]));
    const lock = await assembleOwnedInputLock(environment(event), event.locals.actor, event.params.digest, choices, field(form, 'reason'));
    redirect(303, `/maintain/inputs/${lock.sha256}`);
  }),
  review: (event) => formAction(event, (form) => reviewInputLock(environment(event), event.locals.actor, event.params.digest, field(form, 'kind') as 'area' | 'security', field(form, 'reason'))),
  revoke: (event) => formAction(event, (form) => revokeInputReview(environment(event), event.locals.actor, event.params.digest, field(form, 'reviewId'), field(form, 'reason'))),
  select: (event) => formAction(event, (form) => selectInputLock(environment(event), event.locals.actor, event.params.digest, field(form, 'reason'))),
};

import { inputAuthority } from '$lib/server/input-objects';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { query } from '$lib/server/db';
import type { InputLockRow } from '$lib/server/input-locks';
import { revokeNativeInput } from '$lib/server/input-owned';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const env = environment(event); const actor = maintainer(event);
  const search = (event.url.searchParams.get('search') ?? '').slice(0, 128);
  let canManage = false;

 try { await inputAuthority(env.DB, actor); canManage = true; } catch { /* Maintainers can read retained inputs. */ }

  return { canManage, search,
    locks: await query<InputLockRow & { pkgbase: string; title: string; review_count: number; selected: number }>(env.DB, `SELECT l.*,m.pkgbase,c.title,
      (SELECT COUNT(*) FROM input_lock_reviews review WHERE review.lock_sha256=l.sha256 AND review.revoked_at IS NULL) AS review_count,
      EXISTS(SELECT 1 FROM build_input_selections s WHERE s.lock_sha256=l.sha256) AS selected FROM input_locks l
      JOIN cohort_revisions c ON c.cohort_id=l.cohort_id AND c.revision=l.cohort_revision
      JOIN cohort_members m ON m.cohort_id=l.cohort_id AND m.revision=l.cohort_revision AND m.recipe_revision_id=l.recipe_revision_id
      WHERE m.pkgbase LIKE ? ORDER BY l.created_at DESC,l.sha256 LIMIT 100`, `%${search}%`),
    candidates: await query<{ id: string; pkgbase: string; title: string; cohort_sha256: string; recipe_sha256: string }>(env.DB, `SELECT r.id,m.pkgbase,c.title,
      c.manifest_sha256 AS cohort_sha256,r.recipe_sha256 FROM cohort_members m JOIN cohorts scope ON scope.id=m.cohort_id AND scope.current_revision=m.revision
      JOIN cohort_revisions c ON c.cohort_id=m.cohort_id AND c.revision=m.revision JOIN revisions r ON r.id=m.recipe_revision_id
      WHERE r.surface='binary' AND m.pkgbase LIKE ? ORDER BY m.pkgbase,c.title LIMIT 500`, `%${search}%`),
    nativeInputs: await query<{ package_sha256: string; origin_evidence: string; package_json: string; build_id: string; attempt: number; eligible: number; revoked_at: number | null; revoke_reason: string | null }>(env.DB,
      `SELECT p.package_sha256,p.origin_evidence,p.package_json,p.build_id,p.attempt,p.revoked_at,p.revoke_reason,EXISTS(SELECT 1 FROM eligible_owned_inputs e
       WHERE e.package_sha256=p.package_sha256 AND e.origin_evidence=p.origin_evidence) AS eligible FROM input_owned_packages p
       WHERE json_extract(p.package_json,'$.name') LIKE ? ORDER BY p.created_at DESC,p.package_sha256 LIMIT 100`, `%${search}%`),
  };
};

export const actions: Actions = {
  revoke: (event) => formAction(event, (form) => revokeNativeInput(environment(event), event.locals.actor, field(form, 'digest'), field(form, 'origin'), field(form, 'reason'))),
};

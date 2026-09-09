import { error } from '@sveltejs/kit';
import { query } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { finalDescription } from '$lib/server/descriptions';
import { retryBuild } from '$lib/server/workers';
import { buildArtifacts, packageFilename, storedOutputContract } from '$lib/server/build-outputs';
import type { Build, Revision } from '$lib/model';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async (event) => {
  maintainer(event);
  const { DB } = environment(event);
  const build = await DB.prepare('SELECT * FROM builds WHERE id=?').bind(event.params.id).first<Build>();
  if (!build) error(404, 'Build not found.');
  const revisionRow = await DB.prepare('SELECT * FROM revisions WHERE id=?').bind(build.revision_id).first<Revision>();
  const revision = revisionRow ? { ...revisionRow, description: finalDescription(revisionRow) } : revisionRow;
  const logs = await query<{ attempt: number; sequence: number; text: string; created_at: number }>(DB,
    'SELECT attempt,sequence,text,created_at FROM build_logs WHERE build_id=? ORDER BY attempt,sequence LIMIT 500', build.id);
  const contract = storedOutputContract(build);
  const artifacts = contract ? await buildArtifacts(DB, build) : [];
  const outputs = contract?.outputs.map((output) => ({ ...output, filename: packageFilename(output),
    artifact: artifacts.find((artifact) => artifact.filename === packageFilename(output)) ?? null })) ?? [];
  return { build, revision, logs, outputContract: contract, outputs };
};

export const actions: Actions = {
  retry: (event) => formAction(event, async (form) => retryBuild(environment(event).DB, event.locals.actor, event.params.id, field(form, 'reason'))),
};

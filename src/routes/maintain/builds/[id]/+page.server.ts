import { signNativeOutput } from '$lib/server/native-signing';
import { retainNativeInput } from '$lib/server/input-owned';
import { inputAuthority } from '$lib/server/input-objects';
import { humanMaintainer } from '$lib/server/catalog-ownership';
import { PolicyError } from '$lib/server/policy';
import { WorkerProtocolError } from '$lib/server/worker-protocol';
import { error } from '@sveltejs/kit';
import { query } from '$lib/server/db';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { finalDescription } from '$lib/server/descriptions';
import { retryBuild } from '$lib/server/workers';
import { buildArtifacts, packageFilename, storedOutputContract } from '$lib/server/build-outputs';
import { preservedBuildInputs } from '$lib/preserved-recipe';
import type { Build, Revision } from '$lib/model';
import type { Actions, PageServerLoad } from './$types';
export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event);
  const { DB } = environment(event);
  const build = await DB.prepare('SELECT * FROM builds WHERE id=?').bind(event.params.id).first<Build>();
  if (!build) error(404, 'Build not found.');
  const revisionRow = await DB.prepare('SELECT * FROM revisions WHERE id=?').bind(build.revision_id).first<Revision>();
  const revision = revisionRow ? { ...revisionRow, description: finalDescription(revisionRow) } : revisionRow;
  const logs = await query<{ attempt: number; sequence: number; text: string; created_at: number }>(DB,
    'SELECT attempt,sequence,text,created_at FROM build_logs WHERE build_id=? ORDER BY attempt,sequence LIMIT 500', build.id);
  const contract = storedOutputContract(build);
  const artifacts = contract ? await buildArtifacts(DB, build) : [];
  const signatures = contract ? await query<{ artifact_filename: string; signature_sha256: string }>(DB,
    "SELECT DISTINCT artifact_filename,signature_sha256 FROM signing_intents WHERE build_id=? AND build_attempt=? AND status='signed'", build.id, build.attempt) : [];
  const request = revision ? await DB.prepare('SELECT area FROM requests WHERE id=?').bind(revision.request_id).first<{ area: string }>() : null;
  let canSign = false; try { humanMaintainer(actor, request?.area); canSign = !!request && build.status === 'succeeded'; } catch { /* Read access remains available. */ }
  let canRetain = false; try { await inputAuthority(DB, actor); canRetain = !!build.input_lock_sha256 && canSign; } catch { /* Retention requires system authority. */ }
  const retained = await query<{ package_sha256: string; origin_evidence: string }>(DB,
    'SELECT package_sha256,origin_evidence FROM input_owned_packages WHERE build_id=? AND attempt=? AND revoked_at IS NULL', build.id, build.attempt);
  const outputs = contract?.outputs.map((output) => ({ ...output, filename: packageFilename(output),
    signature: signatures.find((item) => item.artifact_filename === packageFilename(output)) ?? null,
    artifact: artifacts.find((artifact) => artifact.filename === packageFilename(output)) ?? null })) ?? [];
  return { build, revision, logs, preserved: revisionRow ? preservedBuildInputs(revisionRow, build.architecture) : null,
    outputContract: contract, outputs, canSign, canRetain, retained, statementSigned: signatures.some((item) => item.artifact_filename === 'attestation.json') };
};

export const actions: Actions = {
  retain: (event) => formAction(event, async (form) => {
    try { await retainNativeInput(environment(event), event.locals.actor, event.params.id, Number(field(form, 'attempt')), field(form, 'filename')); }
    catch (cause) { if (cause instanceof WorkerProtocolError) throw new PolicyError(cause.status, cause.message); throw cause; }
  }),
  sign: (event) => formAction(event, async (form) => {
    try { return await signNativeOutput(environment(event), event.locals.actor, event.params.id, Number(field(form, 'attempt')), field(form, 'filename')); }
    catch (cause) { if (cause instanceof WorkerProtocolError) throw new PolicyError(cause.status, cause.message); throw cause; }
  }),
  retry: (event) => formAction(event, async (form) => retryBuild(environment(event).DB, event.locals.actor, event.params.id, field(form, 'reason'))),
};

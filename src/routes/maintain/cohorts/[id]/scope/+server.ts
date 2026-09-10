import { error } from '@sveltejs/kit';
import { getCohort } from '$lib/server/cohorts';
import { cohortMemberStream, readCohortManifest } from '$lib/server/cohort-members';
import { environment, maintainer } from '$lib/server/http';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async (event) => {
  maintainer(event);
  const { DB } = environment(event); const record = await getCohort(DB, event.params.id);

  if (event.url.searchParams.get('digest') !== record.manifest_sha256) error(409, 'Cohort scope changed. Download its current proposal.');
  const manifest = await readCohortManifest(record);

  const metadata = { title: manifest.title, lane: manifest.lane, systemVersion: manifest.systemVersion,
    parentSnapshot: manifest.parentSnapshot, compatibleSystems: manifest.compatibleSystems };

  async function* output() {
    yield JSON.stringify(metadata).slice(0, -1) + ',"members":[';
    let first = true;

    for await (const member of cohortMemberStream(DB, record)) {
      yield (first ? '' : ',') + JSON.stringify({ pkgbase: member.pkgbase, catalogRevision: member.catalogRevision,
        recipeRevisionId: member.recipe?.id ?? null, cause: member.cause, reason: member.reason });
      first = false;
    }

    yield ']}';
  }

  const source = output(); const encoder = new TextEncoder();

  return new Response(new ReadableStream<Uint8Array>({
    async pull(controller) { const value = await source.next();

 if (value.done) controller.close(); else controller.enqueue(encoder.encode(value.value)); },
    async cancel() { await source.return(); },
  }), { headers: { 'Content-Type': 'application/json', 'Content-Disposition': 'attachment; filename="cohort-scope.json"',
    'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' } });
};

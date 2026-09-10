import { error } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import { sha256 } from '$lib/server/db';
import { cohortChangeMarkdown, cohortChangeStream, cohortMarkdownParts, previousCohortScope, type CohortFacts } from '$lib/server/cohort-changelogs';
import { readCohortManifest, type CohortScopeRecord } from '$lib/server/cohort-members';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async (event) => {
  maintainer(event);
  const digest = event.url.searchParams.get('digest') ?? '';
  if (!/^[a-f0-9]{64}$/.test(digest)) error(400, 'Select an exact changelog digest.');
  const { DB } = environment(event);
  const row = await DB.prepare('SELECT document_json,markdown FROM cohort_changelogs WHERE cohort_id=? AND digest=?')
    .bind(event.params.id, digest).first<{ document_json: string; markdown: string }>();
  if (!row || await sha256(row.document_json) !== digest) error(404, 'Verified changelog not found.');
  const markdown = event.url.searchParams.get('format') === 'markdown';
  const changes = event.url.searchParams.get('format') === 'changes';
  const document = JSON.parse(row.document_json) as { facts: CohortFacts; narrative: string };
  let body: BodyInit = markdown ? row.markdown : row.document_json;
  if ((markdown || changes) && document.facts.schemaVersion === 2) {
    const facts = document.facts;
    const scope = await DB.prepare('SELECT cohort_id AS id,revision AS current_revision,manifest_json,manifest_sha256 FROM cohort_revisions WHERE cohort_id=? AND revision=?')
      .bind(event.params.id, facts.revision).first<CohortScopeRecord>();
    if (!scope || scope.manifest_sha256 !== facts.manifestSha256 || facts.changes.manifestSha256 !== facts.manifestSha256) error(409, 'Changelog scope is unavailable.');
    await readCohortManifest(scope);
    const previous = await previousCohortScope(DB, scope);
    if ((previous?.manifest_sha256 ?? null) !== facts.changes.previousManifestSha256) error(409, 'Changelog baseline changed.');
    const parts = cohortMarkdownParts(facts, document.narrative);
    async function* output() {
      yield markdown ? parts.before : `{"schemaVersion":1,"changelogSha256":"${digest}","changes":[`;
      let count = 0;
      for await (const change of cohortChangeStream(DB, scope!)) {
        yield markdown ? cohortChangeMarkdown(change) + '\n' : (count ? ',' : '') + JSON.stringify(change);
        count++;
      }
      if (count !== facts.changes.count) throw new Error('Complete changelog coverage could not be verified.');
      yield markdown ? parts.after : ']}';
    }
    const source = output(); const encoder = new TextEncoder();
    body = new ReadableStream<Uint8Array>({
      async pull(controller) { const item = await source.next(); if (item.done) controller.close(); else controller.enqueue(encoder.encode(item.value)); },
      async cancel() { await source.return(); },
    });
  } else if (changes && document.facts.schemaVersion === 1) body = JSON.stringify({ schemaVersion: 1, changelogSha256: digest, changes: document.facts.changes });
  return new Response(body, { headers: {
    'Content-Type': markdown ? 'text/markdown; charset=utf-8' : 'application/json',
    'Content-Disposition': `attachment; filename="${markdown ? 'CHANGELOG.md' : changes ? 'changes.json' : 'changelog.json'}"`,
    'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff',
  } });
};

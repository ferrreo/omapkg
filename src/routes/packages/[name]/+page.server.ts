import { error } from '@sveltejs/kit';
import { query } from '$lib/server/db';
import { environment } from '$lib/server/http';
import { finalDescription } from '$lib/server/descriptions';
import type { Architecture, PackageRequest, CatalogRelease, Release, Revision } from '$lib/model';
import type { PageServerLoad } from './$types';

type PublicRequest = Pick<PackageRequest, 'id' | 'name' | 'description' | 'upstream_url' | 'source_kind' | 'area' | 'status' | 'created_at' | 'updated_at'>;
type PublicRevision = Pick<Revision, 'id' | 'request_id' | 'version' | 'description' | 'recipe' | 'explanation' | 'dependencies_json' | 'license' | 'upstream_commit'>;
type PublicRelease = Pick<Release, 'id' | 'build_id' | 'name' | 'version' | 'architecture' | 'surface' | 'channel' | 'published_at' | 'stable_at'>
  & Pick<CatalogRelease, 'artifact_filename' | 'artifact_sha256' | 'artifact_size'>
  & { sbom_key: string | null; provenance_key: string | null };

export const load: PageServerLoad = async (event) => {
  const { DB } = environment(event);
  const channel = event.url.searchParams.get('channel') === 'dev' ? 'dev' : 'stable';
  const requestedArchitecture = event.url.searchParams.get('architecture');
  if (requestedArchitecture && requestedArchitecture !== 'x86_64' && requestedArchitecture !== 'aarch64') error(400, 'Architecture must be x86_64 or aarch64.');
  const releases = await query<PublicRelease>(DB, `SELECT r.id,r.build_id,r.name,r.version,r.architecture,r.surface,r.channel,r.published_at,r.stable_at,
    b.artifact_filename,b.artifact_sha256,b.artifact_size,
    CASE WHEN r.sbom_key IS NULL THEN NULL ELSE '/repo/metadata/' || r.id || '/sbom.json' END AS sbom_key,
    CASE WHEN r.provenance_key IS NULL THEN NULL ELSE '/repo/metadata/' || r.id || '/provenance.json' END AS provenance_key
    FROM releases r JOIN builds b ON b.id=r.build_id WHERE r.name=? AND (r.channel=? OR (?='stable' AND r.channel='withdrawn' AND r.stable_at IS NOT NULL))
    ORDER BY CASE r.channel WHEN 'stable' THEN 0 WHEN 'dev' THEN 1 ELSE 2 END,r.stable_at DESC,r.published_at DESC`, event.params.name, channel, channel);
  if (!releases.length) error(404, 'Published package not found.');
  const architecture: Architecture = requestedArchitecture === 'x86_64' || requestedArchitecture === 'aarch64'
    ? requestedArchitecture
    : releases[0].architecture;
  const availableArchitectures = [...new Set(releases.map((release) => release.architecture))];
  const scopedReleases = releases.filter((release) => release.architecture === architecture);
  if (!scopedReleases.length) error(404, 'Published package is not available for this architecture.');
  const revisions = (await query<PublicRevision>(DB, `SELECT DISTINCT r.id,r.request_id,r.version,r.description,r.recipe,r.explanation,r.dependencies_json,r.license,r.upstream_commit
    FROM revisions r JOIN builds b ON b.revision_id=r.id JOIN releases p ON p.build_id=b.id WHERE p.name=? AND (p.channel=? OR (?='stable' AND p.channel='withdrawn' AND p.stable_at IS NOT NULL)) AND b.architecture=?
    ORDER BY CASE p.channel WHEN 'stable' THEN 0 WHEN 'dev' THEN 1 ELSE 2 END,p.stable_at DESC,p.published_at DESC`, event.params.name, channel, channel, architecture))
    .map((revision) => ({ ...revision, description: finalDescription(revision, event.params.name) }));
  const request = await DB.prepare('SELECT id,name,description,upstream_url,source_kind,area,status,created_at,updated_at FROM requests WHERE id=?').bind(revisions[0].request_id).first<PublicRequest>();
  const releaseIds = scopedReleases.map((release) => release.id);
  const feedback = await query<{ works: number; comment: string; created_at: number }>(DB, 'SELECT works,comment,created_at FROM feedback WHERE release_id IN (SELECT value FROM json_each(?)) ORDER BY created_at DESC LIMIT 50', JSON.stringify(releaseIds));
  const crashes = event.locals.actor && event.locals.actor.role !== 'public'
    ? await query<{ id: string; release_id: string; summary: string; consent_version: string; created_at: number; resolved_at: number | null; resolved_by: string | null; confirmed_at: number | null; confirmed_by: string | null }>(DB, `SELECT c.id,c.release_id,c.summary,c.consent_version,c.created_at,c.resolved_at,
      resolver.username AS resolved_by,c.confirmed_at,confirmer.username AS confirmed_by FROM crash_reports c
      LEFT JOIN github_identities resolver ON ('github:' || resolver.github_id)=c.resolved_by
      LEFT JOIN github_identities confirmer ON ('github:' || confirmer.github_id)=c.confirmed_by
       WHERE c.release_id IN (SELECT value FROM json_each(?)) ORDER BY c.created_at DESC LIMIT 50`, JSON.stringify(releaseIds))
    : [];
  return { name: event.params.name, channel, architecture, architectures: availableArchitectures, releases: scopedReleases, request, revisions, feedback, crashes };
};

import { error, json } from '@sveltejs/kit';
import { environment, maintainer } from '$lib/server/http';
import { sha256 } from '$lib/server/db';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async (event) => {
  maintainer(event); const { DB } = environment(event);

  const evidence = await DB.prepare(`SELECT r.report_json,r.report_sha256,r.signature,a.public_key,a.worker_id FROM recipe_inspection_results r
    JOIN recipe_inspections i ON i.id=r.job_id JOIN recipe_inspection_attempts a ON a.job_id=r.job_id AND a.attempt=r.attempt
    WHERE i.capture_sha256=? AND r.job_id=? AND r.attempt=?`)
    .bind(event.params.digest, event.url.searchParams.get('job') ?? '', Number(event.url.searchParams.get('attempt')) || 0)
    .first<{ report_json: string; report_sha256: string; signature: string; public_key: string; worker_id: string }>();

  if (!evidence) error(404, 'Inspection evidence not found.');

  if (await sha256(evidence.report_json) !== evidence.report_sha256) error(409, 'Inspection evidence checksum changed.');

  return json({ report: evidence.report_json, sha256: evidence.report_sha256, signature: evidence.signature, publicKey: evidence.public_key, workerId: evidence.worker_id },
    { headers: { 'Cache-Control': 'no-store', 'Content-Disposition': 'attachment; filename="recipe-inspection.json"' } });
};

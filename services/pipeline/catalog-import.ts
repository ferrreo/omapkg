import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from 'cloudflare:workers';
import { getSandbox, type Sandbox } from '@cloudflare/sandbox';
import { cloudflareSandbox } from '@flue/runtime/cloudflare';
import captureScript from './capture-catalog.py?raw';
import type { PipelineEnv } from './types';
import type { Env } from '../../src/lib/server/env';
import type { CaptureJob, CapturePayload } from '../../src/lib/server/catalog-capture';
import type { ImportManifest, ImportSource } from '../../src/lib/imports';
import { actorForGithubId } from '../../src/lib/server/auth';
import { humanMaintainer } from '../../src/lib/server/catalog-ownership';
import { beginCatalogImport, appendCatalogImport, sealCatalogImport, parseImportManifest, parseImportEntry } from '../../src/lib/server/catalog-imports';
import { immutableBytes, immutableText } from '../../src/lib/server/release-storage';
import { canonicalJson } from '../../src/lib/canonical-json';
import { audit, now, sha256 } from '../../src/lib/server/db';
import { shellQuote, redactText } from './security';

export class CatalogImportWorkflow extends WorkflowEntrypoint<PipelineEnv, { jobId: string }> {
  async run(event: Readonly<WorkflowEvent<{ jobId: string }>>, step: WorkflowStep) {
    const env = this.env as unknown as Env;
    const job = await env.DB.prepare('SELECT * FROM catalog_import_jobs WHERE id=?').bind(event.payload.jobId).first<CaptureJob>();
    if (!job) throw new Error('Capture job not found');
    if (job.status === 'captured') return { importId: job.import_id };
    try {
      const actor = humanMaintainer(await actorForGithubId(env.DB, job.created_by.replace(/^github:/, '')), 'system');
      const payload = JSON.parse(job.payload_json) as CapturePayload;
      if (!this.env.Sandbox) throw new Error('Capture Sandbox binding is unavailable');
      const base = `/workspace/import-${job.id}`;
      const prefix = `imports/jobs/${job.id}`;
      const arguments_ = ['--source', payload.kind, '--channel', payload.channel, '--arch', 'all', '--opr-layout', payload.oprLayout,
        ...(payload.oprOrigin ? ['--opr-origin', payload.oprOrigin] : [])];
      const stub = getSandbox(this.env.Sandbox as DurableObjectNamespace<Sandbox>, `catalog-${job.id}`, { sleepAfter: '15m' });
      await stub.setAllowedHosts(['geo.mirror.pkgbuild.com', 'fl.us.mirror.archlinuxarm.org', 'stable-mirror.omarchy.org', 'rc-mirror.omarchy.org', 'mirror.omarchy.org', 'pkgs.omarchy.org',
        ...(payload.oprOrigin ? [new URL(payload.oprOrigin).hostname] : [])]);
      const sandbox = await cloudflareSandbox(stub, { cwd: '/workspace' }).createSandbox({ id: `catalog-${job.id}` });
      const run = (args: string[]) => sandbox.exec(`python3 -c ${shellQuote(captureScript)} ${args.map(shellQuote).join(' ')}`, { timeoutMs: 300_000 });
      const read = async (path: string, maximum: number) => {
        const bytes = new Uint8Array(await sandbox.readFileBuffer(path));
        if (bytes.length > maximum) throw new Error('Capture file exceeds its declared budget');
        return bytes;
      };
      const specs = await step.do('source-plan', async () => {
        await env.DB.prepare("UPDATE catalog_import_jobs SET status='capturing',error=NULL,updated_at=? WHERE id=?").bind(now(), job.id).run();
        const result = await run([...arguments_, '--describe']);
        if (result.exitCode !== 0) throw new Error('Capture source plan failed');
        const values = JSON.parse(result.stdout) as Array<{ id: string; url: string }>;
        if (!Array.isArray(values) || !values.length || values.length > 32 || values.some((value) => !/^[a-z0-9][a-z0-9._-]{0,95}$/.test(value.id))) throw new Error('Capture returned an invalid source plan');
        return values;
      });
      const sources: ImportSource[] = [];
      const index: string[][] = [];
      for (const spec of specs) {
        const source = await step.do(`capture-${spec.id}`, { retries: { limit: 2, delay: '15 seconds', backoff: 'exponential' }, timeout: '10 minutes' }, async () => {
          const directory = `${base}/${spec.id}`;
          const result = await run([...arguments_, '--only-source', spec.id, '--output', directory]);
          if (result.exitCode !== 0) throw new Error(`Capture tool failed for ${spec.id}: ${redactText(result.stderr).slice(0, 1000)}`);
          const manifest = parseImportManifest(JSON.parse(new TextDecoder().decode(await read(`${directory}/manifest.json`, 256 * 1024))));
          if (manifest.sources.length !== 1 || manifest.sources[0].id !== spec.id) throw new Error('Capture source identity changed');
          const captured = manifest.sources[0];
          await immutableText(env, `${prefix}/${spec.id}/manifest.json`, canonicalJson(manifest), 'application/json');
          const sourceIndex = await read(`${directory}/index.json`, 16 * 1024 * 1024);
          await immutableBytes(env, `${prefix}/${spec.id}/index.json`, sourceIndex, await sha256(sourceIndex), 'application/json');
          for (let page = 0; page < Math.ceil(captured.entries / 100); page++) {
            const filename = `entries-${String(page).padStart(5, '0')}.json`;
            const bytes = await read(`${directory}/${filename}`, 1024 * 1024);
            await immutableBytes(env, `${prefix}/${spec.id}/${filename}`, bytes, await sha256(bytes), 'application/json');
            if (captured.format === 'recipe-catalog') for (const value of JSON.parse(new TextDecoder().decode(bytes))) {
              const entry = parseImportEntry(value, manifest);
              const recipe = await read(`${directory}/recipe-${entry.sha256}.PKGBUILD`, 2 * 1024 * 1024);
              if (await sha256(recipe) !== entry.sha256) throw new Error('Captured public recipe digest changed');
              await immutableBytes(env, `imports/recipes/${entry.sha256}/PKGBUILD`, recipe, entry.sha256, 'text/plain; charset=utf-8');
            }
          }
          if (captured.sha256) {
            const database = await read(`${directory}/${spec.id}.db`, 32 * 1024 * 1024);
            if (await sha256(database) !== captured.sha256) throw new Error('Captured database digest changed');
            await immutableBytes(env, `imports/archives/${captured.sha256}.db`, database, captured.sha256, 'application/octet-stream');
          }
          if (captured.signatureSha256) {
            const signature = await read(`${directory}/${spec.id}.db.sig`, 1024 * 1024);
            if (await sha256(signature) !== captured.signatureSha256) throw new Error('Captured signature digest changed');
            await immutableBytes(env, `imports/archives/${captured.signatureSha256}.sig`, signature, captured.signatureSha256, 'application/octet-stream');
          }
          return captured;
        });
        sources.push(source);
        const sourceIndex = await env.ARTIFACTS.get(`${prefix}/${spec.id}/index.json`);
        if (!sourceIndex) throw new Error('Captured source index is missing');
        index.push(...JSON.parse(await sourceIndex.text()) as string[][]);
        await env.DB.prepare('UPDATE catalog_import_jobs SET progress_json=?,updated_at=? WHERE id=?').bind(canonicalJson(sources), now(), job.id).run();
      }
      index.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0);
      const manifest: ImportManifest = { schemaVersion: 1, kind: payload.kind, channel: payload.channel, sources, entriesSha256: await sha256(canonicalJson(index)) };
      const { importId, status: captureStatus } = await step.do('begin-upload', async () => {
        const result = await beginCatalogImport(env.DB, actor, manifest);
        await env.DB.prepare("UPDATE catalog_import_jobs SET status='uploading',import_id=?,updated_at=? WHERE id=?").bind(result.importId, now(), job.id).run();
        return result;
      });
      if (captureStatus === 'capturing') for (const source of sources) for (let page = 0; page < Math.ceil(source.entries / 100); page++) {
        await step.do(`upload-${source.id}-${page}`, async () => {
          const file = await env.ARTIFACTS.get(`${prefix}/${source.id}/entries-${String(page).padStart(5, '0')}.json`);
          if (!file) throw new Error('Captured import chunk is missing');
          return appendCatalogImport(env.DB, actor, importId, JSON.parse(await file.text()));
        });
      }
      return await step.do('seal-capture', async () => {
        await sealCatalogImport(env.DB, actor, importId);
        await env.DB.batch([
          env.DB.prepare("UPDATE catalog_import_jobs SET status='captured',import_id=?,updated_at=? WHERE id=?").bind(importId, now(), job.id),
          audit(env.DB, job.created_by, 'catalog.capture_completed', job.id, { importId, unavailableSources: sources.filter((source) => source.status === 'unavailable').length }),
        ]);
        return { importId };
      });
    } catch (cause) {
      await env.DB.prepare("UPDATE catalog_import_jobs SET status='failed',error=?,updated_at=? WHERE id=? AND status<>'captured'")
        .bind(redactText(cause instanceof Error ? cause.message : 'Capture failed').slice(0, 2000), now(), job.id).run();
      throw cause;
    }
  }
}

export async function catalogImportEndpoint(request: Request, env: PipelineEnv) {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
  if (!env.CATALOG_IMPORT) return Response.json({ error: 'Catalog import workflow is not configured' }, { status: 503 });
  const body = await request.json() as { jobId?: string };
  if (!body.jobId || !/^[a-f0-9-]{36}$/.test(body.jobId) || !await env.DB.prepare("SELECT 1 FROM catalog_import_jobs WHERE id=? AND status='queued'").bind(body.jobId).first()) {
    return Response.json({ error: 'A queued import job is required' }, { status: 400 });
  }
  try { await env.CATALOG_IMPORT.create({ id: `import-${body.jobId}`, params: { jobId: body.jobId } }); }
  catch {
    try {
      const status = await (await env.CATALOG_IMPORT.get(`import-${body.jobId}`)).status();
      if (!['errored', 'terminated'].includes(status.status)) return Response.json({ jobId: body.jobId, deduplicated: true }, { status: 202 });
    } catch { /* preserve the dispatch failure without exposing platform details */ }
    return Response.json({ error: 'Import workflow dispatch failed' }, { status: 503 });
  }
  return Response.json({ jobId: body.jobId }, { status: 202 });
}

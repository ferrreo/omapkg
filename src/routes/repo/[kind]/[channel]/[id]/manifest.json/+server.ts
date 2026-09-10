import { error, type RequestHandler } from '@sveltejs/kit';
import { distributionManifestObject } from '$lib/server/distribution-releases';

function resolve(kind: string, channel: string): { manifestKind: 'system' | 'opr' | 'resolved-transaction'; channel: 'edge' | 'rc' | 'stable' | 'quarantine' } | null {
  if (kind === 'releases' && ['edge', 'rc', 'stable'].includes(channel)) return { manifestKind: 'system', channel: channel as 'edge' | 'rc' | 'stable' };
  if (kind === 'opr' && ['quarantine', 'stable'].includes(channel)) return { manifestKind: 'opr', channel: channel as 'quarantine' | 'stable' };
  if (kind === 'transactions' && ['edge', 'rc', 'stable'].includes(channel)) return { manifestKind: 'resolved-transaction', channel: channel as 'edge' | 'rc' | 'stable' };
  return null;
}

export const GET: RequestHandler = async ({ platform, params }) => {
  if (!platform?.env?.DB || !platform.env.ARTIFACTS) error(503, 'Repository is unavailable.');
  const resolved = resolve(params.kind ?? '', params.channel ?? '');
  if (!resolved) error(404, 'Manifest not found.');
  const response = await distributionManifestObject(platform.env, params.id ?? '', resolved.manifestKind, false, resolved.channel);
  if (!response) error(404, 'Manifest not found.');
  return response;
};

export const HEAD = GET;

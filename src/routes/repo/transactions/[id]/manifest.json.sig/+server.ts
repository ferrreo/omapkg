import { error, type RequestHandler } from '@sveltejs/kit';
import { distributionManifestObject } from '$lib/server/distribution-releases';

export const GET: RequestHandler = async ({ platform, params }) => {
  if (!platform?.env?.DB || !platform.env.ARTIFACTS) error(503, 'Repository is unavailable.');
  const response = await distributionManifestObject(platform.env, params.id ?? '', 'resolved-transaction', true);
  if (!response) error(404, 'Resolved transaction signature not found.');
  return response;
};

export const HEAD = GET;

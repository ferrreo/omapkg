import { error, type RequestHandler } from '@sveltejs/kit';
import { currentDistributionManifestObject } from '$lib/server/distribution-releases';

export const GET: RequestHandler = async ({ platform }) => {
  if (!platform?.env?.DB || !platform.env.ARTIFACTS) error(503, 'Repository is unavailable.');
  const response = await currentDistributionManifestObject(platform.env);
  if (!response) error(404, 'No current resolved transaction manifest is published.');
  return response;
};

export const HEAD = GET;

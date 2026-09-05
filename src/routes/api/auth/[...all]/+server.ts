import { error } from '@sveltejs/kit';
import { createAuth, authReady } from '$lib/server/auth';
import type { RequestHandler } from './$types';

const handler: RequestHandler = ({ request, platform }) => {
  if (!platform?.env || !authReady(platform.env)) error(503, 'GitHub sign-in is being configured.');
  return createAuth(platform.env).handler(request);
};
export const GET = handler;
export const POST = handler;

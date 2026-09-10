import { environment, maintainer } from '$lib/server/http';
import { recipeSourcePlan } from '$lib/server/recipe-source-plans';
import { canonicalJson } from '$lib/canonical-json';
import type { RequestHandler } from './$types';
import { PolicyError } from '$lib/server/policy';
import { error } from '@sveltejs/kit';

export const GET: RequestHandler = async (event) => {
  maintainer(event);
  const plan = await recipeSourcePlan(environment(event), event.params.digest, event.url.searchParams.get('job') ?? '', Number(event.url.searchParams.get('attempt')) || 0)
    .catch((cause) => { if (cause instanceof PolicyError) error(cause.status, cause.message); throw cause; });
  return new Response(canonicalJson(plan), { headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store',
    'Content-Disposition': `attachment; filename="${plan.pkgbase}-${plan.architecture}-sources.json"` } });
};

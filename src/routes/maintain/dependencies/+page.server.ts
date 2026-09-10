import { listDependencyProposals, parseDependencyProposal } from '$lib/server/dependency-proposals';
import { environment, maintainer } from '$lib/server/http';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  maintainer(event);
  const status = event.url.searchParams.get('status') ?? 'proposed';
  const after = (event.url.searchParams.get('after') ?? '').slice(0, 128);
  const proposals = await listDependencyProposals(environment(event).DB, { status, after });

  return { proposals: proposals.map((proposal) => ({ ...proposal, manifest: parseDependencyProposal(JSON.parse(proposal.manifest_json)) })), status, after };
};

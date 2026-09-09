import { redirect } from '@sveltejs/kit';
import { decideDependencyProposal, getDependencyProposal, reviseDependencyProposal } from '$lib/server/dependency-proposals';
import { environment, field, formAction, maintainer } from '$lib/server/http';
import { query } from '$lib/server/db';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const actor = maintainer(event); const { DB } = environment(event);
  const detail = await getDependencyProposal(DB, event.params.id);
  const search = (event.url.searchParams.get('q') ?? detail.manifest.name).slice(0, 100);
  const pattern = `%${search.replace(/[\\%_]/g, '\\$&')}%`;
  return { ...detail, actor, search,
    matches: await query<{ id: string; name: string; status: string; upstream_url: string; area: string }>(DB,
      "SELECT id,name,status,upstream_url,area FROM requests WHERE status<>'rejected' AND name LIKE ? ESCAPE '\\' ORDER BY name,created_at DESC LIMIT 30", pattern),
    history: await query<{ id: string; revision: number; status: string; decision_reason: string | null }>(DB,
      'SELECT id,revision,status,decision_reason FROM dependency_proposals WHERE proposal_key=? ORDER BY revision DESC LIMIT 50', detail.proposal.proposal_key),
  };
};
export const actions: Actions = {
  revise: (event) => formAction(event, async (form) => {
    const { manifest } = await getDependencyProposal(environment(event).DB, event.params.id);
    const upstreamUrl = field(form, 'upstreamUrl').trim() || null;
    const result = await reviseDependencyProposal(environment(event).DB, event.locals.actor, event.params.id, field(form, 'digest'), {
      ...manifest, name: field(form, 'name'), upstreamUrl, sourceKind: upstreamUrl ? field(form, 'sourceKind') : null,
      license: field(form, 'license'), origin: field(form, 'origin'), referenceUrl: field(form, 'referenceUrl').trim() || null,
      targetPkgbase: field(form, 'targetPkgbase').trim() || null,
    }, field(form, 'reason'));
    redirect(303, `/maintain/dependencies/${result.proposalId}`);
  }),
  admit: (event) => formAction(event, async (form) => decideDependencyProposal(environment(event).DB, event.locals.actor, event.params.id,
    field(form, 'digest'), 'admit', field(form, 'reason'), field(form, 'existingRequestId') || undefined)),
  decline: (event) => formAction(event, async (form) => decideDependencyProposal(environment(event).DB, event.locals.actor, event.params.id,
    field(form, 'digest'), 'decline', field(form, 'reason'))),
};

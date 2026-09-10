import { error } from '@sveltejs/kit';
import type { Architecture } from '$lib/model';
import type { DistributionReleaseChannel } from '$lib/distribution-release';
import { getDistributionReleaseView } from '$lib/server/release-workbench';
import { environment } from '$lib/server/http';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => {
  const kind = event.params.kind;
  if (kind !== 'system' && kind !== 'opr' && kind !== 'resolved-transaction') error(404, 'Release record not found.');
  const requestedArchitecture = event.url.searchParams.get('architecture');
  if (requestedArchitecture && requestedArchitecture !== 'x86_64' && requestedArchitecture !== 'aarch64') error(400, 'Architecture must be x86_64 or aarch64.');
  const channel = event.url.searchParams.get('channel') ?? 'stable';
  if (channel !== 'stable' && (kind === 'opr' ? channel !== 'quarantine' : channel !== 'edge' && channel !== 'rc')) error(400, 'Release channel is invalid.');
  const view = await getDistributionReleaseView(environment(event), kind, event.params.id, (requestedArchitecture || null) as Architecture | null, channel as DistributionReleaseChannel);
  if (!view) error(404, 'Published release record not found.');
  return { view, architecture: requestedArchitecture ?? '' };
};

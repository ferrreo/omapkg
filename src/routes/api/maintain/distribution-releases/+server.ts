import { json, type RequestHandler } from '@sveltejs/kit';
import { approveDistributionRelease, activateDistributionRelease, getActiveDistributionRelease, prepareDistributionRelease, renewResolvedTransaction, signDistributionRelease, type DistributionApprovalInput, type DistributionCandidateInput } from '$lib/server/distribution-releases';
import { ownedRepositoryReleaseRepositories, prepareOwnedRepositorySnapshots, type OwnedRepositoryPrepareInput } from '$lib/server/owned-repository';
import { environment, jsonBody, sameOrigin } from '$lib/server/http';
import { humanMaintainer } from '$lib/server/catalog-ownership';
import { PolicyError } from '$lib/server/policy';

const headers = { 'Cache-Control': 'private, no-store' };

export const GET: RequestHandler = async (event) => {
  try {
    humanMaintainer(event.locals.actor);
    const env = environment(event);
    const candidateId = event.url.searchParams.get('candidateId');
    if (candidateId) {
      const channel = event.url.searchParams.get('channel') as 'edge' | 'rc' | 'stable' | 'quarantine' | null;
      if (channel && !['edge', 'rc', 'stable', 'quarantine'].includes(channel)) throw new PolicyError(400, 'Release channel is invalid.');
      if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(candidateId)) throw new PolicyError(400, 'Candidate ID is invalid.');
      const candidate = await env.DB.prepare('SELECT * FROM distribution_release_candidates WHERE id=?').bind(candidateId)
        .first<{ manifest_json: string; channel: string; signature_key: string | null; signature_sha256: string | null }>();
      if (!candidate || (channel && candidate.channel !== channel)) throw new PolicyError(404, 'Distribution release candidate not found.');
      return json({ candidate, manifest: JSON.parse(candidate.manifest_json), signatureKey: candidate.signature_key, signatureSha256: candidate.signature_sha256 }, { headers });
    }
    const lane = event.url.searchParams.get('lane');
    if (lane !== 'system' && lane !== 'opr' && lane !== 'transaction') throw new PolicyError(400, 'Choose a release lane.');
    const channel = event.url.searchParams.get('channel') as 'edge' | 'rc' | 'stable' | 'quarantine' | null;
    if (channel && !['edge', 'rc', 'stable', 'quarantine'].includes(channel)) throw new PolicyError(400, 'Release channel is invalid.');
    return json(await getActiveDistributionRelease(env.DB, lane, channel ?? 'stable'), { headers });
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};

export const POST: RequestHandler = async (event) => {
  try {
    sameOrigin(event.request, event.url.origin);
    humanMaintainer(event.locals.actor);
    const input = await jsonBody(event.request, 4 * 1024 * 1024) as Record<string, unknown>;
    if (!input || typeof input.operation !== 'string') throw new PolicyError(400, 'Choose a distribution release operation.');
    const env = environment(event);
    if (input.operation === 'prepare-repositories') {
      const candidate = input.repository as Partial<OwnedRepositoryPrepareInput> | undefined;
      if (!candidate || (candidate.lane !== 'system' && candidate.lane !== 'opr')) throw new PolicyError(400, 'Choose a repository lane.');
      humanMaintainer(event.locals.actor, candidate.lane === 'system' ? 'system' : undefined);
      const preparation = await prepareOwnedRepositorySnapshots(env, {
        lane: candidate.lane,
        releaseId: String(candidate.releaseId ?? ''),
        cohortIds: Array.isArray(candidate.cohortIds) ? candidate.cohortIds.map(String) : [],
        trustedParentReleaseId: candidate.trustedParentReleaseId == null ? null : String(candidate.trustedParentReleaseId),
      });
      return json({ preparation, repositories: ownedRepositoryReleaseRepositories(preparation) }, { headers });
    }
    if (input.operation === 'prepare') return json(await prepareDistributionRelease(env, event.locals.actor, input.candidate as DistributionCandidateInput), { headers });
    if (input.operation === 'approve') return json(await approveDistributionRelease(env.DB, event.locals.actor, input.approval as DistributionApprovalInput), { headers });
    if (input.operation === 'sign') {
      if (typeof input.candidateId !== 'string') throw new PolicyError(400, 'Choose a release candidate.');
      return json(await signDistributionRelease(env, event.locals.actor, input.candidateId), { headers });
    }
    if (input.operation === 'activate') {
      if (typeof input.candidateId !== 'string') throw new PolicyError(400, 'Choose a release candidate.');
      const parent = input.expectedParent;
      if (parent !== undefined && (!parent || typeof parent !== 'object' || Array.isArray(parent))) throw new PolicyError(400, 'Expected activation parent is invalid.');
      return json(await activateDistributionRelease(env, event.locals.actor, input.candidateId, parent as { digest: string | null; sequence: number | null } | undefined), { headers });
    }
    if (input.operation === 'renew') {
      const parent = input.expectedParent;
      if (parent !== undefined && (!parent || typeof parent !== 'object' || Array.isArray(parent))) throw new PolicyError(400, 'Expected renewal parent is invalid.');
      const channel = input.channel === undefined ? 'stable' : input.channel;
      if (channel !== 'edge' && channel !== 'rc' && channel !== 'stable') throw new PolicyError(400, 'Choose a system release channel.');
      return json(await renewResolvedTransaction(env, event.locals.actor, channel, parent as { digest: string | null; sequence: number | null } | undefined), { headers });
    }
    throw new PolicyError(400, 'Unknown distribution release operation.');
  } catch (cause) {
    if (cause instanceof PolicyError) return json({ error: cause.message }, { status: cause.status, headers });
    throw cause;
  }
};

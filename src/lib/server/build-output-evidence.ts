import type { Worker } from '../model';
import { assertOutputEvidence } from './output-evidence';
import { archRelationCovers } from './arch';
import { storedOutputContract } from './build-outputs';
import { parseDependencyPlan, dependencyPlansEqual } from './dependency-plan';
import { reviewedRuntimeExceptions } from './runtime-evidence';
import { WorkerProtocolError, decodeBase64, parseSources, parseStringArray, sameJson, verifyEd25519, workerImage,
  type ArtifactReference, type WorkerLease } from './worker-protocol';

export async function verifyOutputProvenance(worker: Pick<Worker, 'id' | 'public_key' | 'architecture'>, build: WorkerLease,
  artifacts: ArtifactReference[], provenance: string, signature: string, installedSize: number | undefined): Promise<void> {
  const contract = storedOutputContract(build);
  if (!contract || worker.architecture !== build.architecture) throw new WorkerProtocolError(409, 'Native output contract is required');
  let report;
  try { report = await assertOutputEvidence(JSON.parse(provenance), reviewedRuntimeExceptions(build.revision_sbom_json)); }
  catch (cause) { throw new WorkerProtocolError(409, cause instanceof Error ? cause.message : 'Invalid output evidence'); }
  const { imageDigest } = workerImage(build);
  if ((report.frozenInputs?.lock.sha256 ?? null) !== (build.input_lock_sha256 ?? null)) throw new WorkerProtocolError(409, 'Frozen input lock differs from lease');
  if (report.schemaVersion !== 2 || report.attempt !== build.attempt || !sameJson(report.outputContract, contract) || report.buildId !== build.id ||
      report.revisionId !== build.revision_id || report.workerId !== worker.id || report.recipeSha256 !== build.revision_recipe_sha256 ||
      report.architecture !== build.architecture || report.imageDigest !== imageDigest || report.network !== 'disabled' ||
      report.sourceDateEpoch !== build.revision_source_date_epoch || !sameJson(report.sources, parseSources(build.revision_sources_json))) {
    throw new WorkerProtocolError(409, 'V2 provenance does not match leased inputs');
  }
  const expectedPlan = build.dependency_plan_json ? parseDependencyPlan(JSON.parse(build.dependency_plan_json)) : null;
  const actualPlan = report.dependencyPlan ? parseDependencyPlan(report.dependencyPlan) : null;
  if ((build.dependency_plan_json && !expectedPlan) || (report.dependencyPlan && !actualPlan) || !dependencyPlansEqual(expectedPlan, actualPlan)) {
    throw new WorkerProtocolError(409, 'V2 dependency plan differs from lease');
  }
  if (!Array.isArray(report.outputs) || report.outputs.length !== contract.outputs.length || artifacts.length !== contract.outputs.length) {
    throw new WorkerProtocolError(409, 'Build output set is incomplete');
  }
  let total = 0;
  const relations: string[] = [];
  for (const output of report.outputs) {
    const artifact = artifacts.find((item) => item.filename === output.filename);
    if (output.pkgbase !== build.revision_name || !artifact || artifact.sha256 !== output.artifactSha256) {
      throw new WorkerProtocolError(409, 'Package output differs from reviewed identity or uploaded bytes');
    }
    total += output.packageMetadata.installedSize;
    relations.push(...output.packageMetadata.depends);
  }
  if (!Number.isSafeInteger(total) || total !== installedSize) throw new WorkerProtocolError(409, 'Output installed size does not match completion');
  if (parseStringArray(build.revision_dependencies_json, 'dependencies', 256).some((reviewed) => !relations.some((native) => archRelationCovers(native, reviewed)))) {
    throw new WorkerProtocolError(409, 'Output metadata omits reviewed runtime dependencies');
  }
  if (!await verifyEd25519(decodeBase64(worker.public_key, 'worker public key'), new TextEncoder().encode(provenance), decodeBase64(signature, 'provenance signature'))) {
    throw new WorkerProtocolError(401, 'Invalid v2 provenance signature');
  }
}

import { expect, test } from 'bun:test';
import { sha256 } from '../src/lib/server/db';
import { assertRuntimeEvidence } from '../src/lib/server/runtime-evidence';
import { runtimeEvidence } from './runtime-fixtures';

const digest = `sha256:${'a'.repeat(64)}`;

test('runtime evidence requires distinct exact environments and cannot waive errors or alter findings', async () => {
  const valid = runtimeEvidence(digest);
  await assertRuntimeEvidence(valid, digest, []);
  await expect(assertRuntimeEvidence({ ...valid, runtimeEnvironment: valid.buildEnvironment }, digest, [])).rejects.toThrow('separate');
  await expect(assertRuntimeEvidence({ ...valid, runtimeAnalysis: { ...valid.runtimeAnalysis, runtimeClosureComplete: true } }, digest, [])).rejects.toThrow('coverage');
  const finding = { code: 'library-no-package-associated', level: 'warning', detail: 'plugin resolves its bundled library', sha256: '' };
  finding.sha256 = await sha256(`${finding.level}\n${finding.code}\n${finding.detail}`);
  const exception = { findingSha256: finding.sha256, reason: 'Reviewed bundled plugin lookup' };
  const evidence = { ...valid, runtimeAnalysis: { ...valid.runtimeAnalysis, findings: [finding], exceptions: [exception] } };
  await expect(assertRuntimeEvidence(evidence, digest, [])).rejects.toThrow('reviewed exceptions');
  await assertRuntimeEvidence(evidence, digest, [exception]);
  finding.detail += ' changed';
  await expect(assertRuntimeEvidence(evidence, digest, [exception])).rejects.toThrow('integrity');
  finding.level = 'error';
  finding.sha256 = await sha256(`${finding.level}\n${finding.code}\n${finding.detail}`);
  exception.findingSha256 = finding.sha256;
  await expect(assertRuntimeEvidence(evidence, digest, [exception])).rejects.toThrow('Unresolved');
});

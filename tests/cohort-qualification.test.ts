import { expect, test } from 'bun:test';
import { readFileSync, readdirSync } from 'node:fs';
import type { AbiChunk, AbiInventory, AbiRecord, AbiSymbol } from '../src/lib/abi-inventory';
import { canonicalJson } from '../src/lib/canonical-json';
import { finalProviderInputFindings, indexRetainedQualificationAbi, persistQualificationAbiRecords, qualificationBuildOutputs, qualificationIndexedAbiFindings, qualifyCandidateUniverse, qualifyCohort, storeQualificationRun, type QualificationBuild, type QualificationPackage } from '../src/lib/server/cohort-qualification';
import { sha256 } from '../src/lib/server/db';
import { asD1, TestD1 } from './d1';
import type { Env } from '../src/lib/server/env';
import { MemoryR2 } from './release-fixtures';

const schema = readdirSync(new URL('../migrations', import.meta.url)).filter((name) => name.endsWith('.sql')).sort()
  .map((name) => readFileSync(new URL(`../migrations/${name}`, import.meta.url), 'utf8')).join('\n');

const metadata = (name: string, depends: string[] = [], provides: string[] = []) => ({
  name, fullVersion: '1.0-1', installedSize: 1, depends, provides, conflicts: [], replaces: [],
});

function libraryAbi(artifactSha256: string): QualificationPackage['abi'] {
  const records: AbiRecord[] = [
    { kind: 'file', path: 'usr/lib/libdemo.so.1', sha256: artifactSha256, type: '0', mode: 0o644, link: '', nativeKind: 'elf',
      elf: { machine: 'EM_X86_64', type: 'ET_DYN', bits: 64, byteOrder: 'little', soname: 'libdemo.so.1', needed: [], rpath: [], runpath: [], interpreter: null, debugInfo: 'absent', dynamicSymbols: 'present' } },
    { kind: 'symbol', path: 'usr/lib/libdemo.so.1', table: '.dynsym', dynamic: true, index: 1, name: 'demo', defined: true,
      binding: 'GLOBAL', type: 'FUNC', visibility: 'DEFAULT', size: 4, version: null, versionFile: null, versionHidden: false },
  ];

  return { artifactSha256, typeAbi: 'not-checked', records };
}

function pkg(name: string, origin: QualificationPackage['origin'], artifactSha256: string, depends: string[] = [], abi: QualificationPackage['abi'] = null, provides: string[] = []): QualificationPackage {
  return { pkgbase: name, name, fullVersion: '1.0-1', architecture: 'x86_64', artifactSha256, artifactSize: 1,
    metadata: metadata(name, depends, provides), abi, origin, rebuildOn: [], buildId: null, attempt: null };
}

test('candidate qualification resolves dependencies across the complete owned universe', () => {
  const report = qualifyCandidateUniverse({ cohortId: 'c', revision: 1, manifestSha256: 'a'.repeat(64), architecture: 'x86_64', candidate: [pkg('app', 'candidate', 'b'.repeat(64), ['missing'])] });
  expect(report.findings).toContainEqual(expect.objectContaining({ kind: 'dependency', code: 'unresolved-dependency', pkgbase: 'app', architecture: 'x86_64' }));
  expect(report.universeSha256).toMatch(/^[a-f0-9]{64}$/);
});

test('v2 qualification reads registered output rows when aggregate build artifact fields are null', async () => {
  const db = new TestD1('CREATE TABLE build_artifacts(build_id TEXT,attempt INTEGER,filename TEXT,artifact_key TEXT,sha256 TEXT,size INTEGER);');
  const artifact = 'b'.repeat(64);

 const provenance = JSON.stringify({ outputs: [{ pkgbase: 'demo', filename: 'demo-1.0-1-x86_64.pkg.tar.zst', artifactSha256: artifact,
    packageMetadata: { name: 'demo', fullVersion: '1.0-1', architecture: 'x86_64', installedSize: 1, depends: [], provides: [], conflicts: [], replaces: [] } }] });

  db.prepare('INSERT INTO build_artifacts VALUES(?,?,?,?,?,?)').bind('build-v2', 1, 'demo-1.0-1-x86_64.pkg.tar.zst', 'objects/demo', artifact, 1).run();

  const outputs = await qualificationBuildOutputs({ DB: db as unknown as D1Database, ARTIFACTS: new MemoryR2() as unknown as R2Bucket }, {
    id: 'build-v2', revision_id: 'revision', architecture: 'x86_64', status: 'succeeded', attempt: 1, artifact_sha256: null, artifact_size: null,
    artifact_filename: null, installed_size: 1, provenance, provenance_signature: 'sig', input_lock_sha256: null, worker_id: 'worker', output_contract_json: '{}', pkgbase: 'demo', rebuild_on: '[]', surface: 'binary', worker_status: 'active',
  } satisfies QualificationBuild);

  expect(outputs).toHaveLength(1); expect(outputs[0].artifactSha256).toBe(artifact);
  db.close();
});

test('retained ABI index streams more than one million dynamic records without a heap-sized aggregate', async () => {
  const indexSchema = readFileSync('migrations/0051_cohort_qualification_abi_index.sql', 'utf8'); const holder = new TestD1(indexSchema); const db = asD1(holder);
  const total = 1_000_064; const chunkSize = 4096; const context = { cohortId: 'index-cohort', revision: 1, architecture: 'x86_64' as const };

  const record = (index: number): AbiSymbol => ({ kind: 'symbol', path: `usr/lib/lib${index}.so`, table: '.dynsym', dynamic: true, index: 1, name: `symbol_${index}`, defined: index % 2 === 0,
    binding: 'STB_GLOBAL', type: 'STT_FUNC', visibility: 'STV_DEFAULT', size: 0, version: null, versionFile: null, versionHidden: false });

  for (let start = 0; start < total; start += chunkSize) await persistQualificationAbiRecords(db, context, 'a'.repeat(64), 'b'.repeat(64), start, Array.from({ length: Math.min(chunkSize, total - start) }, (_, offset) => record(start + offset)));
  expect((await db.prepare('SELECT COUNT(*) AS count FROM cohort_qualification_abi_records').first<{ count: number }>())?.count).toBe(total);
  expect((await db.prepare('SELECT record_kind FROM cohort_qualification_abi_records WHERE ordinal=0').first<{ record_kind: string }>())?.record_kind).toBe('symbol');
  holder.close();
}, 180000);

test('qualification ABI index ingests and then reuses real retained ABI chunks', async () => {
  const holder = new TestD1(`CREATE TABLE build_attempts(build_id TEXT,attempt INTEGER,PRIMARY KEY(build_id,attempt));\n${readFileSync('migrations/0045_build_abi_evidence.sql', 'utf8')}\n${readFileSync('migrations/0051_cohort_qualification_abi_index.sql', 'utf8')}`); const db = asD1(holder); const artifacts = new MemoryR2();
  const artifactSha256 = 'a'.repeat(64);

 const chunk: AbiChunk = { schemaVersion: 1, kind: 'abi-records', artifactSha256, start: 0, records: [
    { kind: 'file', path: 'usr/bin/demo', sha256: artifactSha256, type: '0', mode: 0o755, link: '', nativeKind: 'other', elf: null },
    { kind: 'symbol', path: 'usr/bin/demo', table: '.dynsym', dynamic: true, index: 1, name: 'demo', defined: false, binding: 'STB_GLOBAL', type: 'STT_FUNC', visibility: 'STV_DEFAULT', size: 0, version: 'DEMO_1', versionFile: 'libdemo.so.1', versionHidden: false },
  ] };

  const chunkBytes = new TextEncoder().encode(canonicalJson(chunk)); const chunkSha256 = await sha256(chunkBytes); artifacts.objects.set(`private/abi/${chunkSha256}.json`, chunkBytes);

  const manifest: AbiInventory = { schemaVersion: 1, kind: 'abi-inventory', artifactSha256, tool: 'go-debug-elf', toolVersion: 'go1.26.0', files: 1, symbols: 1,
    chunks: [{ sha256: chunkSha256, size: chunkBytes.byteLength, start: 0, count: 2, files: 1, symbols: 1 }], typeAbi: 'not-checked' };

  const manifestBytes = new TextEncoder().encode(canonicalJson(manifest)); const manifestSha256 = await sha256(manifestBytes); artifacts.objects.set(`private/abi/${manifestSha256}.json`, manifestBytes);
  db.prepare("INSERT INTO build_attempts VALUES('build',1)").run();
  db.prepare(`INSERT INTO build_abi_evidence(build_id,attempt,sha256,size,artifact_sha256,kind,start,files,symbols,manifest_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,1),(?,?,?,?,?,?,?,?,?,?,1)`).bind(
    'build', 1, chunkSha256, chunkBytes.byteLength, artifactSha256, 'abi-records', 0, 1, 1, null,
    'build', 1, manifestSha256, manifestBytes.byteLength, artifactSha256, 'abi-inventory', 0, 0, 1, canonicalJson(manifest)).run();
  const env = { DB: db, ARTIFACTS: artifacts as unknown as R2Bucket } as unknown as Env; const ref = { sha256: manifestSha256, size: manifestBytes.byteLength };
  const first = await indexRetainedQualificationAbi(env, ref, artifactSha256, { id: 'build', attempt: 1 }, { cohortId: 'c', revision: 1, architecture: 'x86_64' });
  expect(first?.records).toHaveLength(1); expect((await db.prepare('SELECT COUNT(*) AS count FROM cohort_qualification_abi_records').first<{ count: number }>())?.count).toBe(1);
  const second = await indexRetainedQualificationAbi(env, ref, artifactSha256, { id: 'build', attempt: 1 }, { cohortId: 'c', revision: 1, architecture: 'x86_64' });
  expect(second?.records).toEqual([]); expect((await db.prepare('SELECT COUNT(*) AS count FROM cohort_qualification_abi_records').first<{ count: number }>())?.count).toBe(1);
  holder.close();
});

test('indexed ABI qualifier handles a single provider with more than 32,768 symbols', async () => {
  const holder = new TestD1(readFileSync('migrations/0051_cohort_qualification_abi_index.sql', 'utf8')); const db = asD1(holder); const context = { cohortId: 'large', revision: 1, architecture: 'x86_64' as const };
  const provider = pkg('liblarge', 'candidate', 'p'.repeat(64), [], null, ['lib:liblarge.so.1']); const consumer = pkg('large-app', 'candidate', 'c'.repeat(64), ['lib:liblarge.so.1'], null);
  const records: AbiRecord[] = [{ kind: 'file', path: 'usr/lib/liblarge.so.1', sha256: provider.artifactSha256, type: '0', mode: 0o644, link: '', nativeKind: 'elf', elf: { machine: 'EM_X86_64', type: 'ET_DYN', bits: 64, byteOrder: 'little', soname: 'liblarge.so.1', needed: [], rpath: [], runpath: [], interpreter: null, debugInfo: 'absent', dynamicSymbols: 'present' } }];

  for (let index = 0; index < 40_000; index++) records.push({ kind: 'symbol', path: 'usr/lib/liblarge.so.1', table: '.dynsym', dynamic: true, index: index + 1, name: index === 1 ? 'export_1' : index === 2 ? 'export_obj' : `export_${index}`, defined: true, binding: 'STB_GLOBAL', type: index === 2 ? 'STT_OBJECT' : 'STT_FUNC', visibility: 'STV_DEFAULT', size: index === 2 ? 8 : 0, version: index === 2 ? 'DEMO_2' : null, versionFile: index === 2 ? 'liblarge.so.1' : null, versionHidden: false });

  for (let offset = 0; offset < records.length; offset += 2048) await persistQualificationAbiRecords(db, context, provider.artifactSha256, 'i'.repeat(64), offset, records.slice(offset, offset + 2048));

  const consumerRecords: AbiRecord[] = [
    { kind: 'symbol', path: 'usr/bin/large-app', table: '.dynsym', dynamic: true, index: 1, name: 'export_1', defined: false, binding: 'STB_GLOBAL', type: 'STT_FUNC', visibility: 'STV_DEFAULT', size: 0, version: null, versionFile: null, versionHidden: false },
    { kind: 'symbol', path: 'usr/bin/large-app', table: '.dynsym', dynamic: true, index: 2, name: 'export_obj', defined: false, binding: 'STB_GLOBAL', type: 'STT_OBJECT', visibility: 'STV_DEFAULT', size: 8, version: 'DEMO_2', versionFile: 'liblarge.so.1', versionHidden: false },
  ];

  await persistQualificationAbiRecords(db, context, consumer.artifactSha256, 'j'.repeat(64), 0, consumerRecords);
  const findings = await qualificationIndexedAbiFindings(db, context, [{ ...provider, abi: { inventorySha256: 'i'.repeat(64), artifactSha256: provider.artifactSha256, typeAbi: 'not-checked', records: [] } }, { ...consumer, abi: { inventorySha256: 'j'.repeat(64), artifactSha256: consumer.artifactSha256, typeAbi: 'not-checked', records: [] } }], [], 'x86_64');
  expect(findings.some((item) => item.code === 'abi-coverage' || item.code === 'imported-symbol-unresolved')).toBe(false);
  holder.close();
}, 120000);

test('ABI matching keeps provider selection versioned, class-aware, and copy-relocation safe', async () => {
  const elf = (path: string, soname: string | null, needed: string[], bits: 32 | 64, machine = 'EM_X86_64'): AbiRecord => ({
    kind: 'file', path, sha256: 'e'.repeat(64), type: '0', mode: 0o755, link: '', nativeKind: 'elf',
    elf: { machine, type: 'ET_DYN', bits, byteOrder: 'little', soname, needed, rpath: [], runpath: [], interpreter: null, debugInfo: 'absent', dynamicSymbols: 'present' },
  });

  const symbol = (path: string, index: number, name: string, defined: boolean, version: string | null = null, versionFile: string | null = null,
    versionHidden = false, type = 'STT_FUNC', size = 0): AbiRecord => ({ kind: 'symbol', path, table: '.dynsym', dynamic: true, index, name, defined,
    binding: 'STB_GLOBAL', type, visibility: 'STV_DEFAULT', size, version, versionFile, versionHidden });

  const withAbi = (name: string, origin: QualificationPackage['origin'], artifactSha256: string, inventorySha256: string, records: AbiRecord[], depends: string[] = [], provides: string[] = []): QualificationPackage =>
    pkg(name, origin, artifactSha256, depends, { artifactSha256, inventorySha256, typeAbi: 'not-checked', records }, provides);

  const pad = (path: string, start: number, count: number): AbiRecord[] => Array.from({ length: count }, (_, offset) => symbol(path, start + offset, `pad_${start + offset}`, true));
  const libcPath = 'usr/lib/libc.so.6'; const appPath = 'usr/lib/libqtapp.so'; const qtPath = 'usr/lib/libQt.so.1';

  const old64Records: AbiRecord[] = [elf(libcPath, 'libc.so.6', [], 64),
    symbol(libcPath, 1, 'malloc', true, 'GLIBC_1'), symbol(libcPath, 2, 'copy_data', true, 'GLIBC_1', null, false, 'STT_OBJECT', 8),
    symbol(libcPath, 3, 'default_api', true, 'GLIBC_1')];

  const new64Records: AbiRecord[] = [elf(libcPath, 'libc.so.6', [], 64), symbol(libcPath, 3, 'default_api', true, 'GLIBC_1', null, true)];

  const old32Records: AbiRecord[] = [elf('usr/lib32/libc.so.6', 'libc.so.6', [], 32, 'EM_386'),
    symbol('usr/lib32/libc.so.6', 1, 'malloc', true, 'GLIBC_1'), symbol('usr/lib32/libc.so.6', 2, 'copy_data', true, 'GLIBC_1', null, false, 'STT_OBJECT', 8),
  ];

  const new32Records: AbiRecord[] = [elf('usr/lib32/libc.so.6', 'libc.so.6', [], 32, 'EM_386')];
  const old32IndexedRecords = [...old32Records, ...pad('usr/lib32/libc.so.6', 3, 32_768)];
  const new32IndexedRecords = [new32Records[0]!, ...pad('usr/lib32/libc.so.6', 2, 32_768)];
  const oldQtRecords: AbiRecord[] = [elf(qtPath, 'libQt.so.1', [], 64), symbol(qtPath, 1, 'qt_api', true, 'QT_1', null, false)];
  const newQtRecords: AbiRecord[] = [elf(qtPath, 'libQt.so.1', [], 64), symbol(qtPath, 1, 'qt_api', true, 'QT_1', null, true)];

  const appRecords: AbiRecord[] = [elf(appPath, null, ['libc.so.6', 'libQt.so.1'], 64),
    symbol(appPath, 1, 'malloc', false, 'GLIBC_1', 'libc.so.6'), symbol(appPath, 2, 'copy_data', true, 'GLIBC_1', 'libc.so.6', false, 'STT_OBJECT', 8),
    symbol(appPath, 3, 'default_api', false), symbol(appPath, 4, 'qt_api', false, 'QT_1', 'libQt.so.1')];

  const old64 = withAbi('glibc64', 'owned', 'a'.repeat(64), '1'.repeat(64), old64Records, [], ['lib:libc.so.6']);
  const new64 = withAbi('glibc64', 'candidate', 'b'.repeat(64), '2'.repeat(64), new64Records, [], ['lib:libc.so.6']);
  const old32 = withAbi('lib32', 'owned', 'c'.repeat(64), '3'.repeat(64), old32Records, [], ['lib:libc.so.6']);
  const new32 = withAbi('lib32', 'candidate', 'd'.repeat(64), '4'.repeat(64), new32Records, [], ['lib:libc.so.6']);
  const oldQt = withAbi('qtlib', 'owned', 'e'.repeat(64), '5'.repeat(64), oldQtRecords, [], ['lib:libQt.so.1']);
  const newQt = withAbi('qtlib', 'candidate', 'f'.repeat(64), '6'.repeat(64), newQtRecords, [], ['lib:libQt.so.1']);
  const oldApp = withAbi('qtapp', 'owned', '1'.repeat(64), '7'.repeat(64), appRecords, ['lib:libc.so.6', 'lib:libQt.so.1']);
  const newApp = withAbi('qtapp', 'candidate', '1'.repeat(64), '7'.repeat(64), appRecords, ['lib:libc.so.6', 'lib:libQt.so.1']);
  const candidate = [new64, new32, newQt, newApp]; const baseline = [old64, old32, oldQt, oldApp];
  const inMemory = qualifyCandidateUniverse({ cohortId: 'abi-semantic', revision: 1, manifestSha256: 'a'.repeat(64), architecture: 'x86_64', candidate, baseline });
  const inMemoryNames = inMemory.findings.filter((item) => item.code === 'imported-symbol-unresolved').map((item) => item.reason.match(/imports ([^,]+)/)?.[1]).sort();
  expect(inMemoryNames).toEqual(['copy_data@GLIBC_1', 'default_api', 'malloc@GLIBC_1']);
  expect(inMemory.findings.some((item) => item.relatedPkgbase === 'lib32')).toBe(false);
  expect(inMemory.findings.some((item) => item.reason.includes('qt_api'))).toBe(false);

  const holder = new TestD1(readFileSync('migrations/0051_cohort_qualification_abi_index.sql', 'utf8')); const db = asD1(holder);
  const indexed = (item: QualificationPackage): QualificationPackage => ({ ...item, abi: item.abi ? { ...item.abi, records: [] } : null });

  try {
    const indexedCandidate = candidate.map(indexed); const indexedBaseline = baseline.map(indexed);
    const records = [[new64, new64Records], [new32, new32IndexedRecords], [newQt, newQtRecords], [newApp, appRecords], [old64, old64Records], [old32, old32IndexedRecords], [oldQt, oldQtRecords]] as const;

    for (const [item, values] of records) for (let offset = 0; offset < values.length; offset += 2048) {
      await persistQualificationAbiRecords(db, { cohortId: 'abi-semantic', revision: 1, architecture: 'x86_64' }, item.artifactSha256, item.abi!.inventorySha256!, offset, values.slice(offset, offset + 2048));
    }

    const indexedFindings = await qualificationIndexedAbiFindings(db, { cohortId: 'abi-semantic', revision: 1, architecture: 'x86_64' }, indexedCandidate, indexedBaseline, 'x86_64');
    const indexedNames = indexedFindings.filter((item) => item.code === 'imported-symbol-unresolved').map((item) => item.reason.match(/imports ([^,]+)/)?.[1]).sort();
    expect(indexedNames).toEqual(['copy_data', 'default_api', 'malloc']);
    expect(indexedFindings.some((item) => item.relatedPkgbase === 'lib32')).toBe(false);
    expect(indexedFindings.some((item) => item.reason.includes('qt_api'))).toBe(false);
  } finally { holder.close(); }
}, 120000);

test('changed provider requires reverse rebuild when type ABI remains unknown even with a stable SONAME', () => {
  const oldProvider = pkg('libdemo', 'owned', 'a'.repeat(64), [], libraryAbi('a'.repeat(64)), ['lib:libdemo.so.1']);
  const newProvider = pkg('libdemo', 'candidate', 'b'.repeat(64), [], libraryAbi('b'.repeat(64)), ['lib:libdemo.so.1']);
  const stableConsumer = pkg('demo-app', 'owned', 'c'.repeat(64), ['lib:libdemo.so.1'], libraryAbi('c'.repeat(64)));
  const report = qualifyCandidateUniverse({ cohortId: 'c', revision: 1, manifestSha256: 'a'.repeat(64), architecture: 'x86_64', candidate: [newProvider, stableConsumer], baseline: [oldProvider, stableConsumer] });
  expect(report.findings.some((item) => item.code === 'reverse-rebuild-required')).toBe(true);

  const rebuiltConsumer = { ...stableConsumer, origin: 'candidate' as const, artifactSha256: 'd'.repeat(64) };
  const rebuilt = qualifyCandidateUniverse({ cohortId: 'c', revision: 1, manifestSha256: 'a'.repeat(64), architecture: 'x86_64', candidate: [newProvider, rebuiltConsumer], baseline: [oldProvider, stableConsumer] });
  expect(rebuilt.findings.some((item) => item.code === 'reverse-rebuild-required')).toBe(false);

  const versionedImport = { ...rebuiltConsumer, abi: { ...libraryAbi('d'.repeat(64)), records: [{ kind: 'symbol' as const, path: 'usr/bin/demo', table: '.dynsym', dynamic: true, index: 1, name: 'demo', defined: false,
    binding: 'STB_GLOBAL', type: 'STT_FUNC', visibility: 'STV_DEFAULT', size: 0, version: 'DEMO_2', versionFile: 'libdemo.so.1', versionHidden: false }] } };

  const versionReport = qualifyCandidateUniverse({ cohortId: 'c', revision: 1, manifestSha256: 'a'.repeat(64), architecture: 'x86_64', candidate: [newProvider, versionedImport as QualificationPackage], baseline: [oldProvider, stableConsumer] });
  expect(versionReport.findings.some((item) => item.code === 'imported-symbol-unresolved')).toBe(true);
});

test('rebuilt consumer cannot qualify against a stale provider input lock', async () => {
  const db = new TestD1('CREATE TABLE input_lock_packages(lock_sha256 TEXT,package_json TEXT);'); const provider = pkg('libdemo', 'candidate', 'b'.repeat(64), [], libraryAbi('b'.repeat(64)), ['lib:libdemo.so.1']);
  const consumer = { ...pkg('demo-app', 'candidate', 'c'.repeat(64), ['lib:libdemo.so.1'], libraryAbi('c'.repeat(64))), inputLockSha256: 'lock' };
  const before = pkg('libdemo', 'owned', 'a'.repeat(64), [], libraryAbi('a'.repeat(64)), ['lib:libdemo.so.1']);
  expect((await finalProviderInputFindings(db as unknown as D1Database, [provider, consumer], [before], 'x86_64')).map((item) => item.code)).toContain('stale-provider-input');
  db.prepare('INSERT INTO input_lock_packages VALUES(?,?)').bind('lock', JSON.stringify({ name: 'libdemo', version: '1.0-1', architecture: 'x86_64', package: { sha256: 'b'.repeat(64) }, origin: 'owned-build' })).run();
  expect(await finalProviderInputFindings(db as unknown as D1Database, [provider, consumer], [before], 'x86_64')).toEqual([]);
  const staticConsumer = { ...pkg('static-app', 'owned', 'c'.repeat(64)), inputLockSha256: 'old-lock' };
  db.prepare('INSERT INTO input_lock_packages VALUES(?,?)').bind('old-lock', JSON.stringify({ name: 'libdemo', version: '1.0-1', architecture: 'x86_64', package: { sha256: 'a'.repeat(64) }, origin: 'owned-build' })).run();
  expect((await finalProviderInputFindings(db as unknown as D1Database, [provider], [before, staticConsumer], 'x86_64')).map((item) => item.code)).toContain('reverse-rebuild-required');
  db.close();
});

test('qualification indexes a 12,000-package owned metadata universe once without claiming native coverage', async () => {
  const holder = new TestD1(schema); const db = asD1(holder); const artifacts = new MemoryR2();

  try {
    const root = 'd'.repeat(64); const manifest = { schemaVersion: 1, title: 'Owned universe', lane: 'system', systemVersion: '4.0.3', parentSnapshot: root, compatibleSystems: [], members: [] };
    const manifestJson = canonicalJson(manifest); const manifestSha256 = await sha256(manifestJson);
    db.prepare("INSERT INTO cohorts(id,current_revision,event_sequence,phase,condition,created_at,updated_at) VALUES('qualification-cohort',1,0,'verify','ready',1,1)").run();
    db.prepare("INSERT INTO cohort_revisions(cohort_id,revision,manifest_json,manifest_sha256,title,lane,created_by,created_at) VALUES('qualification-cohort',1,? ,?,'Owned universe','system','github:1',1)").bind(manifestJson, manifestSha256).run();
    db.prepare("INSERT INTO owned_repository_universes(id,lane,release_id,root_sha256,package_count,status,created_at) VALUES('universe-1','system','4.0.3',?,12000,'published',1)").bind(root).run();

    const artifactSql = `INSERT INTO owned_repository_artifacts
      (id,collection,target_architecture,name,version,architecture,pkgbase,filename,artifact_key,artifact_sha256,artifact_size,metadata_json,description,license,upstream_url,source_date_epoch,rebuild_on_json,abi_inventory_ref,
       signature_key,signature_sha256,attestation_key,attestation_sha256,attestation_size,attestation_signature_key,attestation_signature_sha256,build_id,build_attempt,revision_id,cohort_id,cohort_revision,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`;

    const packageSql = 'INSERT INTO owned_repository_universe_packages(universe_id,ordinal,artifact_id,collection,target_architecture) VALUES(?,?,?,?,?)';

    for (let index = 0; index < 12_000; index++) {
      const name = `pkg-${String(index).padStart(5, '0')}`; const metadata = canonicalJson({ name, fullVersion: '1.0-1', architecture: 'x86_64', installedSize: 1, depends: [], provides: [], conflicts: [], replaces: [] });
      db.prepare(artifactSql).bind(`artifact-${index}`, 'core', 'x86_64', name, '1.0-1', 'x86_64', name, `${name}-1.0-1-x86_64.pkg.tar.zst`, `objects/${index}`, 'a'.repeat(64), 1, metadata, name, 'MIT', `https://example.test/${name}`, 1, '[]', null, `sig/${index}`, 'b'.repeat(64), `att/${index}`, 'c'.repeat(64), 1, `att-sig/${index}`, 'e'.repeat(64), `build-${index}`, 1, `revision-${index}`, 'qualification-cohort', 1, 1).run();
      db.prepare(packageSql).bind('universe-1', index, `artifact-${index}`, 'core', 'x86_64').run();
    }

    const first = await qualifyCohort({ DB: db, ARTIFACTS: artifacts as unknown as R2Bucket } as Env, { id: 'qualification-cohort', current_revision: 1, event_sequence: 0, event_sha256: null, phase: 'verify', condition: 'ready', updated_at: 1, manifest_json: manifestJson, manifest_sha256: manifestSha256, title: 'Owned universe', lane: 'system' }, 'x86_64');
    expect(first.report.packageCount).toBe(12_000); expect(first.report.candidatePackageCount).toBe(0); expect(first.report.findings).toEqual([]);
    await storeQualificationRun(db, first);
    const second = await qualifyCohort({ DB: db, ARTIFACTS: artifacts as unknown as R2Bucket } as Env, { id: 'qualification-cohort', current_revision: 1, event_sequence: 0, event_sha256: null, phase: 'verify', condition: 'ready', updated_at: 1, manifest_json: manifestJson, manifest_sha256: manifestSha256, title: 'Owned universe', lane: 'system' }, 'x86_64');
    expect(second.digest).toBe(first.digest); expect(second.report.packageCount).toBe(12_000);
    expect((await db.prepare('SELECT COUNT(*) AS count FROM cohort_qualification_runs').first<{ count: number }>())?.count).toBe(1);
  } finally { holder.close(); }
}, 60000);

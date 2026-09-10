import { parseInputObject, type InputObject } from './frozen-inputs';

export const MAX_ABI_DOCUMENT = 512 * 1024;

export const MAX_ABI_CHUNKS = 2048;

export interface AbiElf {
  machine: string; type: string; bits: 32 | 64; byteOrder: 'little' | 'big'; soname: string | null;
  needed: string[]; rpath: string[]; runpath: string[]; interpreter: string | null;
  debugInfo: 'present' | 'absent'; dynamicSymbols: 'present' | 'absent';
}

export interface AbiFile {
  kind: 'file'; path: string; sha256: string | null; type: string; mode: number; link: string;
  nativeKind: 'elf' | 'static-archive' | 'thin-archive' | 'other' | null; elf: AbiElf | null;
}

export interface AbiSymbol {
  kind: 'symbol'; path: string; table: string; dynamic: boolean; index: number; name: string; defined: boolean;
  binding: string; type: string; visibility: string; size: number; version: string | null; versionFile: string | null; versionHidden: boolean;
}

export type AbiRecord = AbiFile | AbiSymbol;

export interface AbiChunk {
  schemaVersion: 1; kind: 'abi-records'; artifactSha256: string; start: number; records: AbiRecord[];
}

export interface AbiChunkRef extends InputObject { start: number; count: number; files: number; symbols: number }

export interface AbiInventory {
  schemaVersion: 1; kind: 'abi-inventory'; artifactSha256: string; tool: 'go-debug-elf'; toolVersion: string;
  files: number; symbols: number; chunks: AbiChunkRef[]; typeAbi: 'not-checked';
}

const hash = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

const text = (value: unknown, max = 4096): value is string => typeof value === 'string' && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);

const integer = (value: unknown, max = Number.MAX_SAFE_INTEGER): value is number => Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= max;

function assert(valid: unknown): asserts valid { if (!valid) throw new Error('Invalid or incomplete ABI inventory'); }

function keys(value: unknown, fields: string): asserts value is Record<string, unknown> {
  assert(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === fields.split(',').sort().join(','));
}

function path(value: unknown): asserts value is string {
  assert(text(value) && value && value.split('/').every((part) => part && part !== '.' && part !== '..'));
}

function stringList(value: unknown) { assert(Array.isArray(value) && value.length <= 4096 && value.every((entry) => text(entry))); }

export function parseAbiReference(value: unknown): InputObject { return parseInputObject(value, MAX_ABI_DOCUMENT); }

export function parseAbiDocument(value: unknown): AbiChunk | AbiInventory {
  assert(value && typeof value === 'object' && !Array.isArray(value));
  const document = value as AbiChunk | AbiInventory;
  assert(document.schemaVersion === 1 && hash(document.artifactSha256));

  if (document.kind === 'abi-inventory') {
    keys(document, 'schemaVersion,kind,artifactSha256,tool,toolVersion,files,symbols,chunks,typeAbi');
    assert(document.tool === 'go-debug-elf' && text(document.toolVersion, 128) && document.toolVersion && document.typeAbi === 'not-checked' &&
      integer(document.files, 100_000) && document.files > 0 && integer(document.symbols, 2_000_000) &&
      Array.isArray(document.chunks) && document.chunks.length > 0 && document.chunks.length <= MAX_ABI_CHUNKS);
    let count = 0, files = 0, symbols = 0;
    const seen = new Set<string>();

    for (const chunk of document.chunks) {
      keys(chunk, 'sha256,size,start,count,files,symbols');
      parseAbiReference({ sha256: chunk.sha256, size: chunk.size });
      assert(!seen.has(chunk.sha256) && chunk.start === count && integer(chunk.count, 2048) && chunk.count > 0 &&
        integer(chunk.files, chunk.count) && integer(chunk.symbols, chunk.count) && chunk.files + chunk.symbols === chunk.count);
      seen.add(chunk.sha256); count += chunk.count; files += chunk.files; symbols += chunk.symbols;
    }

    assert(files === document.files && symbols === document.symbols);

    return document;
  }

  keys(document, 'schemaVersion,kind,artifactSha256,start,records');
  assert(document.kind === 'abi-records' && integer(document.start, 2_099_999) && Array.isArray(document.records) &&
    document.records.length > 0 && document.records.length <= 2048 && document.start + document.records.length <= 2_100_000);
  const seen = new Set<string>();

  for (const record of document.records) {
    assert(record && typeof record === 'object'); path(record.path);

    if (record.kind === 'file') {
      keys(record, 'kind,path,sha256,type,mode,link,nativeKind,elf');
      assert((record.sha256 === null || hash(record.sha256)) && typeof record.type === 'string' && /^[0-7S]$/.test(record.type) && integer(record.mode, 0o7777) && text(record.link) &&
        [null, 'elf', 'static-archive', 'thin-archive', 'other'].includes(record.nativeKind));
      assert((['0', '7', 'S'].includes(record.type)) === (record.sha256 !== null));
      assert((record.nativeKind === 'elf') === (record.elf !== null));

      if (record.nativeKind) assert(record.sha256 !== null);

      if (record.elf) {
        const elf = record.elf;
        keys(elf, 'machine,type,bits,byteOrder,soname,needed,rpath,runpath,interpreter,debugInfo,dynamicSymbols');
        assert(text(elf.machine, 128) && elf.machine && text(elf.type, 128) && elf.type && [32, 64].includes(elf.bits) && ['little', 'big'].includes(elf.byteOrder) &&
          (elf.soname === null || (text(elf.soname) && elf.soname)) && (elf.interpreter === null || (text(elf.interpreter) && elf.interpreter)) &&
          ['present', 'absent'].includes(elf.debugInfo) && ['present', 'absent'].includes(elf.dynamicSymbols));

        for (const list of [elf.needed, elf.rpath, elf.runpath]) stringList(list);
      }
    } else {
      keys(record, 'kind,path,table,dynamic,index,name,defined,binding,type,visibility,size,version,versionFile,versionHidden');
      assert(record.kind === 'symbol' && text(record.table) && record.table && typeof record.dynamic === 'boolean' && integer(record.index) &&
        text(record.name, 16384) && record.name && typeof record.defined === 'boolean' && text(record.binding, 128) && record.binding &&
        text(record.type, 128) && record.type && text(record.visibility, 128) && record.visibility && integer(record.size) &&
        (record.version === null || (text(record.version) && record.version)) && (record.versionFile === null || (text(record.versionFile) && record.versionFile)) &&
        typeof record.versionHidden === 'boolean');
    }

    const identity = JSON.stringify(record.kind === 'file' ? [record.path] : [record.path, record.table, record.index]);
    assert(!seen.has(identity)); seen.add(identity);
  }

  return document;
}

import type { Architecture } from './model';
import { compareArchVersions, isArchPkgver, parseArchRelation } from './server/arch';

export type Srcinfo = { pkgbase: string; version: string; pkgver: string; pkgrel: string; epoch: number;
  base: Record<string, string[]>; outputs: Array<{ name: string; fields: Record<string, string[]> }> };

const name = /^[a-z0-9][a-z0-9@._+-]{0,63}$/;

const single = new Set(['pkgver', 'pkgrel', 'epoch', 'pkgdesc', 'url', 'install', 'changelog']);

function hasControlCharacters(value: string): boolean {
  return [...value].some((character) => character <= '\u001f' || character === '\u007f');
}

/** Parse the data format only. PKGBUILD shell is never sourced here. */
export function parseSrcinfo(text: string): Srcinfo {
  if (new TextEncoder().encode(text).length > 1024 * 1024 || text.includes('\u0000') || text.includes('\r')) throw new Error('Invalid or oversized .SRCINFO');
  let pkgbase = '';
  const base: Record<string, string[]> = Object.create(null);
  const outputs: Srcinfo['outputs'] = [];
  let fields = base;

  for (const line of text.split('\n')) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const match = /^\s*([a-z][a-z0-9_]*)\s*=\s?(.*)$/.exec(line);

    if (!match || match[2].length > 4096 || hasControlCharacters(match[2])) throw new Error('Malformed .SRCINFO field');
    const [, key, value] = match;

    if (key === 'pkgbase') {
      if (pkgbase || !name.test(value) || Object.keys(base).length || outputs.length) throw new Error('Invalid .SRCINFO package base');
      pkgbase = value;
    } else if (key === 'pkgname') {
      if (!pkgbase || !name.test(value) || outputs.some((output) => output.name === value) || outputs.length >= 256) throw new Error('Invalid .SRCINFO output');
      fields = Object.create(null) as Record<string, string[]>;
      outputs.push({ name: value, fields });
    } else {
      if (!pkgbase || key === '__proto__' || (single.has(key) && fields[key]) || (fields[key]?.length ?? 0) >= 2048) throw new Error('Repeated or misplaced .SRCINFO field');

      if (value === '') { if (fields[key]) throw new Error('Ambiguous .SRCINFO clearing field'); fields[key] = []; }
      else (fields[key] ??= []).push(value);
    }
  }

  const pkgver = base.pkgver?.[0] ?? '', pkgrel = base.pkgrel?.[0] ?? '', epochText = base.epoch?.[0] ?? '0';

  if (!pkgbase || !outputs.length || !isArchPkgver(pkgver) || !/^[1-9]\d{0,3}(?:\.[1-9]\d{0,3})?$/.test(pkgrel) || !/^\d{1,15}$/.test(epochText)) throw new Error('Incomplete .SRCINFO identity or full version');
  const epoch = Number(epochText);
  const version = `${epoch ? `${epoch}:` : ''}${pkgver}-${pkgrel}`;

  if (!Number.isSafeInteger(epoch) || compareArchVersions(version, version) === null) throw new Error('Invalid .SRCINFO version');

  for (const output of outputs) {
    if (['pkgver', 'pkgrel', 'epoch'].some((key) => key in output.fields)) throw new Error('Split output overrides package base version');
    const architectures = output.fields.arch ?? base.arch ?? [];

    if (!architectures.length || architectures.some((arch) => !/^[a-zA-Z0-9_]+$/.test(arch))) throw new Error('Missing or invalid .SRCINFO architecture');
  }

  for (const group of [base, ...outputs.map((output) => output.fields)]) for (const [key, values] of Object.entries(group)) {
    if (/^(?:depends|makedepends|checkdepends|provides|conflicts|replaces)(?:_[a-zA-Z0-9_]+)?$/.test(key) && values.some((value) => !parseArchRelation(value))) throw new Error('Invalid .SRCINFO package relation');
  }

  return { pkgbase, version, pkgver, pkgrel, epoch, base, outputs };
}

export function srcinfoField(metadata: Srcinfo, output: Srcinfo['outputs'][number], key: string, target?: Architecture): string[] {
  const values = output.fields[key] ?? metadata.base[key] ?? [];

  return target ? [...values, ...(output.fields[`${key}_${target}`] ?? metadata.base[`${key}_${target}`] ?? [])] : values;
}

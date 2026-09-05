import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import {
  getBuildImages,
  getDefaultBuildImages,
  registerBuildImage,
  setBuildImageEnabled,
  setDefaultBuildImage,
} from '../src/lib/server/build-images';
import type { Env } from '../src/lib/server/env';
import { asD1, TestD1 } from './d1';

const migration = readFileSync(new URL('../migrations/0011_build_images.sql', import.meta.url), 'utf8');
const schema = `
CREATE TABLE revisions(id TEXT PRIMARY KEY);
CREATE TABLE audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,detail TEXT NOT NULL,created_at INTEGER NOT NULL);
${migration}
`;

function env(db: TestD1): Pick<Env, 'DB'> {
  return { DB: asD1(db) };
}

const admin = { id: 'github:test-admin', role: 'admin' as const, areas: [] };
const maintainer = { id: 'github:7', role: 'maintainer' as const, areas: ['development'] };
const x86Ref = `docker.io/library/archlinux:base-devel@sha256:${'a'.repeat(64)}`;
const x86RcRef = `ghcr.io/omacom/arch-builder:rc@sha256:${'b'.repeat(64)}`;
const armRef = `registry.example.org/omarchy/arch-builder:edge@sha256:${'c'.repeat(64)}`;

describe('build image registry', () => {
  test('requires admin registration and stores digest-pinned records disabled', async () => {
    const db = new TestD1(schema);
    try {
      await expect(registerBuildImage(env(db), maintainer, {
        label: 'Denied', image_ref: x86Ref, architecture: 'x86_64', mirror: 'stable',
      })).rejects.toMatchObject({ status: 403 });

      await expect(registerBuildImage(env(db), admin, {
        label: 'With command', image_ref: x86Ref, architecture: 'x86_64', mirror: 'stable',
        command: 'docker run --privileged', registry_token: 'must never be stored',
      } as unknown)).rejects.toMatchObject({ status: 400 });

      const result = await registerBuildImage(env(db), admin, {
        label: 'Arch base-devel stable', image_ref: x86Ref, architecture: 'x86_64', mirror: 'stable',
      });
      const row = db.prepare('SELECT * FROM build_images WHERE id=?').bind(result.id).first<Record<string, unknown>>();
      expect(row).toMatchObject({
        id: result.id, label: 'Arch base-devel stable', image_ref: x86Ref, architecture: 'x86_64',
        mirror: 'stable', enabled: 0, is_default: 0, created_actor: admin.id,
      });
      expect(db.prepare("SELECT action FROM audit_events WHERE target=?").bind(result.id).first<{ action: string }>()?.action).toBe('build_image.registered');

      await expect(registerBuildImage(env(db), admin, {
        label: 'Mutable', image_ref: 'docker.io/library/archlinux:latest', architecture: 'x86_64', mirror: 'stable',
      })).rejects.toMatchObject({ status: 400 });
      await expect(registerBuildImage(env(db), admin, {
        label: 'Wrong registry', image_ref: `https://registry.example.org/image@sha256:${'d'.repeat(64)}`, architecture: 'x86_64', mirror: 'stable',
      })).rejects.toMatchObject({ status: 400 });
      await expect(registerBuildImage(env(db), admin, {
        label: 'Duplicate', image_ref: x86Ref, architecture: 'x86_64', mirror: 'custom',
      })).rejects.toMatchObject({ status: 409 });
    } finally {
      db.close();
    }
  });

  test('enables images and keeps one enabled default per architecture', async () => {
    const db = new TestD1(schema);
    try {
      const first = await registerBuildImage(env(db), admin, { label: 'Stable', image_ref: x86Ref, architecture: 'x86_64', mirror: 'stable' });
      const second = await registerBuildImage(env(db), admin, { label: 'Release candidate', image_ref: x86RcRef, architecture: 'x86_64', mirror: 'rc' });
      const arm = await registerBuildImage(env(db), admin, { label: 'ARM edge', image_ref: armRef, architecture: 'aarch64', mirror: 'edge' });

      expect((await getBuildImages(env(db))).every((image) => image.enabled === 0 && image.is_default === 0)).toBe(true);
      expect(await getDefaultBuildImages(env(db))).toEqual({});

      await setBuildImageEnabled(env(db), admin, first.id, true);
      await setBuildImageEnabled(env(db), admin, second.id, true);
      await setBuildImageEnabled(env(db), admin, arm.id, true);
      await setDefaultBuildImage(env(db), admin, first.id);
      expect(await getDefaultBuildImages(env(db))).toEqual({ x86_64: x86Ref });

      await setDefaultBuildImage(env(db), admin, second.id);
      expect(await getDefaultBuildImages(env(db))).toEqual({ x86_64: x86RcRef });
      expect(db.prepare('SELECT count(*) AS count FROM build_images WHERE architecture=? AND is_default=1').bind('x86_64').first<{ count: number }>()?.count).toBe(1);

      await setDefaultBuildImage(env(db), admin, arm.id);
      expect(await getDefaultBuildImages(env(db))).toEqual({ x86_64: x86RcRef, aarch64: armRef });
      await setBuildImageEnabled(env(db), admin, second.id, false);
      expect(await getDefaultBuildImages(env(db))).toEqual({ aarch64: armRef });
      expect(db.prepare('SELECT is_default FROM build_images WHERE id=?').bind(second.id).first<{ is_default: number }>()?.is_default).toBe(0);
      await setBuildImageEnabled(env(db), admin, first.id, false);
      await expect(setDefaultBuildImage(env(db), admin, first.id)).rejects.toMatchObject({ status: 409 });
    } finally {
      db.close();
    }
  });

  test('protects registered identity while allowing availability changes', async () => {
    const db = new TestD1(schema);
    try {
      const result = await registerBuildImage(env(db), admin, { label: 'Stable', image_ref: x86Ref, architecture: 'x86_64', mirror: 'stable' });
      expect(() => db.prepare('UPDATE build_images SET label=? WHERE id=?').bind('Changed', result.id).run()).toThrow('immutable');
      expect(() => db.prepare('UPDATE build_images SET image_ref=? WHERE id=?').bind(x86RcRef, result.id).run()).toThrow('immutable');
      expect(() => db.prepare('DELETE FROM build_images WHERE id=?').bind(result.id).run()).toThrow('immutable');
      expect(() => db.prepare('UPDATE build_images SET is_default=1 WHERE id=?').bind(result.id).run()).toThrow();
      await setBuildImageEnabled(env(db), admin, result.id, true);
      expect(db.prepare('SELECT enabled FROM build_images WHERE id=?').bind(result.id).first<{ enabled: number }>()?.enabled).toBe(1);
    } finally {
      db.close();
    }
  });

  test('adds an empty image map to new revisions', () => {
    const db = new TestD1(schema);
    try {
      db.prepare('INSERT INTO revisions(id) VALUES(?)').bind('revision-1').run();
      expect(db.prepare('SELECT build_images_json FROM revisions WHERE id=?').bind('revision-1').first<{ build_images_json: string }>()?.build_images_json).toBe('{}');
    } finally {
      db.close();
    }
  });
});

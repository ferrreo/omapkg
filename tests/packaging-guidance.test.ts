import { describe, expect, test } from 'bun:test';
import {
  PACKAGING_FAMILY_ORDER,
  PACKAGING_GUIDANCE,
  PACKAGING_GUIDANCE_COMMIT,
  PACKAGING_GUIDANCE_SOURCES,
  packagingGuidanceForTemplate,
  renderFluePackagingGuidance,
} from '../services/pipeline/packaging-guidance';

describe('packaging guidance', () => {
  test('covers every required family with bounded offline rules', () => {
    expect(Object.keys(PACKAGING_GUIDANCE).sort()).toEqual([...PACKAGING_FAMILY_ORDER].sort());

    for (const family of PACKAGING_FAMILY_ORDER) {
      const item = PACKAGING_GUIDANCE[family];
      expect(item.inspect.length).toBeGreaterThan(0);
      expect(item.prepare.length + item.build.length + item.check.length + item.install.length).toBeGreaterThan(3);
      expect(item.reject.join(' ')).toMatch(/live downloads|host writes/i);
    }
  });

  test('renders selected families in canonical order and records the pinned source', () => {
    const rendered = renderFluePackagingGuidance(['go', 'cmake', 'go']);
    expect(rendered.indexOf('## cmake')).toBeLessThan(rendered.indexOf('## go'));
    expect(rendered).toContain(PACKAGING_GUIDANCE_COMMIT);
    expect(PACKAGING_GUIDANCE_SOURCES).toHaveLength(10);
    expect(rendered).not.toContain('swamp workflow');
    expect(packagingGuidanceForTemplate('go-v2')?.family).toBe('go');
    expect(packagingGuidanceForTemplate('unknown-v1')).toBeUndefined();
  });

  test('rejects empty and unknown family selections', () => {
    expect(() => renderFluePackagingGuidance([])).toThrow('At least one packaging family');
    expect(() => renderFluePackagingGuidance(['unknown' as never])).toThrow('Unknown packaging family');
  });
});

const EVIDENCE_PREFIX = 'OPR-EVIDENCE-1\n';

export type OprEvidence = Record<string, unknown>;

export function encodeOprEvidence(value: OprEvidence): string {
  return `${EVIDENCE_PREFIX}${JSON.stringify(value)}`;
}

export function readOprEvidence(value: unknown): OprEvidence | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const document = value as Record<string, unknown>;
  if (typeof document.comment === 'string' && document.comment.startsWith(EVIDENCE_PREFIX)) {
    try {
      const parsed: unknown = JSON.parse(document.comment.slice(EVIDENCE_PREFIX.length));
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as OprEvidence : null;
    } catch { /* fall through to legacy evidence when present */ }
  }
  if (document.oprEvidence && typeof document.oprEvidence === 'object' && !Array.isArray(document.oprEvidence)) {
    return document.oprEvidence as OprEvidence;
  }
  return null;
}

export function sourceRedirects(value: unknown): string[] {
  const evidence = readOprEvidence(value);
  const resolution = evidence?.sourceResolution;
  const redirects = resolution && typeof resolution === 'object' && !Array.isArray(resolution)
    ? (resolution as Record<string, unknown>).redirectChain ?? (resolution as Record<string, unknown>).sourceRedirects
    : evidence?.sourceRedirects;
  return Array.isArray(redirects) ? redirects.filter((item): item is string => typeof item === 'string') : [];
}

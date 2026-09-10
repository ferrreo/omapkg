import { expect, test } from 'bun:test';
import { assertExplicitReview } from '../services/pipeline/recipe-policy';
import { encodeOprEvidence } from '../src/lib/server/sbom';
import { TestD1, asD1 } from './d1';

test('custom shell acknowledgement is bound to both current reviewers and exact manifest', async () => {
  const db = new TestD1(`CREATE TABLE approvals(revision_id TEXT,manifest_sha256 TEXT,kind TEXT,actor TEXT,created_at INTEGER,revoked_at INTEGER);
    CREATE TABLE audit_events(action TEXT,actor TEXT,created_at INTEGER,detail TEXT);
    INSERT INTO approvals VALUES('revision','manifest','area','alice',1,NULL),('revision','manifest','security','bob',2,NULL);`);

  const sbom = JSON.stringify({ comment: encodeOprEvidence({ recipePolicy: { mode: 'custom-shell', version: 1 } }) });

  try {
    await expect(assertExplicitReview(asD1(db), 'revision', 'manifest', sbom)).rejects.toThrow('Both reviewers');

    for (const [actor, kind, timestamp] of [['alice', 'area', 1], ['bob', 'security', 2]]) {
      db.prepare("INSERT INTO audit_events VALUES('revision.approved',?,?,?)").bind(actor, timestamp, JSON.stringify({ revisionId: 'revision', manifestSha256: 'manifest', kind, customShellAcknowledged: true })).run();
    }

    await assertExplicitReview(asD1(db), 'revision', 'manifest', sbom);
    db.exec("UPDATE approvals SET actor='replacement' WHERE kind='security'");
    await expect(assertExplicitReview(asD1(db), 'revision', 'manifest', sbom)).rejects.toThrow('Both reviewers');
    db.exec("UPDATE approvals SET actor='bob',manifest_sha256='changed' WHERE kind='security'");
    await expect(assertExplicitReview(asD1(db), 'revision', 'manifest', sbom)).rejects.toThrow('Both reviewers');
  } finally { db.close(); }
});

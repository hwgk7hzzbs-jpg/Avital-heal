import { describe, it, expect } from 'vitest';
import { CONSENT_DOCUMENTS, hashDocument } from '../consentDocuments.js';

describe('CONSENT_DOCUMENTS', () => {
  it('defines both treatment and workshop documents with version/source/text', () => {
    for (const key of ['treatment', 'workshop']) {
      const doc = CONSENT_DOCUMENTS[key];
      expect(doc.version).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(doc.source).toBeTruthy();
      expect(doc.text.length).toBeGreaterThan(100);
    }
  });
});

describe('hashDocument', () => {
  it('is deterministic for the same text', async () => {
    const a = await hashDocument('hello world');
    const b = await hashDocument('hello world');
    expect(a).toBe(b);
  });

  it('produces a 64-char hex SHA-256 digest', async () => {
    const hash = await hashDocument('hello world');
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('changes when the text changes by even one character', async () => {
    const a = await hashDocument('hello world');
    const b = await hashDocument('hello world.');
    expect(a).not.toBe(b);
  });

  it('produces different hashes for the treatment and workshop documents', async () => {
    const a = await hashDocument(CONSENT_DOCUMENTS.treatment.text);
    const b = await hashDocument(CONSENT_DOCUMENTS.workshop.text);
    expect(a).not.toBe(b);
  });
});

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

// admin-utils.js is loaded as a plain classic <script> in the browser (no bundler,
// no <script type="module">), so it can't use `export`. To test the real production
// code without changing how it loads at runtime, evaluate its source in a sandbox
// and pull the resulting global function out.
function loadEscapeHtml() {
  const path = fileURLToPath(new URL('../../app/js/admin-utils.js', import.meta.url));
  const source = readFileSync(path, 'utf8');
  const sandbox = {};
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox);
  return sandbox.escapeHtml;
}

const escapeHtml = loadEscapeHtml();

describe('escapeHtml (admin panel XSS guard)', () => {
  it('neutralizes a classic onerror payload', () => {
    const out = escapeHtml('<img src=x onerror=alert(1)>');
    expect(out).not.toContain('<img');
    expect(out).toBe('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('neutralizes a script tag', () => {
    expect(escapeHtml('<script>alert(1)</script>')).not.toContain('<script>');
  });

  it('escapes quotes to prevent attribute breakout', () => {
    const out = escapeHtml(`"><script>alert(1)</script>`);
    expect(out).not.toContain('"');
    expect(out).not.toContain('<script>');
  });

  it('escapes single quotes (breaks out of onclick="..." single-quoted attrs)', () => {
    expect(escapeHtml(`'; alert(1); '`)).not.toContain("'");
  });

  it('passes plain text through unchanged', () => {
    expect(escapeHtml('שם רגיל')).toBe('שם רגיל');
  });

  it('handles null/undefined without throwing', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
  });

  it('coerces non-strings safely', () => {
    expect(escapeHtml(42)).toBe('42');
  });
});

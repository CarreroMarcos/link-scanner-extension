const { sanitizeUrl, containsPotentialSecret } = require('./service_worker');

test('removes known tracking params and preserves others', () => {
  const u = new URL('https://example.com/path?utm_source=google&utm_medium=cpc&ref=abc');
  const cleaned = sanitizeUrl(u);

  expect(cleaned.searchParams.has('utm_source')).toBe(false);
  expect(cleaned.searchParams.has('utm_medium')).toBe(false);
  expect(cleaned.searchParams.get('ref')).toBe('abc');
});

test('treats tracking keys case-insensitively', () => {
  const u = new URL('https://example.com/?UTM_Source=google&Param=1');
  const cleaned = sanitizeUrl(u);

  expect(Array.from(cleaned.searchParams.keys()).map(k => k.toLowerCase())).not.toContain('utm_source');
  expect(cleaned.searchParams.get('Param')).toBe('1');
});

test('does not mutate the input URL object', () => {
  const original = new URL('https://example.com/?utm_source=google&keep=1');
  const cleaned = sanitizeUrl(original);

  expect(Array.from(original.searchParams.keys()).map(k => k.toLowerCase())).toContain('utm_source');
  
  expect(Array.from(cleaned.searchParams.keys()).map(k => k.toLowerCase())).not.toContain('utm_source');
});

test('detects potential secret when value is very long', () => {
  const longVal = 'x'.repeat(33);
  const u = new URL(`https://example.com/?a=${longVal}`);
  expect(containsPotentialSecret(u)).toBe(true);
});

test('detects potential secret when key matches token-like patterns', () => {
  const u = new URL('https://example.com/?authToken=12345');
  expect(containsPotentialSecret(u)).toBe(true);
});

test('returns false for benign params', () => {
  const u = new URL('https://example.com/?q=search&ref=abc');
  expect(containsPotentialSecret(u)).toBe(false);
});

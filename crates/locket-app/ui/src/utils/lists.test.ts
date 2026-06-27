import { describe, expect, it } from 'vitest';

import { parseCommaList } from './lists';

describe('parseCommaList', () => {
  it('trims entries, skips blanks, dedupes, and keeps first-seen order', () => {
    expect(parseCommaList(' dev , prod, dev ,, qa ,prod ')).toEqual(['dev', 'prod', 'qa']);
  });

  it('returns an empty list for blank input', () => {
    expect(parseCommaList('')).toEqual([]);
    expect(parseCommaList('   ')).toEqual([]);
  });
});

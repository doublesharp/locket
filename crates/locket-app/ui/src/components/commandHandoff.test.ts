import { describe, expect, it, vi } from 'vitest';

import { copyCommandToClipboard } from './commandHandoff';

describe('copyCommandToClipboard', () => {
  it('copies the command and returns an accessible success status', async () => {
    const writeText = vi.fn<(text: string) => Promise<void>>().mockResolvedValue(undefined);

    const result = await copyCommandToClipboard('locket team members', { writeText });

    expect(writeText).toHaveBeenCalledWith('locket team members');
    expect(result).toEqual({
      ok: true,
      message: 'Command copied.',
    });
  });

  it('reports clipboard failures without throwing', async () => {
    const writeText = vi.fn<(text: string) => Promise<void>>().mockRejectedValue(new Error('no'));

    const result = await copyCommandToClipboard('locket team members', { writeText });

    expect(result).toEqual({
      ok: false,
      message: 'Copy failed. Select the command text and copy it manually.',
    });
  });
});

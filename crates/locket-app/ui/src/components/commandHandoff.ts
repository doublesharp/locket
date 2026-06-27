export interface ClipboardWriter {
  writeText(text: string): Promise<void>;
}

export interface CopyCommandResult {
  ok: boolean;
  message: string;
}

export async function copyCommandToClipboard(
  command: string,
  clipboard: ClipboardWriter | null | undefined,
): Promise<CopyCommandResult> {
  try {
    if (clipboard === null || clipboard === undefined) {
      throw new Error('Clipboard unavailable');
    }
    await clipboard.writeText(command);
    return { ok: true, message: 'Command copied.' };
  } catch {
    return {
      ok: false,
      message: 'Copy failed. Select the command text and copy it manually.',
    };
  }
}

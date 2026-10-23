/** Only the newest request in a live, unchanged context may apply its result. */
export function createRequestLifetime() {
  let generation = 0;
  let disposed = false;

  return {
    begin(): () => boolean {
      const captured = ++generation;
      return () => !disposed && captured === generation;
    },
    invalidate(): void {
      ++generation;
    },
    dispose(): void {
      disposed = true;
      ++generation;
    },
  };
}

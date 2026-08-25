/**
 * Whether a granted action covers a requested action.
 * Supports exact match and a single trailing `.*` wildcard (e.g. `cert.*` → `cert.issue`).
 */
export function actionCovers(granted: string, requested: string): boolean {
  if (granted === requested) {
    return true;
  }
  if (granted.endsWith(".*")) {
    const prefix = granted.slice(0, -2);
    if (prefix.length === 0) {
      return false;
    }
    return requested === prefix || requested.startsWith(`${prefix}.`);
  }
  return false;
}

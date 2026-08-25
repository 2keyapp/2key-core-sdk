import type { CapabilitySet, Catalog, ProfileDef } from "./types.js";

/**
 * Expand a named profile into a CapabilitySet using catalog profile defs.
 */
export function expandProfile(
  profile: string,
  profiles: readonly ProfileDef[],
  catalog: Catalog,
): CapabilitySet {
  const found = profiles.find((p) => p.profile === profile);
  if (!found) {
    throw new Error(
      `profile "${profile}" not found for service "${catalog.serviceId}"`,
    );
  }
  return found.permissions;
}

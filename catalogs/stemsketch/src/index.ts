import type { CatalogSeed } from "@2key/dp-spec";

/** Stable serviceId / tenant slug for StemSketch. */
export const SERVICE_ID = "stemsketch";

/**
 * Placeholder catalog — Auth + Billing model TBD.
 * Populate actions / scopeDimensions / profiles after the tenant design discussion.
 */
export const CATALOG_SEED: CatalogSeed = {
  serviceId: SERVICE_ID,
  actions: [],
  scopeDimensions: [{ dimension: "entity", algebra: "exact" }],
  profiles: [],
};

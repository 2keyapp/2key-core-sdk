import { authorize } from "./authorize.js";
import type {
  AuthorizeResult,
  CapabilitySet,
  Catalog,
  Resource,
} from "./types.js";

export type EnforceInput = {
  grants: CapabilitySet;
  action: string;
  resource: Resource;
  catalog: Catalog;
  /** When set, reject if credential/catalog generation is stale. */
  credentialCatalogGeneration?: number;
};

/**
 * Client-side PEP gate: run before calling a remote service.
 * Server must still enforce the same check — this only filters traffic.
 */
export function enforceLocally(input: EnforceInput): AuthorizeResult {
  if (
    input.credentialCatalogGeneration != null &&
    input.credentialCatalogGeneration !== input.catalog.generation
  ) {
    return {
      ok: false,
      code: "CATALOG_GENERATION_MISMATCH",
      message: `credential catalog generation ${input.credentialCatalogGeneration} != ${input.catalog.generation}`,
    };
  }
  return authorize(input.grants, input.action, input.resource, input.catalog);
}

/**
 * Throw if not authorized (convenient for request wrappers).
 */
export function assertAuthorized(input: EnforceInput): void {
  const result = enforceLocally(input);
  if (!result.ok) {
    const err = new Error(result.message) as Error & { code: string };
    err.code = result.code;
    err.name = "DpNotAuthorizedError";
    throw err;
  }
}

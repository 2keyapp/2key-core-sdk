import { actionCovers } from "./action.js";
import { scopeMapSubset } from "./scope.js";
import type {
  Capability,
  CapabilitySet,
  Catalog,
  ScopeAlgebra,
  SubsetResult,
} from "./types.js";

function algebraLookup(
  catalog: Catalog,
): (dimension: string) => ScopeAlgebra | undefined {
  const map = new Map(
    catalog.scopeDimensions.map((d) => [d.dimension, d.algebra] as const),
  );
  return (dimension) => map.get(dimension);
}

function actionKnown(catalog: Catalog, action: string): boolean {
  if (catalog.actions.some((a) => a.action === action)) {
    return true;
  }
  if (action.endsWith(".*")) {
    const prefix = action.slice(0, -2);
    return catalog.actions.some(
      (a) => a.action === prefix || a.action.startsWith(`${prefix}.`),
    );
  }
  return false;
}

function capabilityCoveredByParent(
  child: Capability,
  parentSet: CapabilitySet,
  catalog: Catalog,
): SubsetResult {
  const algebraFor = algebraLookup(catalog);

  for (const parent of parentSet) {
    if (!parent.delegable) {
      continue;
    }
    if (!actionCovers(parent.action, child.action)) {
      continue;
    }
    const scopeResult = scopeMapSubset(child.scope, parent.scope, algebraFor);
    if (!scopeResult.ok) {
      continue;
    }
    return { ok: true };
  }

  return {
    ok: false,
    code: "SUBSET_VIOLATION",
    message: `capability action "${child.action}" is not covered by a delegable parent grant`,
  };
}

/**
 * Assert every child capability is ⊆ some delegable parent capability.
 */
export function assertSubset(
  child: CapabilitySet,
  parent: CapabilitySet,
  catalog: Catalog,
): SubsetResult {
  for (const cap of child) {
    if (!actionKnown(catalog, cap.action)) {
      return {
        ok: false,
        code: "UNKNOWN_ACTION",
        message: `unknown action "${cap.action}"`,
      };
    }
    for (const dimension of Object.keys(cap.scope)) {
      if (!catalog.scopeDimensions.some((d) => d.dimension === dimension)) {
        return {
          ok: false,
          code: "UNKNOWN_SCOPE_DIMENSION",
          message: `unknown scope dimension "${dimension}"`,
        };
      }
    }
    const covered = capabilityCoveredByParent(cap, parent, catalog);
    if (!covered.ok) {
      return covered;
    }
  }
  return { ok: true };
}

import type { ScopeAlgebra, ScopeMap } from "./types.js";

/**
 * Whether `child` is a DNS-style prefix subset of `parent` for left-hand zone labels.
 * Parent `""` covers all. Child matches parent exactly or ends with `.${parent}`.
 */
export function dnsPrefixSubset(child: string, parent: string): boolean {
  if (parent === "") {
    return true;
  }
  if (child === parent) {
    return true;
  }
  return child.endsWith(`.${parent}`);
}

function asStringList(value: string | readonly string[]): readonly string[] {
  return typeof value === "string" ? [value] : value;
}

/**
 * Whether child scope value is ⊆ parent scope value under the given algebra.
 */
export function scopeValueSubset(
  child: string | readonly string[],
  parent: string | readonly string[],
  algebra: ScopeAlgebra,
): boolean {
  switch (algebra) {
    case "exact": {
      const c = asStringList(child);
      const p = asStringList(parent);
      if (c.length !== 1 || p.length !== 1) {
        return false;
      }
      return c[0] === p[0];
    }
    case "dns_prefix": {
      const c = asStringList(child);
      const p = asStringList(parent);
      if (c.length !== 1 || p.length !== 1) {
        return false;
      }
      return dnsPrefixSubset(c[0]!, p[0]!);
    }
    case "set": {
      const c = asStringList(child);
      const p = new Set(asStringList(parent));
      return c.every((member) => p.has(member));
    }
    default: {
      const _exhaustive: never = algebra;
      return _exhaustive;
    }
  }
}

/**
 * Whether child ScopeMap is ⊆ parent ScopeMap.
 */
export function scopeMapSubset(
  child: ScopeMap,
  parent: ScopeMap,
  algebraFor: (dimension: string) => ScopeAlgebra | undefined,
): { ok: true } | { ok: false; dimension: string; message: string } {
  const dimensions = new Set([...Object.keys(child), ...Object.keys(parent)]);

  for (const dimension of dimensions) {
    const parentValue = parent[dimension];
    const childValue = child[dimension];

    if (parentValue === undefined) {
      continue;
    }

    if (childValue === undefined) {
      return {
        ok: false,
        dimension,
        message: `child omits restricted scope dimension "${dimension}"`,
      };
    }

    const algebra = algebraFor(dimension);
    if (!algebra) {
      return {
        ok: false,
        dimension,
        message: `unknown scope dimension "${dimension}"`,
      };
    }

    if (!scopeValueSubset(childValue, parentValue, algebra)) {
      return {
        ok: false,
        dimension,
        message: `scope dimension "${dimension}" is not a subset under ${algebra}`,
      };
    }
  }

  return { ok: true };
}

/**
 * Whether a resource satisfies a grant scope for authorization.
 */
export function resourceSatisfiesScope(
  resource: ScopeMap,
  grantScope: ScopeMap,
  algebraFor: (dimension: string) => ScopeAlgebra | undefined,
): boolean {
  for (const [dimension, grantValue] of Object.entries(grantScope)) {
    const resourceValue = resource[dimension];
    if (resourceValue === undefined) {
      return false;
    }
    const algebra = algebraFor(dimension);
    if (!algebra) {
      return false;
    }
    if (!scopeValueSubset(resourceValue, grantValue, algebra)) {
      return false;
    }
  }
  return true;
}

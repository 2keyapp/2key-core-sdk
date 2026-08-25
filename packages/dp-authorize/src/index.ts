export { actionCovers } from "./action.js";
export { authorize } from "./authorize.js";
export { expandProfile } from "./expand.js";
export { assertAuthorized, enforceLocally, type EnforceInput } from "./enforce.js";
export {
  dnsPrefixSubset,
  resourceSatisfiesScope,
  scopeMapSubset,
  scopeValueSubset,
} from "./scope.js";
export { assertSubset } from "./subset.js";
export type {
  ActionDef,
  AuthorizeResult,
  Capability,
  CapabilitySet,
  Catalog,
  ProfileDef,
  Resource,
  ScopeAlgebra,
  ScopeDimensionDef,
  ScopeMap,
  SubsetResult,
} from "./types.js";

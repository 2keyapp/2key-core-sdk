export { createAdminClient } from "./admin.js";
export type { AdminClient, AdminClientOptions, KickstartRequest } from "./admin.js";
export {
  attachPlatformCosign,
  verifyCredentialSignature,
} from "./credential.js";
export {
  createDeviceIdentity,
  verifyPresentedCredential,
} from "./device.js";
export { generateEd25519KeyPair, randomLocalId } from "./keys.js";
export type { KeyPairMaterial } from "./keys.js";
export type {
  CapabilityCredential,
  CapabilitySet,
  CatalogSeed,
  PlatformCosign,
} from "@2key/dp-spec";

export {
  attachPlatformCertCosign,
  verifyPlatformCertCosign,
} from "./cosign.js";
export {
  createSelfSignedCa,
  generateKeyAndCsr,
  signClientCertFromCsr,
} from "./csr.js";
export type {
  CreateSelfSignedCaParams,
  CreateSelfSignedCaResult,
  GenerateKeyAndCsrParams,
  GenerateKeyAndCsrResult,
  SignClientCertFromCsrParams,
  SignClientCertFromCsrResult,
} from "./csr.js";
export {
  extractSkiFromCertPem,
  materializeMtlsClient,
  skiSanUri,
  toNodeTlsOptions,
} from "./materialize.js";
export type { MtlsTrustOptions } from "./materialize.js";
export type {
  DeviceIdentity,
  MtlsClientMaterial,
} from "@2key/dp-presentation";
export type {
  DeviceEnrollRequest,
  DeviceEnrollResult,
  PlatformCosign,
} from "@2key/dp-spec";

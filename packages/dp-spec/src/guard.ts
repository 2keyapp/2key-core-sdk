import type { CapabilityCredential } from "./types.js";

/** Spec package smoke — types are compile-time only. */
export function isCapabilityCredentialV1(
  value: CapabilityCredential,
): value is CapabilityCredential {
  return value.version === 1;
}

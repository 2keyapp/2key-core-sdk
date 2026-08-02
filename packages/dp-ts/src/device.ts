import type { CapabilityCredential } from "@2key/dp-spec";
import { verifyCredentialSignature } from "./credential.js";
import { generateEd25519KeyPair } from "./keys.js";

/**
 * Device/machine helpers: local keygen + credential verification.
 * Presentation to PEPs (mTLS / WebRTC) is product-specific.
 */
export async function createDeviceIdentity() {
  return generateEd25519KeyPair();
}

export async function verifyPresentedCredential(
  credential: CapabilityCredential,
  issuerPublicJwk: CapabilityCredential["publicJwk"],
): Promise<boolean> {
  return verifyCredentialSignature(credential, issuerPublicJwk);
}

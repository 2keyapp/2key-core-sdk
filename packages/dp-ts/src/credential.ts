import type { CapabilityCredential, PublicJwk } from "@2key/dp-spec";
import { CompactSign, compactVerify, importJWK } from "jose";

type UnsignedCredential = Omit<CapabilityCredential, "signature">;

function canonicalPayload(credential: UnsignedCredential): Uint8Array {
  const ordered = {
    version: credential.version,
    kind: credential.kind,
    entityId: credential.entityId,
    ski: credential.ski,
    publicJwk: credential.publicJwk,
    permissions: credential.permissions,
    zone: credential.zone ?? null,
    host: credential.host ?? null,
    issuerSki: credential.issuerSki,
    notBefore: credential.notBefore,
    notAfter: credential.notAfter,
    package: credential.package ?? null,
  };
  return new TextEncoder().encode(JSON.stringify(ordered));
}

export async function verifyCredentialSignature(
  credential: CapabilityCredential,
  issuerPublicJwk: PublicJwk,
): Promise<boolean> {
  try {
    const key = await importJWK(issuerPublicJwk, "EdDSA");
    const { payload } = await compactVerify(credential.signature, key);
    const expected = canonicalPayload(credential);
    if (payload.byteLength !== expected.byteLength) {
      return false;
    }
    for (let i = 0; i < expected.byteLength; i++) {
      if (payload[i] !== expected[i]) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

/** Attach platformCosign using a platform authority private key (tests / authority service). */
export async function attachPlatformCosign(
  credential: CapabilityCredential,
  platformPrivateJwk: Record<string, unknown>,
  platformKid: string,
): Promise<CapabilityCredential> {
  const signedAt = new Date().toISOString();
  const key = await importJWK(platformPrivateJwk, "EdDSA");
  const body = new TextEncoder().encode(
    JSON.stringify({
      ski: credential.ski,
      kind: credential.kind,
      entityId: credential.entityId,
      host: credential.host ?? null,
      signedAt,
    }),
  );
  const signature = await new CompactSign(body)
    .setProtectedHeader({ alg: "EdDSA", kid: platformKid })
    .sign(key);
  return {
    ...credential,
    platformCosign: { kid: platformKid, signedAt, signature },
  };
}

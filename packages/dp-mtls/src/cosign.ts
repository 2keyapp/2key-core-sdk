import type { PlatformCosign } from "@2key/dp-spec";
import * as x509 from "@peculiar/x509";
import { CompactSign, compactVerify, importJWK } from "jose";

/**
 * Platform authority co-signature over an issued client certificate.
 *
 * Returned as a standalone field (e.g. `DeviceEnrollResult.platformCertCosign`)
 * rather than embedded in the cert itself: the compact JWS payload commits to
 * the certificate's DER bytes (base64) plus a timestamp, so verifiers can
 * confirm "the platform attests to this exact certificate" without re-issuing
 * or mutating the X.509 structure.
 */
export async function attachPlatformCertCosign(
  certPem: string,
  platformPrivateJwk: Record<string, unknown>,
  kid: string,
): Promise<PlatformCosign> {
  const signedAt = new Date().toISOString();
  const key = await importJWK(platformPrivateJwk, "EdDSA");
  const certDerB64 = Buffer.from(new x509.X509Certificate(certPem).rawData).toString(
    "base64",
  );
  const body = new TextEncoder().encode(
    JSON.stringify({ certDerB64, signedAt }),
  );
  const signature = await new CompactSign(body)
    .setProtectedHeader({ alg: "EdDSA", kid })
    .sign(key);
  return { kid, signedAt, signature };
}

/** Verify a `attachPlatformCertCosign` JWS against the cert it claims to cover. */
export async function verifyPlatformCertCosign(
  certPem: string,
  cosign: PlatformCosign,
  platformPublicJwk: Record<string, unknown>,
): Promise<boolean> {
  try {
    const key = await importJWK(platformPublicJwk, "EdDSA");
    const { payload } = await compactVerify(cosign.signature, key);
    const certDerB64 = Buffer.from(
      new x509.X509Certificate(certPem).rawData,
    ).toString("base64");
    const expected = JSON.stringify({ certDerB64, signedAt: cosign.signedAt });
    return new TextDecoder().decode(payload) === expected;
  } catch {
    return false;
  }
}

import type { DeviceIdentity, MtlsClientMaterial } from "@2key/dp-presentation";
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import type { ConnectionOptions } from "node:tls";
import {
  ED25519,
  importEd25519PrivateKeyFromJwk,
  importEd25519PublicKeyFromJwk,
} from "./ed25519.js";

/** URI SAN value encoding the DP subject key id. */
export function skiSanUri(ski: string): string {
  return `urn:dp:ski:${ski}`;
}

/**
 * Build an mTLS client material from DeviceIdentity.
 * AuthN = TLS client cert (SKI in SAN); AuthZ = CapabilityCredential via presenter.
 *
 * If `identity.certPem` is set (issued by a CA via `signClientCertFromCsr`), it is
 * used as-is (chained with `identity.chainPem` when present). Otherwise a
 * self-signed dev certificate is minted from `identity.privateJwk` / `publicJwk`.
 */
export async function materializeMtlsClient(
  identity: DeviceIdentity,
): Promise<MtlsClientMaterial> {
  x509.cryptoProvider.set(webcrypto as Crypto);

  const { privateKey, keyPem } = await importEd25519PrivateKeyFromJwk(
    identity.privateJwk,
  );

  if (typeof identity.certPem === "string" && identity.certPem.length > 0) {
    return {
      certPem: identity.chainPem ?? identity.certPem,
      ...(identity.chainPem !== undefined ? { chainPem: identity.chainPem } : {}),
      keyPem,
      ski: identity.ski,
      credential: identity.credential,
    };
  }

  const publicKey = await importEd25519PublicKeyFromJwk(identity.publicJwk);

  const notBefore = new Date();
  const notAfter = new Date(notBefore.getTime() + 365 * 24 * 60 * 60 * 1000);

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: Buffer.from(identity.ski.slice(0, 16), "utf8")
      .toString("hex")
      .slice(0, 16),
    name: `CN=${identity.ski}`,
    notBefore,
    notAfter,
    keys: { privateKey, publicKey },
    signingAlgorithm: ED25519,
    extensions: [
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyAgreement,
        true,
      ),
      new x509.ExtendedKeyUsageExtension(
        [x509.ExtendedKeyUsage.clientAuth],
        false,
      ),
      new x509.SubjectAlternativeNameExtension(
        [{ type: "url", value: skiSanUri(identity.ski) }],
        false,
      ),
    ],
  });

  return {
    certPem: cert.toString("pem"),
    keyPem,
    ski: identity.ski,
    credential: identity.credential,
  };
}

export type MtlsTrustOptions = {
  /** PEM CA bundle(s). When set, rejectUnauthorized defaults to true. */
  readonly ca?: string | readonly string[];
  readonly rejectUnauthorized?: boolean;
};

/** Map mTLS material to Node `tls.connect` / `https.Agent` options. */
export function toNodeTlsOptions(
  material: MtlsClientMaterial,
  trust?: MtlsTrustOptions,
): ConnectionOptions {
  const hasCa = trust?.ca !== undefined;
  return {
    cert: material.certPem,
    key: material.keyPem,
    ...(hasCa ? { ca: trust.ca as string | string[] } : {}),
    rejectUnauthorized: trust?.rejectUnauthorized ?? hasCa,
  };
}

/** Read urn:dp:ski:* from a PEM certificate, if present. */
export function extractSkiFromCertPem(certPem: string): string | null {
  const cert = new x509.X509Certificate(certPem);
  for (const ext of cert.extensions) {
    if (ext instanceof x509.SubjectAlternativeNameExtension) {
      for (const name of ext.names.items) {
        if (name.type === "url" && name.value.startsWith("urn:dp:ski:")) {
          return name.value.slice("urn:dp:ski:".length);
        }
      }
    }
  }
  return null;
}

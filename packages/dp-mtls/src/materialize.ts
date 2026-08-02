import type { DeviceIdentity, MtlsClientMaterial } from "@2key/dp-presentation";
import * as x509 from "@peculiar/x509";
import { webcrypto } from "node:crypto";
import type { ConnectionOptions } from "node:tls";

const ED25519 = { name: "Ed25519" } as const;

/** URI SAN value encoding the DP subject key id. */
export function skiSanUri(ski: string): string {
  return `urn:dp:ski:${ski}`;
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return Uint8Array.from(Buffer.from(padded + pad, "base64"));
}

/** PKCS#8 PrivateKeyInfo for Ed25519 (RFC 8410). */
function ed25519Pkcs8DerFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.byteLength !== 32) {
    throw new Error("Ed25519 private seed must be 32 bytes");
  }
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return Buffer.concat([prefix, Buffer.from(seed)]);
}

function derToPem(label: string, der: Uint8Array): string {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/**
 * Build a self-signed Ed25519 client cert from DeviceIdentity.
 * AuthN = TLS client cert (SKI in SAN); AuthZ = CapabilityCredential via presenter.
 */
export async function materializeMtlsClient(
  identity: DeviceIdentity,
): Promise<MtlsClientMaterial> {
  x509.cryptoProvider.set(webcrypto as Crypto);

  const d = identity.privateJwk.d;
  if (typeof d !== "string") {
    throw new Error("privateJwk.d (Ed25519 seed) is required");
  }
  const seed = base64UrlToBytes(d);
  const pkcs8Der = ed25519Pkcs8DerFromSeed(seed);
  const keyPem = derToPem("PRIVATE KEY", pkcs8Der);

  const privateKey = await webcrypto.subtle.importKey(
    "pkcs8",
    pkcs8Der,
    ED25519,
    true,
    ["sign"],
  );

  let publicKey: CryptoKey;
  if (typeof identity.publicJwk.x === "string") {
    // SPKI for Ed25519: 12-byte header + 32-byte raw public key
    const raw = base64UrlToBytes(identity.publicJwk.x);
    if (raw.byteLength !== 32) {
      throw new Error("Ed25519 public key must be 32 bytes");
    }
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const spki = Buffer.concat([spkiPrefix, Buffer.from(raw)]);
    publicKey = await webcrypto.subtle.importKey(
      "spki",
      spki,
      ED25519,
      true,
      ["verify"],
    );
  } else {
    throw new Error("publicJwk.x is required");
  }

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

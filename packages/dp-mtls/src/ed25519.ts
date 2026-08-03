import { createHash, randomBytes, webcrypto } from "node:crypto";
import type { PublicJwk } from "@2key/dp-spec";

/** WebCrypto algorithm identifier shared by all Ed25519 operations in this package. */
export const ED25519 = { name: "Ed25519" } as const;

export function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  return Uint8Array.from(Buffer.from(padded + pad, "base64"));
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** PKCS#8 PrivateKeyInfo for Ed25519 (RFC 8410). */
export function ed25519Pkcs8DerFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.byteLength !== 32) {
    throw new Error("Ed25519 private seed must be 32 bytes");
  }
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return Buffer.concat([prefix, Buffer.from(seed)]);
}

/** SubjectPublicKeyInfo for Ed25519 (RFC 8410). */
export function ed25519SpkiDerFromRaw(raw: Uint8Array): Uint8Array {
  if (raw.byteLength !== 32) {
    throw new Error("Ed25519 public key must be 32 bytes");
  }
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return Buffer.concat([prefix, Buffer.from(raw)]);
}

export function derToPem(label: string, der: Uint8Array): string {
  const b64 = Buffer.from(der).toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/** Derive the DP subject key id from a public JWK (must match `@2key/dp-ts` `skiFromPublicJwk`). */
export function skiFromPublicJwk(publicJwk: PublicJwk): string {
  const material = JSON.stringify({
    kty: publicJwk.kty,
    crv: publicJwk.crv,
    x: publicJwk.x,
  });
  return createHash("sha256").update(material).digest("hex").slice(0, 32);
}

/** Import an Ed25519 private key from a JWK (`d` seed) as a signing CryptoKey + PKCS8 PEM. */
export async function importEd25519PrivateKeyFromJwk(
  privateJwk: Record<string, unknown>,
): Promise<{ privateKey: CryptoKey; keyPem: string }> {
  const d = (privateJwk as { d?: unknown }).d;
  if (typeof d !== "string") {
    throw new Error("privateJwk.d (Ed25519 seed) is required");
  }
  const seed = base64UrlToBytes(d);
  const pkcs8Der = ed25519Pkcs8DerFromSeed(seed);
  const privateKey = await webcrypto.subtle.importKey(
    "pkcs8",
    pkcs8Der,
    ED25519,
    true,
    ["sign"],
  );
  return { privateKey, keyPem: derToPem("PRIVATE KEY", pkcs8Der) };
}

/** Import an Ed25519 public key from a JWK (`x` raw point) as a verify CryptoKey. */
export async function importEd25519PublicKeyFromJwk(
  publicJwk: PublicJwk,
): Promise<CryptoKey> {
  if (typeof publicJwk.x !== "string") {
    throw new Error("publicJwk.x is required");
  }
  const raw = base64UrlToBytes(publicJwk.x);
  const spkiDer = ed25519SpkiDerFromRaw(raw);
  return webcrypto.subtle.importKey("spki", spkiDer, ED25519, true, ["verify"]);
}

export type GeneratedEd25519KeyPair = {
  readonly privateKey: CryptoKey;
  readonly publicKey: CryptoKey;
  readonly privateJwk: Record<string, unknown>;
  readonly publicJwk: PublicJwk;
  readonly ski: string;
};

/** Generate a fresh Ed25519 keypair. Private key material never leaves this process. */
export async function generateEd25519KeyPair(): Promise<GeneratedEd25519KeyPair> {
  const { privateKey, publicKey } = (await webcrypto.subtle.generateKey(
    ED25519,
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const privateJwkRaw = (await webcrypto.subtle.exportKey(
    "jwk",
    privateKey,
  )) as Record<string, unknown>;
  const publicJwkRaw = (await webcrypto.subtle.exportKey(
    "jwk",
    publicKey,
  )) as PublicJwk;
  const ski = skiFromPublicJwk(publicJwkRaw);
  return {
    privateKey,
    publicKey,
    privateJwk: { ...privateJwkRaw, kid: ski, alg: "EdDSA" },
    publicJwk: { ...publicJwkRaw, kid: ski, alg: "EdDSA" },
    ski,
  };
}

/** Random hexadecimal serial number suitable for `X509Certificate` generation. */
export function randomSerialHex(bytes = 16): string {
  return randomBytes(bytes).toString("hex");
}

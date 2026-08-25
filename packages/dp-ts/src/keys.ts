import { randomBytes } from "node:crypto";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK } from "jose";
import type { PublicJwk } from "@2key/dp-spec";

export type KeyPairMaterial = {
  readonly ski: string;
  readonly publicJwk: PublicJwk;
  readonly privateJwk: Record<string, unknown>;
};

/** Canonical SKI: RFC 7638 JWK thumbprint. Matches better-auth `bindCsrToPublicJwk`. */
async function skiFromPublicJwk(publicJwk: PublicJwk): Promise<string> {
  const { d: _d, ...pub } = publicJwk as PublicJwk & { d?: unknown };
  return calculateJwkThumbprint(pub, "sha256");
}

/** Generate an Ed25519 keypair for Admin or Device subject use. Keys stay client-side. */
export async function generateEd25519KeyPair(): Promise<KeyPairMaterial> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  const publicJwk = (await exportJWK(publicKey)) as PublicJwk;
  const privateJwk = (await exportJWK(privateKey)) as Record<string, unknown>;
  const ski = await skiFromPublicJwk(publicJwk);
  return {
    ski,
    publicJwk: { ...publicJwk, kid: ski, alg: "EdDSA" },
    privateJwk: { ...privateJwk, kid: ski, alg: "EdDSA" },
  };
}

export async function importPublicKey(publicJwk: PublicJwk) {
  return importJWK(publicJwk, "EdDSA");
}

/** Opaque local id helper for demos (not a SKI). */
export function randomLocalId(bytes = 8): string {
  return randomBytes(bytes).toString("hex");
}

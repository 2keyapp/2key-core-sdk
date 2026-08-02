import { createHash, randomBytes } from "node:crypto";
import { exportJWK, generateKeyPair, importJWK } from "jose";
import type { PublicJwk } from "@2key/dp-spec";

export type KeyPairMaterial = {
  readonly ski: string;
  readonly publicJwk: PublicJwk;
  readonly privateJwk: Record<string, unknown>;
};

function skiFromPublicJwk(publicJwk: PublicJwk): string {
  const material = JSON.stringify({
    kty: publicJwk.kty,
    crv: publicJwk.crv,
    x: publicJwk.x,
  });
  return createHash("sha256").update(material).digest("hex").slice(0, 32);
}

/** Generate an Ed25519 keypair for Admin or Device subject use. Keys stay client-side. */
export async function generateEd25519KeyPair(): Promise<KeyPairMaterial> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  const publicJwk = (await exportJWK(publicKey)) as PublicJwk;
  const privateJwk = (await exportJWK(privateKey)) as Record<string, unknown>;
  const ski = skiFromPublicJwk(publicJwk);
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

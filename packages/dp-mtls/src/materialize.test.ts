import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { DeviceIdentity } from "@2key/dp-presentation";
import { generateKeyPair, exportJWK } from "jose";
import { createHash } from "node:crypto";
import {
  extractSkiFromCertPem,
  materializeMtlsClient,
  skiSanUri,
  toNodeTlsOptions,
} from "./materialize.js";

async function testIdentity(): Promise<DeviceIdentity> {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", {
    crv: "Ed25519",
    extractable: true,
  });
  const publicJwk = (await exportJWK(publicKey)) as DeviceIdentity["publicJwk"];
  const privateJwk = (await exportJWK(privateKey)) as Record<string, unknown>;
  const ski = createHash("sha256")
    .update(
      JSON.stringify({
        kty: publicJwk.kty,
        crv: publicJwk.crv,
        x: publicJwk.x,
      }),
    )
    .digest("hex")
    .slice(0, 32);

  return {
    ski,
    publicJwk: { ...publicJwk, kid: ski, alg: "EdDSA" },
    privateJwk: { ...privateJwk, kid: ski, alg: "EdDSA" },
    credential: {
      version: 1,
      kind: "machine",
      entityId: "acme.example",
      ski,
      publicJwk: { ...publicJwk, kid: ski, alg: "EdDSA" },
      permissions: [
        {
          action: "machine.connect",
          scope: { name: "db1" },
          delegable: false,
        },
      ],
      host: "db1--acme.example",
      issuerSki: "issuer",
      notBefore: new Date().toISOString(),
      notAfter: new Date(Date.now() + 86400000).toISOString(),
      signature: "hdr.payload.sig",
    },
  };
}

describe("materializeMtlsClient", () => {
  it("embeds ski in SAN and produces Node tls options", async () => {
    const identity = await testIdentity();
    const material = await materializeMtlsClient(identity);
    assert.equal(material.ski, identity.ski);
    assert.match(material.certPem, /BEGIN CERTIFICATE/);
    assert.match(material.keyPem, /BEGIN PRIVATE KEY/);
    assert.equal(extractSkiFromCertPem(material.certPem), identity.ski);
    assert.equal(skiSanUri(identity.ski), `urn:dp:ski:${identity.ski}`);

    const opts = toNodeTlsOptions(material, {
      ca: material.certPem,
    });
    assert.equal(opts.cert, material.certPem);
    assert.equal(opts.key, material.keyPem);
    assert.equal(opts.rejectUnauthorized, true);
  });
});

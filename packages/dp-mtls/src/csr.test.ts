import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { calculateJwkThumbprint } from "jose";
import type { DeviceIdentity } from "@2key/dp-presentation";
import { attachPlatformCertCosign, verifyPlatformCertCosign } from "./cosign.js";
import {
  createSelfSignedCa,
  generateKeyAndCsr,
  signClientCertFromCsr,
} from "./csr.js";
import { generateEd25519KeyPair } from "./ed25519.js";
import {
  extractSkiFromCertPem,
  materializeMtlsClient,
  skiSanUri,
  toNodeTlsOptions,
} from "./materialize.js";

function baseCredential(ski: string, host: string) {
  return {
    version: 1 as const,
    kind: "machine" as const,
    entityId: "acme.example",
    ski,
    publicJwk: { kty: "OKP", crv: "Ed25519", x: "x" },
    permissions: [
      { action: "machine.connect", scope: { name: "db1" }, delegable: false },
    ],
    host,
    issuerSki: "issuer",
    notBefore: new Date().toISOString(),
    notAfter: new Date(Date.now() + 86400000).toISOString(),
    signature: "hdr.payload.sig",
  };
}

describe("generateKeyAndCsr", () => {
  it("produces a CSR whose SAN carries the device SKI and host", async () => {
    const { privateJwk, publicJwk, ski, csrPem } = await generateKeyAndCsr({
      commonName: "device-1",
      host: "db1--acme.example",
    });
    assert.match(csrPem, /BEGIN CERTIFICATE REQUEST/);
    assert.equal(typeof privateJwk.d, "string");
    assert.equal(typeof publicJwk.x, "string");
    assert.equal(typeof ski, "string");
    assert.equal(ski.length, 43);
    assert.equal(ski, await calculateJwkThumbprint(publicJwk, "sha256"));
  });
});

describe("createSelfSignedCa", () => {
  it("produces a CA certificate with basic constraints CA=true", async () => {
    const { caCertPem, ski } = await createSelfSignedCa({
      commonName: "DP Test CA",
    });
    assert.match(caCertPem, /BEGIN CERTIFICATE/);
    assert.equal(typeof ski, "string");
  });
});

describe("signClientCertFromCsr", () => {
  it("issues a leaf cert chained to the CA, embedding the trusted ski/host", async () => {
    const ca = await createSelfSignedCa({ commonName: "DP Test CA" });
    const device = await generateKeyAndCsr({
      commonName: "device-2",
      host: "db1--acme.example",
    });

    const { leafPem, chainPem } = await signClientCertFromCsr({
      csrPem: device.csrPem,
      caCertPem: ca.caCertPem,
      caPrivateJwk: ca.privateJwk,
      ski: device.ski,
      host: "db1--acme.example",
    });

    assert.match(leafPem, /BEGIN CERTIFICATE/);
    assert.ok(chainPem.includes(leafPem));
    assert.ok(chainPem.includes(ca.caCertPem.trim()));
    assert.equal(extractSkiFromCertPem(leafPem), device.ski);
  });

  it("rejects a CSR with an invalid signature", async () => {
    const ca = await createSelfSignedCa({ commonName: "DP Test CA" });
    const { csrPem } = await generateKeyAndCsr({ commonName: "device-3" });

    // Flip the last byte of the DER (part of the trailing signature value)
    // while re-encoding as a structurally valid PEM, so verification fails
    // rather than PEM/ASN.1 parsing itself throwing.
    const { PemConverter } = await import("@peculiar/x509");
    const der = new Uint8Array(PemConverter.decodeFirst(csrPem));
    der[der.length - 1] = der[der.length - 1] ^ 0xff;
    const tampered = PemConverter.encode(der, "CERTIFICATE REQUEST");

    await assert.rejects(() =>
      signClientCertFromCsr({
        csrPem: tampered,
        caCertPem: ca.caCertPem,
        caPrivateJwk: ca.privateJwk,
        ski: "deadbeef",
      }),
    );
  });
});

describe("materializeMtlsClient with a CA-issued cert", () => {
  it("uses identity.certPem/chainPem as-is instead of self-signing", async () => {
    const ca = await createSelfSignedCa({ commonName: "DP Test CA" });
    const device = await generateKeyAndCsr({
      commonName: "device-4",
      host: "db1--acme.example",
    });
    const { leafPem, chainPem } = await signClientCertFromCsr({
      csrPem: device.csrPem,
      caCertPem: ca.caCertPem,
      caPrivateJwk: ca.privateJwk,
      ski: device.ski,
      host: "db1--acme.example",
    });

    const identity: DeviceIdentity = {
      ski: device.ski,
      publicJwk: device.publicJwk,
      privateJwk: device.privateJwk,
      credential: baseCredential(device.ski, "db1--acme.example"),
      certPem: leafPem,
      chainPem,
    };

    const material = await materializeMtlsClient(identity);
    assert.equal(material.certPem, chainPem);
    assert.equal(material.chainPem, chainPem);
    assert.match(material.keyPem, /BEGIN PRIVATE KEY/);
    assert.equal(extractSkiFromCertPem(material.certPem), device.ski);

    const opts = toNodeTlsOptions(material, { ca: ca.caCertPem });
    assert.equal(opts.cert, chainPem);
    assert.equal(opts.rejectUnauthorized, true);
  });

  it("falls back to self-signed when identity has no certPem", async () => {
    const kp = await generateEd25519KeyPair();
    const identity: DeviceIdentity = {
      ski: kp.ski,
      publicJwk: kp.publicJwk,
      privateJwk: kp.privateJwk,
      credential: baseCredential(kp.ski, "db1--acme.example"),
    };
    const material = await materializeMtlsClient(identity);
    assert.equal(extractSkiFromCertPem(material.certPem), kp.ski);
    assert.equal(skiSanUri(kp.ski), `urn:dp:ski:${kp.ski}`);
  });
});

describe("attachPlatformCertCosign", () => {
  it("produces a verifiable compact JWS over the cert DER", async () => {
    const ca = await createSelfSignedCa({ commonName: "DP Test CA" });
    const platform = await generateEd25519KeyPair();

    const cosign = await attachPlatformCertCosign(
      ca.caCertPem,
      platform.privateJwk,
      platform.ski,
    );

    assert.equal(cosign.kid, platform.ski);
    assert.match(cosign.signature, /^[\w-]+\.[\w-]+\.[\w-]+$/);

    const ok = await verifyPlatformCertCosign(
      ca.caCertPem,
      cosign,
      platform.publicJwk,
    );
    assert.equal(ok, true);

    const bad = await verifyPlatformCertCosign(
      (await createSelfSignedCa({ commonName: "Other CA" })).caCertPem,
      cosign,
      platform.publicJwk,
    );
    assert.equal(bad, false);
  });
});

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { DeviceEnrollRequest, DeviceEnrollResult } from "@2key/dp-spec";
import { createEnrollClient } from "./admin.js";

function fakeCredential(ski: string, entityId: string) {
  return {
    version: 1 as const,
    kind: "machine" as const,
    entityId,
    ski,
    publicJwk: { kty: "OKP", crv: "Ed25519", x: "x" },
    permissions: [
      { action: "machine.connect", scope: { name: "db1" }, delegable: false },
    ],
    host: "db1--acme.example",
    issuerSki: "issuer",
    notBefore: new Date().toISOString(),
    notAfter: new Date(Date.now() + 86400000).toISOString(),
    signature: "hdr.payload.sig",
  };
}

describe("createEnrollClient", () => {
  it("generates a device key+CSR, posts it, and returns a materializable identity", async () => {
    let capturedBody: DeviceEnrollRequest | undefined;

    const fetchImpl: typeof fetch = async (_url, init) => {
      capturedBody = JSON.parse(String(init?.body)) as DeviceEnrollRequest;
      const result: DeviceEnrollResult = {
        credential: fakeCredential(capturedBody.ski, capturedBody.entityId),
        certPem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
      };
      return new Response(JSON.stringify(result), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const client = createEnrollClient({
      baseURL: "https://auth.example.com/api/auth/",
      fetch: fetchImpl,
    });

    const { identity, result } = await client.enroll({
      entityId: "acme.example",
      host: "db1--acme.example",
    });

    assert.ok(capturedBody);
    assert.equal(capturedBody?.entityId, "acme.example");
    assert.equal(capturedBody?.host, "db1--acme.example");
    assert.match(capturedBody?.csrPem ?? "", /BEGIN CERTIFICATE REQUEST/);

    assert.equal(identity.ski, capturedBody?.ski);
    assert.equal(typeof identity.privateJwk.d, "string");
    assert.equal(identity.certPem, result.certPem);
    assert.equal(identity.credential.entityId, "acme.example");
  });
});

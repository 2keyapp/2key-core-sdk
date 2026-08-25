import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { generateEd25519KeyPair } from "./keys.js";

describe("generateEd25519KeyPair", () => {
  it("returns ski + public/private jwks", async () => {
    const kp = await generateEd25519KeyPair();
    assert.equal(typeof kp.ski, "string");
    assert.ok(kp.ski.length >= 16);
    assert.equal(kp.ski.length, 43);
    assert.equal(kp.publicJwk.kty, "OKP");
    assert.equal(kp.publicJwk.crv, "Ed25519");
    assert.ok(kp.privateJwk.d);
  });
});

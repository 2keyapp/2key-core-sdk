import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createInBandCredentialPresenter,
  parseDpCredentialFrame,
} from "./in-band.js";
import type { DeviceIdentity, PepSession } from "./types.js";
import { DP_CREDENTIAL_FRAME_TYPE } from "./types.js";

function mockSession(): PepSession & { frames: Uint8Array[] } {
  const frames: Uint8Array[] = [];
  return {
    frames,
    async send(frame) {
      frames.push(frame);
    },
    onFrame() {
      return () => {};
    },
    async close() {},
  };
}

const identity = {
  ski: "ski-abc",
  publicJwk: { kty: "OKP", crv: "Ed25519", x: "x" },
  privateJwk: { kty: "OKP", crv: "Ed25519", x: "x", d: "d" },
  credential: {
    version: 1 as const,
    kind: "machine" as const,
    entityId: "acme.example",
    ski: "ski-abc",
    publicJwk: { kty: "OKP", crv: "Ed25519", x: "x" },
    permissions: [
      {
        action: "machine.connect",
        scope: { name: "db1" },
        delegable: false,
      },
    ],
    host: "db1--acme.example",
    issuerSki: "issuer",
    notBefore: "2026-01-01T00:00:00.000Z",
    notAfter: "2027-01-01T00:00:00.000Z",
    signature: "hdr.payload.sig",
  },
} satisfies DeviceIdentity;

describe("createInBandCredentialPresenter", () => {
  it("sends a dp.credential.v1 frame", async () => {
    const session = mockSession();
    await createInBandCredentialPresenter().present(session, identity);
    assert.equal(session.frames.length, 1);
    const parsed = parseDpCredentialFrame(session.frames[0]!);
    assert.ok(parsed);
    assert.equal(parsed.type, DP_CREDENTIAL_FRAME_TYPE);
    assert.equal(parsed.credential.ski, "ski-abc");
  });
});

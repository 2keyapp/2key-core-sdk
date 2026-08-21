import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { DeviceEnrollRequest, EnrollCreateResult } from "@2key/dp-spec";
import { createAdminClient, createEnrollClient } from "./admin.js";

describe("createEnrollClient", () => {
  it("generates a device key+CSR, posts enroll-create, and returns local material", async () => {
    let capturedUrl = "";
    let capturedBody: DeviceEnrollRequest | undefined;

    const fetchImpl: typeof fetch = async (url, init) => {
      capturedUrl = String(url);
      capturedBody = JSON.parse(String(init?.body)) as DeviceEnrollRequest;
      const result: EnrollCreateResult = {
        enrollId: "enr_1",
        pullToken: "pull_1",
        subjectSki: capturedBody.subjectSki ?? "",
        kind: "machine_target",
        status: "pending",
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

    const enrolled = await client.enroll({
      entityId: "acme.example",
      host: "db1--acme.example",
    });

    assert.ok(capturedBody);
    assert.match(capturedUrl, /\/delegate-permissions\/enroll-create$/);
    assert.equal(capturedBody?.entityId, "acme.example");
    assert.equal(capturedBody?.host, "db1--acme.example");
    assert.equal(capturedBody?.subjectSki, enrolled.ski);
    assert.match(capturedBody?.csrPem ?? "", /BEGIN CERTIFICATE REQUEST/);
    assert.equal(enrolled.ski.length, 43);
    assert.equal(typeof enrolled.privateJwk.d, "string");
    assert.equal(enrolled.enrollment.status, "pending");
    assert.equal(enrolled.enrollment.enrollId, "enr_1");
    assert.equal(enrolled.identity, undefined);
  });
});

describe("createAdminClient lifecycle", () => {
  it("calls credential/machine/enroll lifecycle endpoints", async () => {
    const seen: { method: string; url: string; body: unknown }[] = [];
    const fetchImpl: typeof fetch = async (url, init) => {
      seen.push({
        method: String(init?.method ?? "GET"),
        url: String(url),
        body: init?.body ? JSON.parse(String(init.body)) : undefined,
      });
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };

    const admin = createAdminClient({
      baseURL: "https://auth.example.com/api/auth/",
      fetch: fetchImpl,
    });

    await admin.credentialRevoke({ ski: "abc", reason: "key_compromise" });
    await admin.credentialStatus({ ski: "abc" });
    await admin.credentialList({ entityId: "acme.example", status: "active" });
    await admin.machineDecommission({ ski: "abc" });
    await admin.machineRenew({
      ski: "abc",
      csrPem: "csr",
      leafPem: "leaf",
      chainPem: "chain",
      credential: { version: 1 } as never,
      issuerSki: "iss",
    });
    await admin.enrollList({ entityId: "acme.example" });
    await admin.enrollReject({ enrollId: "enr_1" });
    await admin.issueDelegate({
      entityId: "acme.example",
      kind: "interim_admin",
      issuerPrivateJwk: { kty: "OKP" },
      issuerSki: "iss",
    });
    await admin.issueMachine({
      entityId: "acme.example",
      host: "db1--acme.example",
      issuerPrivateJwk: { kty: "OKP" },
      issuerSki: "iss",
    });

    const paths = seen.map((s) => `${s.method} ${new URL(s.url).pathname}`);
    assert.deepEqual(paths, [
      "POST /delegate-permissions/credential-revoke",
      "GET /delegate-permissions/credential-status",
      "GET /delegate-permissions/credential-list",
      "POST /delegate-permissions/machine-decommission",
      "POST /delegate-permissions/machine-renew",
      "GET /delegate-permissions/enroll-list",
      "POST /delegate-permissions/enroll-reject",
      "POST /delegate-permissions/issue-delegate",
      "POST /delegate-permissions/issue-machine",
    ]);
    const statusCall = seen[1];
    const revokeCall = seen[0];
    assert.ok(statusCall);
    assert.ok(revokeCall);
    assert.equal(new URL(statusCall.url).searchParams.get("ski"), "abc");
    assert.equal(
      (revokeCall.body as { reason: string }).reason,
      "key_compromise",
    );
  });
});

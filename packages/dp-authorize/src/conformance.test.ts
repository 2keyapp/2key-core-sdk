import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { actionCovers } from "./action.js";
import { authorize } from "./authorize.js";
import { enforceLocally } from "./enforce.js";
import { dnsPrefixSubset } from "./scope.js";
import { assertSubset } from "./subset.js";
import type { CapabilitySet, Catalog, Resource } from "./types.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(
  here,
  "../../../conformance/dp-authz/fixtures.json",
);

type Fixtures = {
  catalog: Catalog;
  actionCovers: { granted: string; requested: string; ok: boolean }[];
  dnsPrefixSubset: { child: string; parent: string; ok: boolean }[];
  authorize: {
    name: string;
    grants: CapabilitySet;
    action: string;
    resource: Resource;
    ok: boolean;
    code?: string;
  }[];
  assertSubset: {
    name: string;
    parent: CapabilitySet;
    child: CapabilitySet;
    ok: boolean;
    code?: string;
  }[];
};

const fixtures = JSON.parse(readFileSync(fixturesPath, "utf8")) as Fixtures;

describe("conformance fixtures", () => {
  for (const row of fixtures.actionCovers) {
    it(`actionCovers ${row.granted} → ${row.requested}`, () => {
      assert.equal(actionCovers(row.granted, row.requested), row.ok);
    });
  }

  for (const row of fixtures.dnsPrefixSubset) {
    it(`dnsPrefixSubset ${row.child} ⊆ ${row.parent}`, () => {
      assert.equal(dnsPrefixSubset(row.child, row.parent), row.ok);
    });
  }

  for (const row of fixtures.authorize) {
    it(`authorize: ${row.name}`, () => {
      const result = authorize(
        row.grants,
        row.action,
        row.resource,
        fixtures.catalog,
      );
      assert.equal(result.ok, row.ok);
      if (!row.ok && !result.ok && row.code) {
        assert.equal(result.code, row.code);
      }
    });
  }

  for (const row of fixtures.assertSubset) {
    it(`assertSubset: ${row.name}`, () => {
      const result = assertSubset(row.child, row.parent, fixtures.catalog);
      assert.equal(result.ok, row.ok);
      if (!row.ok && !result.ok && row.code) {
        assert.equal(result.code, row.code);
      }
    });
  }
});

describe("enforceLocally", () => {
  it("rejects catalog generation mismatch", () => {
    const result = enforceLocally({
      grants: [
        {
          action: "machine.connect",
          scope: { name: "us-east" },
          delegable: false,
        },
      ],
      action: "machine.connect",
      resource: { name: "us-east" },
      catalog: fixtures.catalog,
      credentialCatalogGeneration: 99,
    });
    assert.equal(result.ok, false);
    if (!result.ok) {
      assert.equal(result.code, "CATALOG_GENERATION_MISMATCH");
    }
  });
});

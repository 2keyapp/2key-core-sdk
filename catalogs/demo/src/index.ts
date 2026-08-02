import type { CatalogSeed, CapabilitySet } from "@2key/dp-spec";

export const SERVICE_ID = "demo";
/** @deprecated Prefer SERVICE_ID */
export const DEMO_SERVICE_ID = SERVICE_ID;

const rootAdminPermissions: CapabilitySet = [
  { action: "admin.invite", scope: {}, delegable: true },
  { action: "cert.issue", scope: { name: "" }, delegable: true },
  { action: "zone.ns", scope: { name: "" }, delegable: true },
  { action: "zone.delegate", scope: { name: "" }, delegable: true },
  { action: "machine.bind", scope: { name: "" }, delegable: true },
  { action: "machine.connect", scope: { name: "" }, delegable: true },
  { action: "seat.bind", scope: {}, delegable: true },
  { action: "resource.access", scope: { service: ["*"] }, delegable: true },
  { action: "entity.read", scope: {}, delegable: true },
];

const machinePermissions: CapabilitySet = [
  { action: "machine.bind", scope: { name: "" }, delegable: false },
  { action: "machine.connect", scope: { name: "" }, delegable: false },
  { action: "resource.access", scope: { service: ["*"] }, delegable: false },
];

/** Example hierarchical-host seed for local/dev. */
export const CATALOG_SEED: CatalogSeed = {
  serviceId: SERVICE_ID,
  actions: [
    { action: "admin.invite", description: "Create interim admin identity" },
    { action: "cert.issue", description: "Sign downstream credentials" },
    { action: "zone.ns", description: "Occupy a zone name as ZA" },
    { action: "zone.delegate", description: "Create child zone under scope" },
    { action: "machine.bind", description: "Occupy leaf host as Machine" },
    { action: "machine.connect", description: "Act as a machine peer" },
    { action: "seat.bind", description: "Bind permanent machine seat" },
    { action: "resource.access", description: "Access named resources" },
    { action: "entity.read", description: "Read entity control-plane data" },
  ],
  scopeDimensions: [
    { dimension: "entity", algebra: "exact" },
    { dimension: "name", algebra: "dns_prefix" },
    { dimension: "seat", algebra: "exact" },
    { dimension: "service", algebra: "set" },
  ],
  profiles: [
    { profile: "root_admin", permissions: rootAdminPermissions },
    { profile: "machine", permissions: machinePermissions },
  ],
};

/** @deprecated Prefer CATALOG_SEED */
export const DEMO_CATALOG_SEED = CATALOG_SEED;

import type { CapabilitySet, CatalogSeed } from "@2key/dp-spec";

/**
 * Stable serviceId / tenant slug for IDR.
 * Wire: `delegatePermissions({ serviceId: SERVICE_ID, seed: CATALOG_SEED })`
 */
export const SERVICE_ID = "idr";

/**
 * IDR naming (FQHN hierarchy, DNS-like attenuation):
 *
 * - Entity apex is the right-hand identity (e.g. `acme.idr.to` or entity id).
 * - Zones / machines occupy names under that apex with `dns_prefix` algebra:
 *   child name is equal to parent or a leftward label extension (`db1.us-east` under `us-east`).
 * - Wire host forms used by Presence today: classic FQHN (`cam1.acme.idr.to`) and/or
 *   DP host `{path}--{entity}`; PEPs canonicalize before AuthZ.
 * - A name is Zone Authority XOR Machine — never both (enforced at issue / occupancy).
 *
 * Presence PEP flow:
 * Target Agent → POST auth.idr.to `/api/auth/agent/token` (CapabilityCredential PoP)
 *   → JWT → Presence `register_target.entitlement_jwt` → JWKS verify + cached claims
 *   for register / ensure_relay / mint_turn / accept_session (no Billing WSS mux).
 * CapabilityCredential + optional client cert still AuthN the device / mTLS path. *
 * Packages (see BILLING_PACKAGES.md):
 * - Personal: Source mTLS required; same-entity AuthZ; single-label hosts; ≤5 Targets.
 * - Enterprise: Source mTLS; hierarchy / multi-admin / SCIM; ≤5 Targets.
 * - Service Provider: anonymous Sources allowed; per-Target seat + optional CNAME.
 * - Data Transfer: Target pays; bytes to+from Target on Relay/TURN; Sources not billed.
 */

const IDR_ACTIONS = [
  // --- Control-plane / PKI hierarchy ---
  { action: "admin.invite", description: "Create interim admin identity" },
  { action: "cert.issue", description: "Sign downstream capability credentials" },
  { action: "zone.ns", description: "Occupy a zone name as Zone Authority (ZA)" },
  {
    action: "zone.delegate",
    description: "Create a child zone under dns_prefix name scope",
  },
  {
    action: "machine.bind",
    description: "Occupy a leaf host name as Machine (Target) — exclusive vs ZA",
  },
  {
    action: "machine.connect",
    description: "Act as Source/Target peer under bound host name",
  },
  {
    action: "seat.bind",
    description: "Bind permanent machine seat in Billing to machine SKI + host",
  },
  { action: "entity.read", description: "Read entity control-plane metadata" },

  // --- Presence PEP (Target ↔ Presence QUIC/WSS) ---
  {
    action: "presence.register",
    description:
      "Register Target with Presence (register_target); requires client cert + capability",
  },
  {
    action: "presence.ensure_relay",
    description:
      "Allow Presence to push ensure_relay_connection / wake Target for Relay",
  },
  {
    action: "session.accept",
    description:
      "Accept inbound sessions (WebRTC / relay) as Target — Billing accept_session",
  },
  {
    action: "session.request",
    description:
      "Request a session to a Target as Source — Presence webrtc_session_request",
  },
  {
    action: "turn.mint",
    description: "Mint TURN credentials attributed to party pair + target FQHN",
  },

  // --- Target application ACL ---
  {
    action: "acl.service",
    description: "Open named Target services over tunnels / data channels",
  },

  // --- Custom domains ---
  {
    action: "domain.alias",
    description:
      "Bind customer CNAME alias → Target FQHN (Billing → Presence alias push)",
  },
] as const;

const IDR_SCOPE_DIMENSIONS = [
  { dimension: "entity", algebra: "exact" as const },
  /** Zone / machine path under entity — DNS-like leftward labels. */
  { dimension: "name", algebra: "dns_prefix" as const },
  { dimension: "seat", algebra: "exact" as const },
  /** Named Target services for acl.service. */
  { dimension: "service", algebra: "set" as const },
  /** Optional transport hint: relay | webrtc (set algebra). */
  { dimension: "transport", algebra: "set" as const },
] as const;

const rootAdminPermissions: CapabilitySet = [
  { action: "admin.invite", scope: {}, delegable: true },
  { action: "cert.issue", scope: { name: "" }, delegable: true },
  { action: "zone.ns", scope: { name: "" }, delegable: true },
  { action: "zone.delegate", scope: { name: "" }, delegable: true },
  { action: "machine.bind", scope: { name: "" }, delegable: true },
  { action: "machine.connect", scope: { name: "" }, delegable: true },
  { action: "seat.bind", scope: {}, delegable: true },
  { action: "entity.read", scope: {}, delegable: true },
  { action: "presence.register", scope: { name: "" }, delegable: true },
  { action: "presence.ensure_relay", scope: { name: "" }, delegable: true },
  { action: "session.accept", scope: { name: "" }, delegable: true },
  { action: "session.request", scope: { name: "" }, delegable: true },
  { action: "turn.mint", scope: { name: "" }, delegable: true },
  {
    action: "acl.service",
    scope: { service: ["*"], transport: ["relay", "webrtc"] },
    delegable: true,
  },
  { action: "domain.alias", scope: { name: "" }, delegable: true },
];

/** Personal package: no zone.delegate / admin.invite chain; machines under apex only. */
const personalRootPermissions: CapabilitySet = [
  { action: "cert.issue", scope: { name: "" }, delegable: true },
  { action: "machine.bind", scope: { name: "" }, delegable: true },
  { action: "machine.connect", scope: { name: "" }, delegable: true },
  { action: "seat.bind", scope: {}, delegable: true },
  { action: "entity.read", scope: {}, delegable: true },
  { action: "presence.register", scope: { name: "" }, delegable: true },
  { action: "presence.ensure_relay", scope: { name: "" }, delegable: true },
  { action: "session.accept", scope: { name: "" }, delegable: true },
  { action: "session.request", scope: { name: "" }, delegable: true },
  { action: "turn.mint", scope: { name: "" }, delegable: true },
  {
    action: "acl.service",
    scope: { service: ["*"], transport: ["relay", "webrtc"] },
    delegable: true,
  },
  { action: "domain.alias", scope: { name: "" }, delegable: true },
];

const interimAdminPermissions: CapabilitySet = [
  { action: "admin.invite", scope: {}, delegable: true },
  { action: "entity.read", scope: {}, delegable: true },
];

const zoneDelegatePermissions: CapabilitySet = [
  { action: "cert.issue", scope: { name: "" }, delegable: true },
  { action: "zone.ns", scope: { name: "" }, delegable: true },
  { action: "zone.delegate", scope: { name: "" }, delegable: true },
  { action: "machine.bind", scope: { name: "" }, delegable: true },
  { action: "machine.connect", scope: { name: "" }, delegable: true },
  { action: "seat.bind", scope: {}, delegable: true },
  { action: "entity.read", scope: {}, delegable: true },
  { action: "presence.register", scope: { name: "" }, delegable: true },
  { action: "presence.ensure_relay", scope: { name: "" }, delegable: true },
  { action: "session.accept", scope: { name: "" }, delegable: true },
  { action: "turn.mint", scope: { name: "" }, delegable: true },
  {
    action: "acl.service",
    scope: { service: ["*"], transport: ["relay", "webrtc"] },
    delegable: true,
  },
  { action: "domain.alias", scope: { name: "" }, delegable: true },
];

/**
 * Target Machine leaf — Presence registration + accept sessions.
 * Non-delegable; name scope narrowed to the bound host path at issue time.
 */
const machineTargetPermissions: CapabilitySet = [
  { action: "machine.bind", scope: { name: "" }, delegable: false },
  { action: "machine.connect", scope: { name: "" }, delegable: false },
  { action: "presence.register", scope: { name: "" }, delegable: false },
  { action: "presence.ensure_relay", scope: { name: "" }, delegable: false },
  { action: "session.accept", scope: { name: "" }, delegable: false },
  { action: "turn.mint", scope: { name: "" }, delegable: false },
  {
    action: "acl.service",
    scope: { service: ["*"], transport: ["relay", "webrtc"] },
    delegable: false,
  },
];

/**
 * Source Agent / browser Source — request sessions to Targets under name scope.
 */
const machineSourcePermissions: CapabilitySet = [
  { action: "machine.connect", scope: { name: "" }, delegable: false },
  { action: "session.request", scope: { name: "" }, delegable: false },
  { action: "turn.mint", scope: { name: "" }, delegable: false },
];

export const CATALOG_SEED: CatalogSeed = {
  serviceId: SERVICE_ID,
  actions: IDR_ACTIONS,
  scopeDimensions: IDR_SCOPE_DIMENSIONS,
  profiles: [
    { profile: "root_admin", permissions: rootAdminPermissions },
    { profile: "personal_root", permissions: personalRootPermissions },
    { profile: "interim_admin", permissions: interimAdminPermissions },
    { profile: "zone_delegate", permissions: zoneDelegatePermissions },
    { profile: "machine", permissions: machineTargetPermissions },
    { profile: "machine_source", permissions: machineSourcePermissions },
  ],
};

/** Map Presence entitlement JWT `actions[]` (and legacy mux action names) → catalog action. */
export const ENTITLEMENT_ACTION_MAP = {
  register: "presence.register",
  accept_session: "session.accept",
  ensure_relay: "presence.ensure_relay",
  mint_turn: "turn.mint",
} as const;

/** Commercial package codes seeded in Billing `040_idr_packages.sql`. */
export const IDR_PLAN_CODES = {
  personalBundle: "idr_personal_bundle",
  enterpriseBundle: "idr_enterprise_bundle",
  serviceProviderTarget: "idr_sp_target",
  dataTransfer1Tb: "idr_data_transfer_1tb",
} as const;

/** Usage meters (Target pays; to+from Target). */
export const IDR_METERS = {
  relayBytes: "idr.relay.bytes",
  turnBytes: "idr.turn.bytes",
} as const;

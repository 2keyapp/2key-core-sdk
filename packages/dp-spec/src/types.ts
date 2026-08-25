export type ScopeValue = string | readonly string[];

export type Scope = Readonly<Record<string, ScopeValue>>;

export type Capability = {
  readonly action: string;
  readonly scope: Scope;
  readonly delegable: boolean;
};

export type CapabilitySet = readonly Capability[];

export type CredentialKind =
  | "entity_root"
  | "root_admin"
  | "interim_admin"
  | "zone_authority"
  | "machine";

export type EntityPackage = "personal" | "enterprise";

export type PublicJwk = {
  readonly kty: string;
  readonly crv?: string;
  readonly x?: string;
  readonly d?: never;
  readonly kid?: string;
  readonly alg?: string;
};

/** Platform authority co-sign block (separate from issuer signature). */
export type PlatformCosign = {
  readonly kid: string;
  readonly signedAt: string;
  readonly signature: string;
};

/**
 * Wire format for Option B capability credentials.
 * Aligns with Better Auth `delegate-permissions` plugin.
 */
export type CapabilityCredential = {
  readonly version: 1;
  readonly kind: CredentialKind;
  readonly entityId: string;
  readonly ski: string;
  readonly publicJwk: PublicJwk;
  readonly permissions: CapabilitySet;
  readonly zone?: string;
  readonly host?: string;
  readonly issuerSki: string;
  readonly notBefore: string;
  readonly notAfter: string;
  readonly package?: EntityPackage;
  readonly platformCosign?: PlatformCosign;
  readonly signature: string;
};

/**
 * Wire response for a device/machine enrollment or kickstart call.
 * `certPem`/`chainPem` are Entity-CA materials; `platformCertPem` /
 * `platformRootPem` are Platform CA X.509 endorsements issued after Entity
 * admin signs the leaf. Legacy `platformCertCosign` (detached JWS) may still
 * appear on older servers.
 */
export type DeviceEnrollResult = {
  readonly credential: CapabilityCredential;
  /** PEM leaf certificate issued by the Entity CA, if any. */
  readonly certPem?: string;
  /** PEM chain (leaf + Entity CA), if any. */
  readonly chainPem?: string;
  /** Platform CA X.509 endorsement for the same device SPKI. */
  readonly platformCertPem?: string;
  /** Platform self-signed Root CA PEM. */
  readonly platformRootPem?: string;
  /**
   * @deprecated Detached JWS cosign — prefer `platformCertPem` /
   * `platformRootPem`.
   */
  readonly platformCertCosign?: PlatformCosign;
};

export type ActionDef = {
  readonly action: string;
  readonly description?: string;
};

export type ScopeDimensionDef = {
  readonly dimension: string;
  readonly algebra: "exact" | "dns_prefix" | "set";
};

export type ProfileDef = {
  readonly profile: string;
  readonly permissions: CapabilitySet;
};

export type CatalogSeed = {
  readonly serviceId: string;
  readonly actions: readonly ActionDef[];
  readonly scopeDimensions: readonly ScopeDimensionDef[];
  readonly profiles: readonly ProfileDef[];
};

export type EnrollKind =
  | "machine_target"
  | "machine_source"
  | "zone_authority"
  | "interim_admin"
  | "target"
  | "source";

/**
 * Wire request to enroll a device/machine: the caller supplies its public
 * key (and, for CA-issued mTLS, a PKCS#10 CSR) instead of receiving a
 * server-generated private key.
 *
 * Field names match better-auth `POST /delegate-permissions/enroll-create`.
 */
export type DeviceEnrollRequest = {
  readonly entityId: string;
  readonly csrPem: string;
  readonly publicJwk?: PublicJwk;
  /** RFC 7638 JWK thumbprint. Must match better-auth `bindCsrToPublicJwk`. */
  readonly subjectSki?: string;
  readonly host?: string;
  readonly zone?: string;
  readonly kind?: EnrollKind;
};

/** Pending enroll-create response (credential arrives later via enroll-pull). */
export type EnrollCreateResult = {
  readonly enrollId: string;
  readonly pullToken: string;
  readonly subjectSki: string;
  readonly kind: string;
  readonly status: "pending" | string;
};

export type EnrollListItem = {
  readonly enrollId: string;
  readonly host: string | null;
  readonly zone: string | null;
  readonly kind: string;
  readonly role: string;
  readonly subjectSki: string;
  readonly status: string;
  readonly createdAt: string;
  readonly csrPem: string;
  readonly publicJwk: unknown;
  readonly entityId: string;
};

export type EnrollListResult = {
  readonly enrollments: readonly EnrollListItem[];
};

export type EnrollRejectRequest = {
  readonly enrollId: string;
};

export type EnrollRejectResult = {
  readonly enrollId: string;
  readonly status: "rejected";
};

export type EnrollApproveRequest = {
  readonly enrollId: string;
  readonly leafPem: string;
  readonly chainPem: string;
  readonly credential: CapabilityCredential | Record<string, unknown>;
  readonly issuerSki: string;
  readonly issuerPrivateJwk?: Record<string, unknown>;
  readonly payingPartyId?: string;
};

export type EnrollInstantRequest = {
  readonly entityId: string;
  readonly csrPem: string;
  readonly leafPem: string;
  readonly chainPem: string;
  readonly credential: CapabilityCredential | Record<string, unknown>;
  readonly issuerSki: string;
  readonly publicJwk?: PublicJwk;
  readonly subjectSki?: string;
  readonly host?: string;
  readonly zone?: string;
  readonly kind?: EnrollKind;
  readonly payingPartyId?: string;
};

export type IssueDelegateRequest = {
  readonly entityId: string;
  readonly kind: "interim_admin" | "zone_authority";
  readonly issuerPrivateJwk: Record<string, unknown>;
  readonly issuerSki: string;
  readonly zone?: string;
  readonly permissions?: CapabilitySet;
};

export type IssueMachineRequest = {
  readonly entityId: string;
  readonly host: string;
  readonly issuerPrivateJwk: Record<string, unknown>;
  readonly issuerSki: string;
  readonly permissions?: CapabilitySet;
  readonly payingPartyId?: string;
};

/** Server-keygen issue response (`issue-delegate` / `issue-machine`). */
export type IssueCredentialResult = {
  readonly credential: CapabilityCredential;
  readonly privateJwk: Record<string, unknown>;
};

export type CredentialStatusName =
  | "active"
  | "revoked"
  | "decommissioned"
  | "renewed";

export type RevocationReason =
  | "decommissioned"
  | "key_compromise"
  | "machine_lost"
  | "replaced"
  | "organization_policy"
  | "renewed"
  | "other";

export type CredentialRevokeRequest = {
  readonly ski: string;
  readonly reason?: RevocationReason;
};

export type CredentialRevokeResult = {
  readonly ski: string;
  readonly status: "revoked";
  readonly reason: RevocationReason;
  readonly revokedAt: string;
};

export type CredentialStatusResult = {
  readonly ski: string;
  readonly entityId: string;
  readonly kind: string;
  readonly status: string;
  readonly host: string | null;
  readonly zone: string | null;
  readonly revokedAt: string | null;
  readonly revokedReason: string | null;
  readonly renewedBySki: string | null;
  readonly createdAt: string;
};

export type CredentialListResult = {
  readonly credentials: readonly CredentialStatusResult[];
};

export type MachineDecommissionRequest = {
  readonly ski: string;
  readonly reason?: RevocationReason;
};

export type MachineDecommissionResult = {
  readonly ski: string;
  readonly entityId: string;
  readonly status: "decommissioned";
  readonly reason: RevocationReason;
  readonly revokedAt: string;
};

export type MachineRenewRequest = {
  readonly ski: string;
  readonly csrPem: string;
  readonly leafPem: string;
  readonly chainPem: string;
  readonly credential: CapabilityCredential | Record<string, unknown>;
  readonly issuerSki: string;
  readonly publicJwk?: PublicJwk;
};

export type MachineRenewResult = {
  readonly oldSki: string;
  readonly newSki: string;
  readonly status: "renewed";
  readonly entityId: string;
  readonly host: string | null;
  readonly platformCertPem: string;
  readonly platformRootPem: string;
};

export type PlatformRootResult = {
  readonly platformRootPem: string;
  readonly ski: string;
};

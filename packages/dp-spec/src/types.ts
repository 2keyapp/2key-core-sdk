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
 * Wire request to enroll a device/machine: the caller supplies its public
 * key (and, for CA-issued mTLS, a PKCS#10 CSR) instead of receiving a
 * server-generated private key.
 */
export type DeviceEnrollRequest = {
  readonly entityId: string;
  readonly ski: string;
  readonly publicJwk: PublicJwk;
  /** PEM PKCS#10 CSR, present when the deployment issues CA-signed mTLS certs. */
  readonly csrPem?: string;
  readonly host?: string;
};

/**
 * Wire response for a device/machine enrollment or kickstart call.
 * `certPem`/`chainPem`/`platformCertCosign` are only present when the
 * deployment issues CA-signed mTLS certs (else clients fall back to a
 * self-signed dev cert derived from their own keys).
 */
export type DeviceEnrollResult = {
  readonly credential: CapabilityCredential;
  /** PEM leaf certificate issued by the deployment's CA, if any. */
  readonly certPem?: string;
  /** PEM chain (leaf + intermediates/CA), if any. */
  readonly chainPem?: string;
  /** Platform authority co-signature over `certPem`, if any. */
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

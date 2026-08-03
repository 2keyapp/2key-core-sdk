import type { CapabilityCredential, PublicJwk } from "@2key/dp-spec";

/**
 * Client-held DP identity: keys stay local; credential is issued by Auth.
 *
 * `certPem`/`chainPem` are optional: when a deployment issues CA-signed mTLS
 * certs (via `@2key/dp-mtls` `signClientCertFromCsr`), the issued cert/chain
 * is carried here so `materializeMtlsClient` can use it as-is instead of
 * minting a self-signed dev certificate.
 */
export type DeviceIdentity = {
  readonly ski: string;
  readonly publicJwk: PublicJwk;
  readonly privateJwk: Record<string, unknown>;
  readonly credential: CapabilityCredential;
  /** PEM leaf certificate issued by a CA for this device's key, if any. */
  readonly certPem?: string;
  /** PEM chain (leaf + intermediates/CA) for `certPem`, if any. */
  readonly chainPem?: string;
};

/**
 * mTLS client material produced by `@2key/dp-mtls` (or an equivalent adapter).
 * Structural so presentation ports do not depend on the mTLS package.
 */
export type MtlsClientMaterial = {
  /** Cert presented on the wire: the full chain when `chainPem` is set, else the leaf alone. */
  readonly certPem: string;
  /** PEM chain (leaf + intermediates/CA), when the identity carries a CA-issued cert. */
  readonly chainPem?: string;
  readonly keyPem: string;
  readonly ski: string;
  readonly credential: CapabilityCredential;
};

/** Authenticated (or post-auth) byte session to a PEP or peer. */
export interface PepSession {
  send(frame: Uint8Array): Promise<void>;
  /** Register a frame handler; returns an unsubscribe function. */
  onFrame(handler: (frame: Uint8Array) => void): () => void;
  close(): Promise<void>;
}

/**
 * App supplies how to reach the PEP (TCP+mTLS, WebRTC DataChannel, etc.).
 * WebRTC and product signaling live in the app — not in this SDK.
 */
export interface PepConnector {
  connect(req: {
    readonly entityId: string;
    readonly host?: string;
    readonly mtls?: MtlsClientMaterial;
  }): Promise<PepSession>;
}

/**
 * Present CapabilityCredential for AuthZ after (or instead of) transport AuthN.
 */
export interface CredentialPresenter {
  present(session: PepSession, identity: DeviceIdentity): Promise<void>;
}

/** In-band credential frame type for PepSession. */
export const DP_CREDENTIAL_FRAME_TYPE = "dp.credential.v1" as const;

export type DpCredentialFrame = {
  readonly type: typeof DP_CREDENTIAL_FRAME_TYPE;
  readonly credential: CapabilityCredential;
};

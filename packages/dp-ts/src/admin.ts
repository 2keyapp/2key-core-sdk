/**
 * Admin client helpers for kickstart / delegate / machine issue against a
 * Better Auth `delegate-permissions` deployment.
 *
 * Enrollment calls are typed to send the caller's public key (and, for
 * CA-issued mTLS deployments, a PKCS#10 CSR) instead of expecting the server
 * to generate and return a private key.
 */
import type {
  CapabilityCredential,
  DeviceEnrollRequest,
  DeviceEnrollResult,
  PublicJwk,
} from "@2key/dp-spec";
import type { DeviceIdentity } from "@2key/dp-presentation";
import { generateKeyAndCsr } from "@2key/dp-mtls";

export type AdminClientOptions = {
  /** Better Auth base URL, e.g. `https://auth.example.com/api/auth` */
  readonly baseURL: string;
  /** Optional fetch implementation (Node, browser, custom). */
  readonly fetch?: typeof fetch;
  /** Session cookie / bearer headers for authenticated DP endpoints. */
  readonly headers?: HeadersInit;
};

export type KickstartRequest = {
  readonly entityId: string;
  readonly package: "personal" | "enterprise";
  /** Entity root public key, when the caller generates keys client-side. */
  readonly publicJwk?: PublicJwk;
  /** PKCS#10 CSR for the entity root, for CA-issued mTLS deployments. */
  readonly csrPem?: string;
};

export function createAdminClient(options: AdminClientOptions) {
  const fetchImpl = options.fetch ?? globalThis.fetch;

  async function post<T>(path: string, body: unknown): Promise<T> {
    const headers = new Headers(options.headers);
    headers.set("content-type", "application/json");
    const res = await fetchImpl(new URL(path, options.baseURL), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Admin DP request failed (${res.status}): ${text}`);
    }
    return (await res.json()) as T;
  }

  return {
    kickstartEntity(body: KickstartRequest): Promise<DeviceEnrollResult> {
      return post("/delegate-permissions/kickstart-entity", body);
    },
    issueDelegate(body: Record<string, unknown>): Promise<CapabilityCredential> {
      return post("/delegate-permissions/issue-delegate", body);
    },
    /** @deprecated Use `enrollMachine` for typed public-key/CSR enrollment. */
    issueMachine(body: Record<string, unknown>): Promise<CapabilityCredential> {
      return post("/delegate-permissions/issue-machine", body);
    },
    enrollMachine(body: DeviceEnrollRequest): Promise<DeviceEnrollResult> {
      return post("/delegate-permissions/enroll-create", body);
    },
    enrollInstant(body: Record<string, unknown>): Promise<DeviceEnrollResult> {
      return post("/delegate-permissions/enroll-instant", body);
    },
    enrollPull(body: { pullToken: string }): Promise<DeviceEnrollResult & { status: string }> {
      return post("/delegate-permissions/enroll-pull", body);
    },
    enrollApprove(body: Record<string, unknown>): Promise<unknown> {
      return post("/delegate-permissions/enroll-approve", body);
    },
  };
}

export type AdminClient = ReturnType<typeof createAdminClient>;

export type EnrollClientOptions = AdminClientOptions & {
  /** Wire path to POST the enrollment request to. Default `/delegate-permissions/enroll-machine`. */
  readonly enrollPath?: string;
};

export type EnrollDeviceParams = {
  readonly entityId: string;
  /** Subject common name for the generated CSR; defaults to `entityId`. */
  readonly commonName?: string;
  /** Optional DNS SAN / routing host for the device (e.g. `db1--acme.example`). */
  readonly host?: string;
};

export type EnrollDeviceResult = {
  /** Ready to hand to `@2key/dp-mtls` `materializeMtlsClient`. */
  readonly identity: DeviceIdentity;
  /** Raw server response, in case callers need `platformCertCosign` etc. */
  readonly result: DeviceEnrollResult;
};

/**
 * Device-side enrollment client: generates an Ed25519 keypair + CSR
 * on-device, sends the public key/CSR to the admin/auth server, and returns
 * a `DeviceIdentity` combining the local private key with the server-issued
 * credential (and CA cert/chain, if the deployment issues one).
 *
 * The private key never leaves this process.
 */
export function createEnrollClient(options: EnrollClientOptions) {
  const admin = createAdminClient(options);
  const enrollPath = options.enrollPath ?? "/delegate-permissions/enroll-machine";

  async function post(body: unknown): Promise<DeviceEnrollResult> {
    if (enrollPath === "/delegate-permissions/enroll-machine") {
      return admin.enrollMachine(body as DeviceEnrollRequest);
    }
    const headers = new Headers(options.headers);
    headers.set("content-type", "application/json");
    const fetchImpl = options.fetch ?? globalThis.fetch;
    const res = await fetchImpl(new URL(enrollPath, options.baseURL), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Device enroll request failed (${res.status}): ${text}`);
    }
    return (await res.json()) as DeviceEnrollResult;
  }

  return {
    async enroll(params: EnrollDeviceParams): Promise<EnrollDeviceResult> {
      const { privateJwk, publicJwk, ski, csrPem } = await generateKeyAndCsr({
        commonName: params.commonName ?? params.entityId,
        ...(params.host !== undefined ? { host: params.host } : {}),
      });

      const request: DeviceEnrollRequest = {
        entityId: params.entityId,
        ski,
        publicJwk,
        csrPem,
        ...(params.host !== undefined ? { host: params.host } : {}),
      };

      const result = await post(request);

      const identity: DeviceIdentity = {
        ski,
        publicJwk,
        privateJwk,
        credential: result.credential,
        ...(result.certPem !== undefined ? { certPem: result.certPem } : {}),
        ...(result.chainPem !== undefined ? { chainPem: result.chainPem } : {}),
      };

      return { identity, result };
    },
  };
}

export type EnrollClient = ReturnType<typeof createEnrollClient>;

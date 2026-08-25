/**
 * Admin client helpers for kickstart / delegate / machine issue against a
 * Better Auth `delegate-permissions` deployment.
 *
 * Enrollment calls are typed to send the caller's public key (and, for
 * CA-issued mTLS deployments, a PKCS#10 CSR) instead of expecting the server
 * to generate and return a private key.
 */
import type {
  CredentialListResult,
  CredentialRevokeRequest,
  CredentialRevokeResult,
  CredentialStatusResult,
  DeviceEnrollRequest,
  DeviceEnrollResult,
  EnrollApproveRequest,
  EnrollCreateResult,
  EnrollInstantRequest,
  EnrollListResult,
  EnrollRejectRequest,
  EnrollRejectResult,
  IssueCredentialResult,
  IssueDelegateRequest,
  IssueMachineRequest,
  MachineDecommissionRequest,
  MachineDecommissionResult,
  MachineRenewRequest,
  MachineRenewResult,
  PlatformRootResult,
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

  async function request<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
    query?: Record<string, string | undefined>,
  ): Promise<T> {
    const url = new URL(path, options.baseURL);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined) url.searchParams.set(key, value);
      }
    }
    const headers = new Headers(options.headers);
    if (body !== undefined) {
      headers.set("content-type", "application/json");
    }
    const res = await fetchImpl(url, {
      method,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Admin DP request failed (${res.status}): ${text}`);
    }
    return (await res.json()) as T;
  }

  function post<T>(path: string, body: unknown): Promise<T> {
    return request<T>("POST", path, body);
  }

  function get<T>(
    path: string,
    query?: Record<string, string | undefined>,
  ): Promise<T> {
    return request<T>("GET", path, undefined, query);
  }

  return {
    kickstartEntity(body: KickstartRequest): Promise<DeviceEnrollResult> {
      return post("/delegate-permissions/kickstart-entity", body);
    },
    issueDelegate(body: IssueDelegateRequest): Promise<IssueCredentialResult> {
      return post("/delegate-permissions/issue-delegate", body);
    },
    /** @deprecated Prefer CSR enrollment (`enrollMachine` / `enrollInstant`). */
    issueMachine(body: IssueMachineRequest): Promise<IssueCredentialResult> {
      return post("/delegate-permissions/issue-machine", body);
    },
    enrollMachine(body: DeviceEnrollRequest): Promise<EnrollCreateResult> {
      return post("/delegate-permissions/enroll-create", body);
    },
    enrollInstant(body: EnrollInstantRequest): Promise<DeviceEnrollResult> {
      return post("/delegate-permissions/enroll-instant", body);
    },
    enrollPull(
      body: { pullToken: string },
    ): Promise<DeviceEnrollResult & { status: string }> {
      return post("/delegate-permissions/enroll-pull", body);
    },
    enrollApprove(body: EnrollApproveRequest): Promise<unknown> {
      return post("/delegate-permissions/enroll-approve", body);
    },
    enrollList(query: {
      entityId: string;
      status?: string;
    }): Promise<EnrollListResult> {
      return get("/delegate-permissions/enroll-list", {
        entityId: query.entityId,
        status: query.status,
      });
    },
    enrollReject(body: EnrollRejectRequest): Promise<EnrollRejectResult> {
      return post("/delegate-permissions/enroll-reject", body);
    },
    credentialRevoke(
      body: CredentialRevokeRequest,
    ): Promise<CredentialRevokeResult> {
      return post("/delegate-permissions/credential-revoke", body);
    },
    credentialStatus(query: { ski: string }): Promise<CredentialStatusResult> {
      return get("/delegate-permissions/credential-status", {
        ski: query.ski,
      });
    },
    credentialList(query: {
      entityId: string;
      status?: string;
    }): Promise<CredentialListResult> {
      return get("/delegate-permissions/credential-list", {
        entityId: query.entityId,
        status: query.status,
      });
    },
    machineDecommission(
      body: MachineDecommissionRequest,
    ): Promise<MachineDecommissionResult> {
      return post("/delegate-permissions/machine-decommission", body);
    },
    machineRenew(body: MachineRenewRequest): Promise<MachineRenewResult> {
      return post("/delegate-permissions/machine-renew", body);
    },
    platformRoot(): Promise<PlatformRootResult> {
      return get("/delegate-permissions/platform-root");
    },
  };
}

export type AdminClient = ReturnType<typeof createAdminClient>;

export type EnrollClientOptions = AdminClientOptions & {
  /** Wire path to POST the enrollment request to. Default `/delegate-permissions/enroll-create`. */
  readonly enrollPath?: string;
};

export type EnrollDeviceParams = {
  readonly entityId: string;
  /** Subject common name for the generated CSR; defaults to `entityId`. */
  readonly commonName?: string;
  /** Optional DNS SAN / routing host for the device (e.g. `db1--acme.example`). */
  readonly host?: string;
  readonly kind?: DeviceEnrollRequest["kind"];
};

export type EnrollDeviceResult = {
  readonly ski: string;
  readonly publicJwk: PublicJwk;
  readonly privateJwk: Record<string, unknown>;
  readonly csrPem: string;
  /** Server enroll-create (or custom path) response. */
  readonly enrollment: EnrollCreateResult;
  /**
   * Present when the server returned a signed credential on the same call
   * (instant enroll or a custom `enrollPath`).
   */
  readonly identity?: DeviceIdentity;
};

/**
 * Device-side enrollment client: generates an Ed25519 keypair + CSR
 * on-device, sends the public key/CSR to the admin/auth server, and returns
 * local key material plus the pending enroll-create response.
 *
 * The private key never leaves this process. Pull the signed credential
 * later with `createAdminClient().enrollPull({ pullToken })`.
 */
export function createEnrollClient(options: EnrollClientOptions) {
  const admin = createAdminClient(options);
  const enrollPath =
    options.enrollPath ?? "/delegate-permissions/enroll-create";

  async function postEnroll(body: DeviceEnrollRequest): Promise<EnrollCreateResult> {
    if (enrollPath === "/delegate-permissions/enroll-create") {
      return admin.enrollMachine(body);
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
    return (await res.json()) as EnrollCreateResult;
  }

  return {
    async enroll(params: EnrollDeviceParams): Promise<EnrollDeviceResult> {
      const { privateJwk, publicJwk, ski, csrPem } = await generateKeyAndCsr({
        commonName: params.commonName ?? params.entityId,
        ...(params.host !== undefined ? { host: params.host } : {}),
      });

      const request: DeviceEnrollRequest = {
        entityId: params.entityId,
        subjectSki: ski,
        publicJwk,
        csrPem,
        ...(params.host !== undefined ? { host: params.host } : {}),
        ...(params.kind !== undefined ? { kind: params.kind } : {}),
      };

      const enrollment = await postEnroll(request);
      const maybeCredential = (enrollment as unknown as Partial<DeviceEnrollResult>)
        .credential;

      return {
        ski,
        publicJwk,
        privateJwk,
        csrPem,
        enrollment,
        ...(maybeCredential
          ? {
              identity: {
                ski,
                publicJwk,
                privateJwk,
                credential: maybeCredential,
              },
            }
          : {}),
      };
    },
  };
}

export type EnrollClient = ReturnType<typeof createEnrollClient>;

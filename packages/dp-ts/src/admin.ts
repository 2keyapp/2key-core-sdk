/**
 * Admin client helpers for kickstart / delegate / machine issue against a
 * Better Auth `delegate-permissions` deployment.
 *
 * Keys are generated client-side; the server should eventually accept public
 * JWKs / CSRs instead of returning private JWKs.
 */
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
    kickstartEntity(body: KickstartRequest) {
      return post("/delegate-permissions/kickstart-entity", body);
    },
    issueDelegate(body: Record<string, unknown>) {
      return post("/delegate-permissions/issue-delegate", body);
    },
    issueMachine(body: Record<string, unknown>) {
      return post("/delegate-permissions/issue-machine", body);
    },
  };
}

export type AdminClient = ReturnType<typeof createAdminClient>;

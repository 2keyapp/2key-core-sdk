import type {
  CredentialPresenter,
  DeviceIdentity,
  DpCredentialFrame,
  PepSession,
} from "./types.js";
import { DP_CREDENTIAL_FRAME_TYPE } from "./types.js";

/**
 * Default presenter: send CapabilityCredential as the first application frame.
 * Use after mTLS AuthN, or alone on app transports (e.g. WebRTC DataChannel).
 */
export function createInBandCredentialPresenter(): CredentialPresenter {
  return {
    async present(session: PepSession, identity: DeviceIdentity) {
      const frame: DpCredentialFrame = {
        type: DP_CREDENTIAL_FRAME_TYPE,
        credential: identity.credential,
      };
      const bytes = new TextEncoder().encode(JSON.stringify(frame));
      await session.send(bytes);
    },
  };
}

/** Parse an in-band credential frame; returns null if not a dp.credential.v1 frame. */
export function parseDpCredentialFrame(
  frame: Uint8Array,
): DpCredentialFrame | null {
  try {
    const text = new TextDecoder().decode(frame);
    const parsed = JSON.parse(text) as { type?: string; credential?: unknown };
    if (parsed.type !== DP_CREDENTIAL_FRAME_TYPE || !parsed.credential) {
      return null;
    }
    return {
      type: DP_CREDENTIAL_FRAME_TYPE,
      credential: parsed.credential as DpCredentialFrame["credential"],
    };
  } catch {
    return null;
  }
}

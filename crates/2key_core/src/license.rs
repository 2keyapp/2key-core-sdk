//! ES256 license JWT verification (pure Rust via `p256`, no ring).

use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde_json::Value;

use crate::error::{ErrorCode, Result, TwoKeyError};
use crate::models::LicensePayload;
use crate::ports::Clock;

/// Outcome of verify + decode.
#[derive(Debug, Clone)]
pub enum VerifyOutcome {
    /// Valid payload.
    Success(LicensePayload),
    /// Verification failed with stable code.
    Failure {
        /// Error code.
        code: ErrorCode,
        /// Message.
        message: String,
    },
}

/// Verifies license JWTs with the configured EC public key.
pub struct LicenseVerifier {
    verifying_key: VerifyingKey,
}

impl LicenseVerifier {
    /// Build from PEM (SPKI EC public key).
    pub fn from_pem(public_key_pem: &str) -> Result<Self> {
        let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem).map_err(|e| {
            TwoKeyError::new(ErrorCode::Config, "Invalid public_key_pem").with_detail(e.to_string())
        })?;
        Ok(Self { verifying_key })
    }

    /// Verify signature + exp, then parse claims into [LicensePayload].
    pub fn verify_and_decode(&self, token: &str, clock: &dyn Clock) -> VerifyOutcome {
        self.verify_and_decode_for_device(token, clock, None)
    }

    /// Like [Self::verify_and_decode], but when `local_ski` is set and the
    /// license lists devices, require that SKI to appear on an active seat.
    pub fn verify_and_decode_for_device(
        &self,
        token: &str,
        clock: &dyn Clock,
        local_ski: Option<&str>,
    ) -> VerifyOutcome {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return VerifyOutcome::Failure {
                code: ErrorCode::LicenseMalformed,
                message: "Invalid format. Please paste the full token from the billing portal."
                    .into(),
            };
        }

        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() != 3 {
            return VerifyOutcome::Failure {
                code: ErrorCode::LicenseMalformed,
                message: "Invalid format. Please paste the full token from the billing portal."
                    .into(),
            };
        }

        let header_json = match b64url_decode(parts[0]) {
            Ok(b) => b,
            Err(_) => {
                return VerifyOutcome::Failure {
                    code: ErrorCode::LicenseMalformed,
                    message: "Invalid format. Please paste the full token from the billing portal."
                        .into(),
                };
            }
        };
        let header: Value = match serde_json::from_slice(&header_json) {
            Ok(v) => v,
            Err(_) => {
                return VerifyOutcome::Failure {
                    code: ErrorCode::LicenseMalformed,
                    message: "Invalid format. Please paste the full token from the billing portal."
                        .into(),
                };
            }
        };
        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        if alg != "ES256" {
            return VerifyOutcome::Failure {
                code: ErrorCode::LicenseInvalid,
                message: "Invalid token. It may have been copied incorrectly.".into(),
            };
        }

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = match b64url_decode(parts[2]) {
            Ok(b) => b,
            Err(_) => {
                return VerifyOutcome::Failure {
                    code: ErrorCode::LicenseMalformed,
                    message: "Invalid format. Please paste the full token from the billing portal."
                        .into(),
                };
            }
        };

        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(_) => {
                return VerifyOutcome::Failure {
                    code: ErrorCode::LicenseInvalid,
                    message: "Invalid token. It may have been copied incorrectly.".into(),
                };
            }
        };

        if self
            .verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .is_err()
        {
            return VerifyOutcome::Failure {
                code: ErrorCode::LicenseInvalid,
                message: "Invalid token. It may have been copied incorrectly.".into(),
            };
        }

        let payload_json = match b64url_decode(parts[1]) {
            Ok(b) => b,
            Err(_) => {
                return VerifyOutcome::Failure {
                    code: ErrorCode::LicenseMalformed,
                    message: "Invalid format. Please paste the full token from the billing portal."
                        .into(),
                };
            }
        };
        let claims: Value = match serde_json::from_slice(&payload_json) {
            Ok(v) => v,
            Err(_) => {
                return VerifyOutcome::Failure {
                    code: ErrorCode::LicenseMalformed,
                    message: "Invalid format. Please paste the full token from the billing portal."
                        .into(),
                };
            }
        };

        match LicensePayload::from_claims(&claims) {
            Ok(payload) => {
                if payload.is_expired(clock.unix_seconds()) {
                    VerifyOutcome::Failure {
                        code: ErrorCode::LicenseExpired,
                        message: "This token has expired. Please sync or get a new token from the billing portal.".into(),
                    }
                } else if let Some(ski) = local_ski {
                    if !payload.allows_local_device(ski) {
                        VerifyOutcome::Failure {
                            code: ErrorCode::LicenseDeviceMismatch,
                            message: "This license is not valid for this device. Bind this device in billing or replace another device.".into(),
                        }
                    } else {
                        VerifyOutcome::Success(payload)
                    }
                } else {
                    VerifyOutcome::Success(payload)
                }
            }
            Err(e) => VerifyOutcome::Failure {
                code: ErrorCode::LicenseMalformed,
                message: format!("Token is missing required data. {}", e.message),
            },
        }
    }
}

fn b64url_decode(input: &str) -> std::result::Result<Vec<u8>, ()> {
    URL_SAFE_NO_PAD
        .decode(input.as_bytes())
        .or_else(|_| STANDARD.decode(input.as_bytes()))
        .map_err(|_| ())
}

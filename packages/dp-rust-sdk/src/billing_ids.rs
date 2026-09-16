//! Billing v1 Machine AuthN needs `payingPartyId` + `memberId` on register/enroll.

use reqwest::Method;
use serde_json::Value;

use crate::client::DpClient;
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct BillingPartyIds {
    pub paying_party_id: String,
    pub member_id: String,
}

/// Decode a JWT payload without verifying (claims only).
pub fn jwt_payload(token: &str) -> Option<Value> {
    let raw = token
        .trim()
        .strip_prefix("Bearer ")
        .unwrap_or(token)
        .trim();
    let payload = raw.split('.').nth(1)?;
    let bytes = b64url_decode(payload)?;
    serde_json::from_slice(&bytes).ok()
}

pub fn jwt_claim_string(token: &str, claim: &str) -> Option<String> {
    jwt_payload(token)?
        .get(claim)?
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn b64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut s = input.replace('-', "+").replace('_', "/");
    while s.len() % 4 != 0 {
        s.push('=');
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut buf = 0u32;
    let mut n = 0;
    for b in s.bytes() {
        if b == b'=' {
            break;
        }
        let v = table.iter().position(|&c| c == b)? as u32;
        buf = (buf << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((buf >> n) as u8);
        }
    }
    Some(out)
}

impl DpClient {
    /// Resolve billing register/enroll IDs from the Bearer JWT + `/paying-parties/me`.
    pub async fn billing_party_ids(&self) -> Result<BillingPartyIds> {
        let token = self
            .auth_token()
            .ok_or_else(|| Error::auth("not logged in — run auth login with a billing JWT"))?;
        let member_id = jwt_claim_string(token, "member_id").ok_or_else(|| {
            Error::auth(
                "JWT has no member_id — paste the portal access token (eyJ…), not a session cookie",
            )
        })?;

        let raw: Value = self
            .send_json(Method::GET, "paying-parties/me", &[], None::<&()>)
            .await?;
        let data = raw.get("data").unwrap_or(&raw);
        let personal = data.get("personal").ok_or_else(|| {
            Error::auth("GET /paying-parties/me missing personal paying party")
        })?;
        let paying_party_id = json_id(personal.get("id")).ok_or_else(|| {
            Error::auth("GET /paying-parties/me personal.id missing")
        })?;

        Ok(BillingPartyIds {
            paying_party_id,
            member_id,
        })
    }
}

fn json_id(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_payload_reads_member_id() {
        // header.payload.sig — payload {"member_id":"abc","email":"a@b.c"}
        let payload = base64_url(br#"{"member_id":"abc","email":"a@b.c"}"#);
        let token = format!("eyJhbGciOiJub25lIn0.{payload}.x");
        assert_eq!(jwt_claim_string(&token, "member_id").as_deref(), Some("abc"));
        assert_eq!(jwt_claim_string(&token, "email").as_deref(), Some("a@b.c"));
    }

    fn base64_url(bytes: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        let mut i = 0;
        while i < bytes.len() {
            let b0 = bytes[i];
            let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
            let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
            out.push(T[(b0 >> 2) as usize] as char);
            out.push(T[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
            if i + 1 < bytes.len() {
                out.push(T[(((b1 & 15) << 2) | (b2 >> 6)) as usize] as char);
            }
            if i + 2 < bytes.len() {
                out.push(T[(b2 & 63) as usize] as char);
            }
            i += 3;
        }
        out.replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
    }
}

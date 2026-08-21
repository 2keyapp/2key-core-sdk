//! Machine identity: `<machine_name><separator><entity_id>`.
//!
//! Parsing splits on the **first** `<separator>` from the right so names like
//! `api.prod.eu--acme.com` are unambiguous.

use crate::error::{Error, Result};

const MACHINE_NAME_CHARS: &str = "lowercase ASCII a-z, digits, `.`, or `-`";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdentity {
    pub machine_name: String,
    pub entity_id: String,
    pub separator: String,
}

impl MachineIdentity {
    pub fn new(
        machine_name: impl Into<String>,
        entity_id: impl Into<String>,
        separator: impl Into<String>,
    ) -> Result<Self> {
        let identity = Self {
            machine_name: machine_name.into(),
            entity_id: entity_id.into(),
            separator: separator.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Parse `name<sep>entity`, splitting on the first `sep` from the right.
    pub fn parse(raw: &str, separator: &str) -> Result<Self> {
        if separator.is_empty() {
            return Err(Error::identity("separator must not be empty"));
        }
        let Some((name, entity)) = raw.rsplit_once(separator) else {
            return Err(Error::identity(format!(
                "{raw:?} does not contain separator {separator:?}"
            )));
        };
        Self::new(name, entity, separator)
    }

    pub fn as_str(&self) -> String {
        format!("{}{}{}", self.machine_name, self.separator, self.entity_id)
    }

    pub fn validate(&self) -> Result<()> {
        if self.separator.is_empty() {
            return Err(Error::identity("separator must not be empty"));
        }
        validate_machine_name(&self.machine_name, &self.separator)?;
        validate_entity_id(&self.entity_id, &self.separator)?;
        Ok(())
    }
}

impl std::fmt::Display for MachineIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_str())
    }
}

fn validate_machine_name(name: &str, separator: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::identity("machine name must not be empty"));
    }
    if name.contains(separator) {
        return Err(Error::identity(format!(
            "machine name {name:?} must not contain separator {separator:?}"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-')
    {
        return Err(Error::identity(format!(
            "machine name {name:?} must be {MACHINE_NAME_CHARS}"
        )));
    }
    Ok(())
}

fn validate_entity_id(entity_id: &str, separator: &str) -> Result<()> {
    if entity_id.is_empty() {
        return Err(Error::identity("entity id must not be empty"));
    }
    if entity_id.contains(separator) {
        return Err(Error::identity(format!(
            "entity id {entity_id:?} must not contain separator {separator:?}"
        )));
    }
    if entity_id.chars().any(|c| c.is_ascii_uppercase()) || !entity_id.is_ascii() {
        return Err(Error::identity(format!(
            "entity id {entity_id:?} must be lowercase ASCII"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parses_from_the_right() {
        let id = MachineIdentity::new("api.prod.eu", "acme.com", "--").unwrap();
        assert_eq!(id.as_str(), "api.prod.eu--acme.com");
        let parsed = MachineIdentity::parse("api.prod.eu--acme.com", "--").unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn rejects_separator_inside_name() {
        let err = MachineIdentity::parse("a--b--acme.com", "--").unwrap_err();
        assert!(err.to_string().contains("must not contain separator"));
    }

    #[test]
    fn rejects_uppercase_name() {
        let err = MachineIdentity::new("DB1", "acme.com", "--").unwrap_err();
        assert!(err.to_string().contains("machine name"));
    }

    #[test]
    fn rejects_missing_separator() {
        assert!(MachineIdentity::parse("db1.acme.com", "--").is_err());
    }
}

//! Key storage abstraction. Default implementation is a filesystem tree under
//! `$DP_STATE_DIR` with `0600` files and `0700` directories.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{Error, Result};

/// Well-known keys matching the spec's `$DP_STATE_DIR` layout.
pub mod keys {
    pub const MACHINE_KEY: &str = "identity/machine.key";
    pub const MACHINE_KEY_NEW: &str = "identity/machine.key.new";
    pub const MACHINE_CSR: &str = "identity/machine.csr";
    pub const MACHINE_CRT: &str = "identity/machine.crt";
    pub const ORG_CA: &str = "identity/org-ca.crt";
    pub const PLATFORM_CA: &str = "identity/platform-ca.crt";
    pub const PLATFORM_ENDORSED: &str = "identity/platform-endorsed.crt";
    pub const CHAIN: &str = "identity/chain.pem";
    pub const CREDENTIAL: &str = "identity/credential.json";
    pub const STATE: &str = "state.json";
    pub const CONFIG: &str = "config.json";
    /// Human Better Auth session (not machine identity). 0600.
    pub const SESSION: &str = "session";
}

pub use keys::{
    CHAIN as KEY_CHAIN, CONFIG as KEY_CONFIG, CREDENTIAL as KEY_CREDENTIAL,
    MACHINE_CRT as KEY_MACHINE_CRT, MACHINE_CSR as KEY_MACHINE_CSR, MACHINE_KEY as KEY_MACHINE_KEY,
    MACHINE_KEY_NEW as KEY_MACHINE_KEY_NEW, ORG_CA as KEY_ORG_CA, PLATFORM_CA as KEY_PLATFORM_CA,
    PLATFORM_ENDORSED as KEY_PLATFORM_ENDORSED, SESSION as KEY_SESSION, STATE as KEY_STATE,
};

pub trait KeyStore: Send + Sync {
    fn save(&self, key: &str, value: &[u8]) -> Result<()>;
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn delete(&self, key: &str) -> Result<()>;
    fn exists(&self, key: &str) -> Result<bool>;

    /// Overwrite then unlink when the backend supports it. Default: [`delete`].
    fn secure_delete(&self, key: &str) -> Result<()> {
        self.delete(key)
    }

    fn load_string(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .load(key)?
            .map(|b| String::from_utf8_lossy(&b).into_owned()))
    }

    fn save_string(&self, key: &str, value: &str) -> Result<()> {
        self.save(key, value.as_bytes())
    }
}

/// In-memory store for tests.
#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl KeyStore for MemoryKeyStore {
    fn save(&self, key: &str, value: &[u8]) -> Result<()> {
        validate_key(key)?;
        self.inner
            .lock()
            .map_err(|e| Error::keystore(e.to_string()))?
            .insert(key.to_string(), value.to_vec());
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;
        Ok(self
            .inner
            .lock()
            .map_err(|e| Error::keystore(e.to_string()))?
            .get(key)
            .cloned())
    }

    fn delete(&self, key: &str) -> Result<()> {
        validate_key(key)?;
        self.inner
            .lock()
            .map_err(|e| Error::keystore(e.to_string()))?
            .remove(key);
        Ok(())
    }

    fn exists(&self, key: &str) -> Result<bool> {
        validate_key(key)?;
        Ok(self
            .inner
            .lock()
            .map_err(|e| Error::keystore(e.to_string()))?
            .contains_key(key))
    }
}

/// Filesystem store. Keys are relative paths under `root`.
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    root: PathBuf,
}

impl FileKeyStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        set_dir_mode(&root)?;
        fs::create_dir_all(root.join("identity"))?;
        set_dir_mode(&root.join("identity"))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, key: &str) -> Result<PathBuf> {
        validate_key(key)?;
        Ok(self.root.join(key))
    }
}

impl KeyStore for FileKeyStore {
    fn save(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = self.path_for(key)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            set_dir_mode(parent)?;
        }
        atomic_write(&path, value)?;
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path_for(key)?;
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.path_for(key)?.exists())
    }

    fn secure_delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key)?;
        if !path.exists() {
            return Ok(());
        }
        let len = fs::metadata(&path)?.len();
        overwrite_file(&path, len)?;
        fs::remove_file(&path)?;
        Ok(())
    }
}

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.starts_with('/')
        || key.starts_with('\\')
        || key.contains("..")
        || Path::new(key).is_absolute()
    {
        return Err(Error::keystore(format!("illegal key {key:?}")));
    }
    Ok(())
}

fn atomic_write(path: &Path, value: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(value)?;
        file.sync_all()?;
    }
    set_file_mode(&tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn overwrite_file(path: &Path, len: u64) -> Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let zeros = vec![0u8; 8192];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    file.sync_all()?;
    Ok(())
}

fn set_file_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    let _ = path;
    Ok(())
}

fn set_dir_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_roundtrip() {
        let store = MemoryKeyStore::new();
        store.save(keys::STATE, b"{}").unwrap();
        assert!(store.exists(keys::STATE).unwrap());
        assert_eq!(
            store.load(keys::STATE).unwrap().as_deref(),
            Some(&b"{}"[..])
        );
        store.delete(keys::STATE).unwrap();
        assert!(!store.exists(keys::STATE).unwrap());
    }

    #[test]
    fn rejects_path_escape() {
        let store = MemoryKeyStore::new();
        assert!(store.save("../etc/passwd", b"x").is_err());
        assert!(store.save("/tmp/x", b"x").is_err());
    }

    #[test]
    fn file_store_persists() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::open(dir.path()).unwrap();
        store.save(keys::MACHINE_KEY, b"secret").unwrap();
        assert_eq!(
            store.load(keys::MACHINE_KEY).unwrap().as_deref(),
            Some(&b"secret"[..])
        );
        store.secure_delete(keys::MACHINE_KEY).unwrap();
        assert!(!store.exists(keys::MACHINE_KEY).unwrap());
    }
}

//! OpenClaw Vault Resolver — Rust binary for credential decryption.
//!
//! Reads a JSON request from stdin, decrypts the requested credential file,
//! writes the credential to stdout as JSON, drops all capabilities, and exits.
//!
//! File format: [16-byte salt][12-byte nonce][ciphertext][16-byte auth tag]
//! Key derivation: Argon2id (memory=64MiB, iterations=3, parallelism=1, hash_length=32)
//! Cipher: AES-256-GCM

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process;

// Exit codes per spec
const EXIT_SUCCESS: i32 = 0;
const EXIT_NOT_FOUND: i32 = 1;
const EXIT_DECRYPT_FAILED: i32 = 2;
const EXIT_PERMISSION_DENIED: i32 = 3;
#[allow(dead_code)]
const EXIT_SECCOMP_VIOLATION: i32 = 4;

// Crypto constants — must match TypeScript implementation
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const AUTH_TAG_LENGTH: usize = 16;
const ARGON2_MEMORY_KIB: u32 = 65536; // 64 MiB in KiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_HASH_LENGTH: usize = 32;

#[derive(Deserialize)]
struct Request {
    tool: String,
    #[allow(dead_code)]
    context: Option<String>,
    #[allow(dead_code)]
    command: Option<String>,
}

#[derive(Serialize)]
struct SuccessResponse {
    credential: String,
    expires: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
    message: String,
}

/// Vault metadata stored in .vault-meta.json
#[derive(Deserialize)]
struct VaultMeta {
    #[serde(rename = "installTimestamp")]
    install_timestamp: String,
    #[serde(rename = "masterKeyMode")]
    master_key_mode: String,
}

/// Derive a machine-specific passphrase: SHA-256(hostname:uid:timestamp) as hex.
/// Must produce identical output to TypeScript's getMachinePassphrase().
fn get_machine_passphrase(install_timestamp: &str) -> String {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_default();
    let uid = unsafe { libc::getuid() };
    let material = format!("{}:{}:{}", hostname, uid, install_timestamp);
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Derive a 256-bit key from a passphrase using Argon2id.
/// Parameters must exactly match the TypeScript implementation.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_HASH_LENGTH),
    )
    .map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = vec![0u8; ARGON2_HASH_LENGTH];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 hash error: {}", e))?;

    Ok(key)
}

/// Decrypt a credential from the binary payload.
/// Format: [salt(16)][nonce(12)][ciphertext(var)][authTag(16)]
///
/// Note: aes-gcm crate expects ciphertext with auth tag appended.
fn decrypt_payload(payload: &[u8], passphrase: &str) -> Result<String, String> {
    let min_len = SALT_LENGTH + NONCE_LENGTH + AUTH_TAG_LENGTH;
    if payload.len() < min_len {
        return Err("Invalid encrypted payload: too short".to_string());
    }

    let salt = &payload[..SALT_LENGTH];
    let nonce_bytes = &payload[SALT_LENGTH..SALT_LENGTH + NONCE_LENGTH];
    let ciphertext = &payload[SALT_LENGTH + NONCE_LENGTH..payload.len() - AUTH_TAG_LENGTH];
    let auth_tag = &payload[payload.len() - AUTH_TAG_LENGTH..];

    let key = derive_key(passphrase, salt)?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("AES key error: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    // aes-gcm expects ciphertext || auth_tag concatenated
    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + AUTH_TAG_LENGTH);
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(auth_tag);

    let plaintext = cipher
        .decrypt(nonce, ct_with_tag.as_ref())
        .map_err(|_| "Decryption failed: invalid key or corrupted data".to_string())?;

    String::from_utf8(plaintext).map_err(|e| format!("UTF-8 decode error: {}", e))
}

/// Find the vault directory and metadata.
/// Checks /var/lib/openclaw-vault/ first, falls back to ~/.openclaw/vault/
fn find_vault_paths(tool_name: &str) -> Result<(VaultMeta, PathBuf), (i32, String)> {
    let system_dir = Path::new("/var/lib/openclaw-vault");
    let home_dir = dirs_fallback();

    // Try system dir first, then home dir
    let dirs_to_try: Vec<PathBuf> = vec![
        system_dir.to_path_buf(),
        home_dir,
    ];

    let mut meta: Option<VaultMeta> = None;
    let mut cred_path: Option<PathBuf> = None;

    for dir in &dirs_to_try {
        // Try to read meta if we haven't found it yet
        if meta.is_none() {
            let meta_path = dir.join(".vault-meta.json");
            if let Ok(content) = fs::read_to_string(&meta_path) {
                if let Ok(m) = serde_json::from_str::<VaultMeta>(&content) {
                    meta = Some(m);
                }
            }
        }

        // Try to find credential file
        if cred_path.is_none() {
            let enc_path = dir.join(format!("{}.enc", tool_name));
            if enc_path.exists() {
                cred_path = Some(enc_path);
            }
        }
    }

    let meta = meta.ok_or((EXIT_NOT_FOUND, "Vault metadata not found".to_string()))?;
    let cred = cred_path.ok_or((EXIT_NOT_FOUND, format!("Credential file not found for tool: {}", tool_name)))?;

    // Check we can actually read the credential file
    match fs::metadata(&cred) {
        Ok(_) => Ok((meta, cred)),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            Err((EXIT_PERMISSION_DENIED, format!("Permission denied: {}", cred.display())))
        }
        Err(e) => Err((EXIT_NOT_FOUND, format!("Cannot access credential file: {}", e))),
    }
}

/// Get the home vault directory fallback
fn dirs_fallback() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".openclaw").join("vault")
}

/// Install seccomp filter to restrict syscalls.
/// Only allows: read, write, exit, exit_group, sigreturn, rt_sigreturn,
/// brk, mmap, munmap, close, fstat, newfstatat.
#[cfg(target_os = "linux")]
fn install_seccomp_filter() -> Result<(), String> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompFilter,
    };
    use std::collections::BTreeMap;

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();

    // Allowed syscalls (x86_64 numbers) — empty rules vec = unconditional allow
    let allowed_syscalls: &[i64] = &[
        0,   // read
        1,   // write
        3,   // close
        5,   // fstat
        9,   // mmap
        10,  // mprotect (stack guard pages)
        11,  // munmap
        12,  // brk
        15,  // rt_sigreturn
        20,  // writev
        60,  // exit
        202, // futex (thread sync for Argon2)
        231, // exit_group
        262, // newfstatat
        318, // getrandom
    ];

    for &syscall in allowed_syscalls {
        rules.insert(syscall, vec![]);
    }

    let target_arch = std::env::consts::ARCH
        .try_into()
        .map_err(|e: seccompiler::BackendError| format!("arch error: {}", e))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        target_arch,
    )
    .map_err(|e| format!("seccomp filter creation failed: {}", e))?;

    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| format!("seccomp BPF compilation failed: {}", e))?;

    seccompiler::apply_filter(&prog)
        .map_err(|e| format!("seccomp apply failed: {}", e))?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_seccomp_filter() -> Result<(), String> {
    // seccomp is Linux-only; on other platforms this is a no-op
    Ok(())
}

/// Drop all Linux capabilities.
#[cfg(target_os = "linux")]
fn drop_capabilities() {
    if let Err(e) = caps::clear(None, caps::CapSet::Effective) {
        eprintln!("Warning: failed to drop effective caps: {}", e);
    }
    if let Err(e) = caps::clear(None, caps::CapSet::Permitted) {
        eprintln!("Warning: failed to drop permitted caps: {}", e);
    }
    if let Err(e) = caps::clear(None, caps::CapSet::Inheritable) {
        eprintln!("Warning: failed to drop inheritable caps: {}", e);
    }
}

#[cfg(not(target_os = "linux"))]
fn drop_capabilities() {
    // No-op on non-Linux
}

fn write_error(exit_code: i32, error_type: &str, message: &str) -> ! {
    let err = ErrorResponse {
        error: error_type.to_string(),
        message: message.to_string(),
    };
    eprintln!("{}", serde_json::to_string(&err).unwrap_or_default());
    process::exit(exit_code);
}

fn main() {
    // 1. Read JSON from stdin
    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        write_error(EXIT_NOT_FOUND, "EINVAL", &format!("Failed to read stdin: {}", e));
    }

    let request: Request = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => write_error(EXIT_NOT_FOUND, "EINVAL", &format!("Invalid JSON input: {}", e)),
    };

    // 2. Find vault metadata and credential file
    let (meta, cred_path) = match find_vault_paths(&request.tool) {
        Ok(v) => v,
        Err((code, msg)) => write_error(code, "ENOENT", &msg),
    };

    // 3. Derive passphrase
    let passphrase = if meta.master_key_mode == "passphrase" {
        match std::env::var("OPENCLAW_VAULT_PASSPHRASE") {
            Ok(p) => p,
            Err(_) => write_error(
                EXIT_PERMISSION_DENIED,
                "EACCES",
                "Vault in passphrase mode but OPENCLAW_VAULT_PASSPHRASE not set",
            ),
        }
    } else {
        get_machine_passphrase(&meta.install_timestamp)
    };

    // 4. Read encrypted file
    let payload = match fs::read(&cred_path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            write_error(EXIT_PERMISSION_DENIED, "EPERM", &format!("Permission denied: {}", cred_path.display()));
        }
        Err(e) => {
            write_error(EXIT_NOT_FOUND, "EIO", &format!("Failed to read credential file: {}", e));
        }
    };

    // 5. Decrypt
    let credential = match decrypt_payload(&payload, &passphrase) {
        Ok(c) => c,
        Err(e) => write_error(EXIT_DECRYPT_FAILED, "EDECRYPT", &e),
    };

    // 6. Install seccomp filter (before writing to stdout)
    // After this point, only read/write/exit syscalls are allowed
    if let Err(e) = install_seccomp_filter() {
        // Non-fatal on non-Linux or if seccomp not available
        eprintln!("Warning: seccomp filter not installed: {}", e);
    }

    // 7. Write JSON response to stdout
    let response = SuccessResponse {
        credential,
        expires: None,
    };
    let output = serde_json::to_string(&response).unwrap_or_else(|_| {
        process::exit(EXIT_DECRYPT_FAILED);
    });
    println!("{}", output);

    // 8. Drop all capabilities
    drop_capabilities();

    // 9. Exit
    process::exit(EXIT_SUCCESS);
}

// ============================================================
// Tests
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Test that Argon2id key derivation produces deterministic output.
    #[test]
    fn test_argon2id_deterministic() {
        let passphrase = "test-passphrase";
        let salt = [0u8; 16]; // fixed salt for reproducibility

        let key1 = derive_key(passphrase, &salt).expect("derive_key should succeed");
        let key2 = derive_key(passphrase, &salt).expect("derive_key should succeed");

        assert_eq!(key1, key2, "Same passphrase + salt must produce same key");
        assert_eq!(key1.len(), 32, "Key must be 32 bytes (256 bits)");
    }

    /// Test that different salts produce different keys.
    #[test]
    fn test_argon2id_different_salt() {
        let passphrase = "test-passphrase";
        let salt1 = [0u8; 16];
        let salt2 = [1u8; 16];

        let key1 = derive_key(passphrase, &salt1).unwrap();
        let key2 = derive_key(passphrase, &salt2).unwrap();

        assert_ne!(key1, key2, "Different salts must produce different keys");
    }

    /// Test decrypt with a known payload.
    /// This creates an encrypted payload using the same primitives, then decrypts it.
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        use aes_gcm::aead::OsRng;

        let passphrase = "roundtrip-test-passphrase";
        let plaintext = "my-secret-api-key-12345";

        // Generate random salt and nonce
        let salt: [u8; SALT_LENGTH] = {
            let mut s = [0u8; SALT_LENGTH];
            use aes_gcm::aead::rand_core::RngCore;
            OsRng.fill_bytes(&mut s);
            s
        };
        let nonce_bytes: [u8; NONCE_LENGTH] = {
            let mut n = [0u8; NONCE_LENGTH];
            use aes_gcm::aead::rand_core::RngCore;
            OsRng.fill_bytes(&mut n);
            n
        };

        // Derive key
        let key = derive_key(passphrase, &salt).unwrap();

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext_with_tag = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("encryption should succeed");

        // aes-gcm appends the 16-byte auth tag to the ciphertext
        let ct_len = ciphertext_with_tag.len() - AUTH_TAG_LENGTH;
        let ciphertext = &ciphertext_with_tag[..ct_len];
        let auth_tag = &ciphertext_with_tag[ct_len..];

        // Build the file format: [salt][nonce][ciphertext][authTag]
        let mut payload = Vec::new();
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(ciphertext);
        payload.extend_from_slice(auth_tag);

        // Decrypt
        let decrypted = decrypt_payload(&payload, passphrase).expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    /// Test that decrypt fails with wrong passphrase.
    #[test]
    fn test_decrypt_wrong_passphrase() {
        use aes_gcm::aead::OsRng;

        let passphrase = "correct-passphrase";
        let plaintext = "secret";

        let salt: [u8; SALT_LENGTH] = {
            let mut s = [0u8; SALT_LENGTH];
            use aes_gcm::aead::rand_core::RngCore;
            OsRng.fill_bytes(&mut s);
            s
        };
        let nonce_bytes: [u8; NONCE_LENGTH] = {
            let mut n = [0u8; NONCE_LENGTH];
            use aes_gcm::aead::rand_core::RngCore;
            OsRng.fill_bytes(&mut n);
            n
        };

        let key = derive_key(passphrase, &salt).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct_with_tag = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .unwrap();

        let ct_len = ct_with_tag.len() - AUTH_TAG_LENGTH;
        let mut payload = Vec::new();
        payload.extend_from_slice(&salt);
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ct_with_tag[..ct_len]);
        payload.extend_from_slice(&ct_with_tag[ct_len..]);

        let result = decrypt_payload(&payload, "wrong-passphrase");
        assert!(result.is_err(), "Decryption with wrong passphrase should fail");
    }

    /// Test payload too short.
    #[test]
    fn test_decrypt_too_short() {
        let result = decrypt_payload(&[0u8; 10], "passphrase");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    /// Test machine passphrase derivation produces deterministic output.
    #[test]
    fn test_machine_passphrase_deterministic() {
        let ts = "2026-03-08T00:00:00.000Z";
        let p1 = get_machine_passphrase(ts);
        let p2 = get_machine_passphrase(ts);
        assert_eq!(p1, p2, "Same timestamp should produce same passphrase");
        assert_eq!(p1.len(), 64, "SHA-256 hex should be 64 chars");
    }

    /// Test JSON request deserialization.
    #[test]
    fn test_request_parsing() {
        let json = r#"{"tool": "gumroad", "context": "exec", "command": "curl api.gumroad.com"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.tool, "gumroad");
        assert_eq!(req.context.as_deref(), Some("exec"));
    }

    /// Test JSON response serialization.
    #[test]
    fn test_response_serialization() {
        let resp = SuccessResponse {
            credential: "test-key-123".to_string(),
            expires: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("test-key-123"));
        assert!(json.contains("\"expires\":null"));
    }
}

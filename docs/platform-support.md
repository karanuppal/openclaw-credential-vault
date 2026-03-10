# Platform Support

## Current: Linux (Fully Supported)

The credential vault is developed and tested on Linux (x86_64).

### What works

- **AES-256-GCM encryption** via Node.js `crypto` module (all platforms support this, but tested on Linux)
- **Argon2id key derivation** via the `argon2` npm package (native addon, builds on Linux)
- **Rust resolver binary** — statically linked musl binary for Linux x86_64
  - seccomp sandboxing (Linux-only kernel feature)
  - setuid support for OS-level user isolation
- **File permissions** — vault directory restricted to 0700 via POSIX filesystem permissions
- **SIGUSR2 hot-reload** — signals gateway to reload credentials without restart

### Tested configurations

| OS | Arch | Node.js | Status |
|----|------|---------|--------|
| Debian 11+ (Bullseye) | x86_64 | 20, 22 | ✅ Primary target |
| Ubuntu 22.04+ | x86_64 | 20, 22 | ✅ CI tested |

---

## Future: macOS (Exploration)

### Keychain Integration

macOS provides the system Keychain (`security` CLI / Security.framework) for credential storage. A future backend could:

- Store encrypted credentials in the user's login Keychain instead of flat `.enc` files
- Leverage Keychain Access Control Lists (ACLs) for per-app credential access
- Use `security find-generic-password` / `security add-generic-password` for CLI integration
- Benefit from hardware-backed key storage on Apple Silicon (Secure Enclave)

### Considerations

- **No seccomp equivalent.** macOS has App Sandbox and `sandbox-exec` (deprecated), but no equivalent fine-grained syscall filtering. The Rust resolver would need a different sandboxing strategy (possibly `sandbox_init` or just rely on Keychain ACLs).
- **setuid is discouraged** on macOS (SIP restrictions). Keychain-based access control is the idiomatic alternative.
- **Argon2 native addon** builds fine on macOS via Homebrew/Xcode CLIs.
- **Universal binary** — the Rust resolver would need to be built as a universal binary (x86_64 + aarch64) for Intel and Apple Silicon Macs.

### Implementation path

1. Create a `SecretBackend` interface (abstraction over storage mechanism)
2. Implement `KeychainBackend` using the `security` CLI or a Node.js native module
3. Auto-detect platform at init time, default to Keychain on macOS
4. Rust resolver: replace seccomp with Keychain-based access, or skip binary mode on macOS (inline decryption with Keychain is already well-isolated)

---

## Future: Windows (Exploration)

### Credential Manager / DPAPI Integration

Windows provides the Credential Manager (accessible via `cmdkey` CLI) and DPAPI (Data Protection API) for user-scoped encryption.

### Considerations

- **DPAPI** encrypts data tied to the current user's login credentials — similar to machine-mode key derivation but managed by the OS. Could replace the Argon2id key derivation on Windows entirely.
- **Credential Manager** stores credentials in the Windows Vault, accessible per-user. Good for individual tokens but may have size limits for large cookie blobs.
- **No setuid equivalent.** Windows uses different ACL and impersonation models. The Rust resolver would need a different isolation strategy (possibly running as a Windows Service with restricted token).
- **seccomp unavailable.** Windows has Job Objects and restricted tokens as alternatives, but the sandboxing model would be fundamentally different.
- **Path handling** — vault directory paths, permission checks, and signal handling (SIGUSR2) all need Windows-specific implementations.

### Implementation path

1. Extend `SecretBackend` interface with a `DpapiBackend`
2. Use DPAPI for encryption (via a Node.js native module or `powershell` CLI shim)
3. Replace SIGUSR2 with a named pipe or file-watching mechanism for hot-reload
4. Rust resolver: adapt to Windows security model or rely on DPAPI isolation

---

## Cross-Platform Architecture (Proposed)

```
SecretBackend (interface)
├── FileBackend       ← current (Linux, works everywhere as fallback)
├── KeychainBackend   ← macOS Keychain
├── DpapiBackend      ← Windows DPAPI
└── CustomBackend     ← user-extensible
```

The `FileBackend` will remain available on all platforms as a universal fallback. Platform-specific backends are opt-in enhancements that provide better OS integration.

---

_This document is exploratory. macOS and Windows support is not yet implemented. Contributions welcome._

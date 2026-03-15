# Release Notes — 1.0.0-beta.3

## Install verification

New CI jobs prove the plugin installs and works on a clean machine — not just from the source tree.

Three test combos run in Docker on every push:
- **Debian 12:** curl install + binary setup, plugin install + inline, plugin install + binary setup
- **Ubuntu 24.04:** curl install + binary setup, plugin install + binary setup

Each combo runs 5 commands inside a fresh container: install the plugin, init the vault, add a credential, test injection + scrubbing, remove the credential. If any step fails, CI fails.

This catches packaging bugs that source-tree tests can't: missing files in the npm tarball, dependencies in devDependencies instead of dependencies, setup script broken on a specific distro.

## Alpine dropped

Alpine Linux is explicitly not supported. OpenClaw itself doesn't install cleanly on Alpine (`node-llama-cpp` requires cmake/xpm, and `--ignore-scripts` breaks `openclaw plugins install`). The vault plugin code is platform-independent, but there's no way to test the full install path.

## Documentation refresh

All docs updated to match the current code:

- **README** rewritten for user clarity — leads with what you get, not implementation details
- **TESTING.md** — corrected test counts (610 passing, 0 failing), added missing test file documentation
- **ARCHITECTURE.md** — added protocol versioning, resolver failure handling, params.env injection model, Perl stdout scrubber, auto-reload on tool calls
- **SPEC.md** — updated injection flow and hot-reload mechanism
- **SECURITY-AUDIT.md** — updated test count
- **platform-support.md** — Alpine explicitly listed as not supported

---

Full documentation: [README](README.md) · [Architecture](docs/ARCHITECTURE.md) · [Threat Model](docs/THREAT-MODEL.md) · [Specification](docs/SPEC.md)

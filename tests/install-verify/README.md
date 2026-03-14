# Install Verification Tests

Tests that prove the vault plugin **installs correctly and works** on a clean machine. Complements the 610+ unit/integration tests which verify code logic.

## Quick Start

```bash
npm run verify-install
```

This runs:
1. `npm run build` — compile TypeScript
2. `npm pack` — create the same tarball that goes to npm
3. Build Debian 12 Docker image (cached after first run)
4. Run 3 install combos sequentially (~2 min)

**Requirements:** Docker must be installed and running.

## What It Tests

| Combo | Install | Setup | What It Proves |
|-------|---------|-------|----------------|
| I1+S2 | Curl script | Binary (automatic) | Full install path works, Perl auto-installed |
| I2+S1 | plugins install | Inline (no sudo) | Basic install works, Perl warning shown |
| I2+S2 | plugins install | Binary (manual sudo) | Manual setup path works |

Each combo runs 5 verification steps inside a clean Docker container:
1. Install the plugin
2. `vault init` — vault directory created
3. `vault add github --key <fake>` — credential encrypted + stored
4. `vault test github` — decryption works, injection rules correct
5. `vault remove github --purge` — full cleanup

## Running a Single Combo

```bash
bash tests/install-verify/run.sh --install I1 --setup S2
```

## Other Platforms (CI only)

Ubuntu 24 and Alpine images are available for CI:

```bash
bash tests/install-verify/run.sh --platform ubuntu24
bash tests/install-verify/run.sh --platform alpine
```

## Rebuilding the Docker Image

The base image is cached. To force a rebuild:

```bash
docker rmi vault-verify-debian12
npm run verify-install
```

Rebuild when:
- OpenClaw ships a new major version
- Base OS packages need updating
- Dockerfile changes

## Troubleshooting

### "openclaw: command not found" in container
The base image installs OpenClaw globally. If this fails during image build, check that `openclaw` is published to npm and the version satisfies the plugin's `peerDependencies`.

### "vault-setup.sh not found"
The plugin tarball didn't include `bin/vault-setup.sh`. Check that `bin/` is listed in `package.json` `files` array.

### S2 tests fail with "Binary resolver: OK" not found
The Rust binary isn't in the tarball or doesn't run on the target platform. Check `bin/<platform>-<arch>/` exists and contains the compiled resolver.

### Perl-related failures
- **I1/I2+S2:** `vault-setup.sh` should auto-install Perl. If it fails, the setup script's package manager detection may not work on the target OS.
- **I2+S1:** `vault init` should warn about missing Perl. If no warning appears, check the Perl detection logic in `src/cli.ts`.

## Output Format

Tests produce [TAP](https://testanything.org/) (Test Anything Protocol) output for easy parsing by CI tools.

## File Overview

- `run.sh` — Host-side orchestrator (build, pack, docker run)
- `entrypoint.sh` — Container-side test runner
- `install.sh` (project root, mounted at runtime) — Real install script, accepts optional local tarball arg
- `Dockerfile.debian12` — Debian 12 base image (local + CI)
- `Dockerfile.ubuntu24` — Ubuntu 24.04 base image (CI only)
- `Dockerfile.alpine` — Alpine base image (CI only)

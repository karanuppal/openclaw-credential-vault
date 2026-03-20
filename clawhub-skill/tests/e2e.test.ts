/**
 * End-to-End Tests for the OpenClaw Credential Vault Plugin.
 *
 * Three test suites:
 *   1. Phase 1 Full Flow (inline TypeScript mode)
 *   2. Phase 2 Full Flow (Rust binary mode)
 *   3. Phase 1 → Phase 2 Migration
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { execFileSync } from "node:child_process";

import {
  writeCredentialFile,
  readCredentialFile,
  getMachinePassphrase,
} from "../src/crypto.js";
import {
  initConfig,
  readConfig,
  writeConfig,
  upsertTool,
  readMeta,
} from "../src/config.js";
import { findMatchingRules, KNOWN_TOOLS } from "../src/registry.js";
import {
  compileScrubRules,
  scrubText,
  scrubLiteralCredential,
} from "../src/scrubber.js";
import { ToolConfig, VaultConfig } from "../src/types.js";

// ---- Helpers ----

const RESOLVER_BINARY = path.join(
  __dirname,
  "..",
  "resolver",
  "target",
  "x86_64-unknown-linux-musl",
  "release",
  "openclaw-vault-resolver"
);

function findBinary(): string | null {
  // Also check release without target triple
  const paths = [
    RESOLVER_BINARY,
    path.join(__dirname, "..", "resolver", "target", "release", "openclaw-vault-resolver"),
  ];
  for (const p of paths) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

const HAS_RESOLVER = findBinary() !== null;

/** Create a temp vault dir structure under a fake HOME */
function makeTempVault(): { home: string; vaultDir: string } {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "vault-e2e-"));
  const vaultDir = path.join(home, ".openclaw", "vault");
  fs.mkdirSync(vaultDir, { recursive: true });
  return { home, vaultDir };
}

/** Invoke the Rust binary directly, using a fake HOME so it finds our vault */
function rustDecrypt(
  binaryPath: string,
  fakeHome: string,
  toolName: string,
  passphrase?: string
): { credential: string; expires: string | null } {
  const request = JSON.stringify({ tool: toolName, context: "exec", command: "test" });
  const env: Record<string, string> = { HOME: fakeHome };
  if (passphrase) env.OPENCLAW_VAULT_PASSPHRASE = passphrase;

  const result = execFileSync(binaryPath, [], {
    input: request,
    env,
    timeout: 60000,
  });
  return JSON.parse(result.toString().trim());
}

/** Build a ToolConfig from KNOWN_TOOLS for a given tool name */
function knownToolConfig(name: string): ToolConfig {
  const def = KNOWN_TOOLS[name];
  if (!def) throw new Error(`Unknown tool: ${name}`);
  return {
    name,
    addedAt: new Date().toISOString(),
    lastRotated: new Date().toISOString(),
    inject: def.inject,
    scrub: def.scrub,
  };
}

// ================================================================
// E2E Suite 1: Phase 1 Full Flow (inline mode)
// ================================================================
describe("E2E Suite 1: Phase 1 Full Flow (inline mode)", () => {
  let home: string;
  let vaultDir: string;
  let passphrase: string;
  let config: VaultConfig;
  const STRIPE_KEY = "sk_test_abc123def456ghi789xyzw01234";

  beforeAll(async () => {
    // 1. Setup: create temp vault, init config with machine mode
    ({ home, vaultDir } = makeTempVault());
    config = initConfig(vaultDir, "machine");
    const meta = readMeta(vaultDir);
    expect(meta).not.toBeNull();
    passphrase = getMachinePassphrase(meta!.installTimestamp);
  });

  afterAll(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("should store and retrieve a Stripe credential", async () => {
    // 2. vault add: write credential + save tool config
    await writeCredentialFile(vaultDir, "stripe", STRIPE_KEY, passphrase);

    const toolConfig = knownToolConfig("stripe");
    config = upsertTool(config, toolConfig);
    writeConfig(vaultDir, config);

    // Verify round-trip via TS
    const decrypted = await readCredentialFile(vaultDir, "stripe", passphrase);
    expect(decrypted).toBe(STRIPE_KEY);
  });

  it("should match injection rules for a Stripe-related exec command", () => {
    // 3. before_tool_call simulation
    const reloadedConfig = readConfig(vaultDir);
    const stripeRules = reloadedConfig.tools["stripe"]?.inject ?? [];

    const matchingRules = findMatchingRules(
      "exec",
      { command: "curl api.stripe.com/v1/charges" },
      stripeRules
    );

    expect(matchingRules.length).toBeGreaterThan(0);
    // The matched rule should have env with STRIPE_API_KEY
    const envRule = matchingRules.find((r) => r.env?.STRIPE_API_KEY);
    expect(envRule).toBeDefined();
    expect(envRule!.env!.STRIPE_API_KEY).toBe("$vault:stripe");
  });

  it("should resolve vault refs to actual credential values", async () => {
    // Simulate resolving $vault:stripe → actual key
    const cred = await readCredentialFile(vaultDir, "stripe", passphrase);
    expect(cred).toBe(STRIPE_KEY);
    // In the real hook, $vault:stripe in env values gets replaced with this
  });

  it("should scrub credentials from tool output (after_tool_call)", () => {
    // 4. after_tool_call / tool_result_persist simulation
    const reloadedConfig = readConfig(vaultDir);
    const rules = compileScrubRules(reloadedConfig.tools);

    const dirtyOutput = `Error: Invalid API key ${STRIPE_KEY} for request`;
    const scrubbed = scrubText(dirtyOutput, rules);

    expect(scrubbed).toBe("Error: Invalid API key [VAULT:stripe] for request");
    expect(scrubbed).not.toContain(STRIPE_KEY);
  });

  it("should scrub credentials from outbound messages (message_sending)", () => {
    // 5. message_sending simulation
    const reloadedConfig = readConfig(vaultDir);
    const rules = compileScrubRules(reloadedConfig.tools);

    const message = `Tried key ${STRIPE_KEY} but it failed`;
    let scrubbed = scrubText(message, rules);
    scrubbed = scrubLiteralCredential(scrubbed, STRIPE_KEY, "stripe");

    expect(scrubbed).not.toContain(STRIPE_KEY);
    expect(scrubbed).toContain("[VAULT:stripe]");
  });

  it("should never leak the credential in any scrubbed output", () => {
    // 6. Comprehensive leakage check
    const reloadedConfig = readConfig(vaultDir);
    const rules = compileScrubRules(reloadedConfig.tools);

    const testStrings = [
      `Key: ${STRIPE_KEY}`,
      `"api_key": "${STRIPE_KEY}"`,
      `${STRIPE_KEY}\n${STRIPE_KEY}`,
      `prefix_${STRIPE_KEY}_suffix`,
    ];

    for (const input of testStrings) {
      let scrubbed = scrubText(input, rules);
      scrubbed = scrubLiteralCredential(scrubbed, STRIPE_KEY, "stripe");
      expect(scrubbed).not.toContain(STRIPE_KEY);
    }
  });
});

// ================================================================
// E2E Suite 2: Phase 2 Full Flow (binary mode)
// ================================================================
describe.skipIf(!HAS_RESOLVER)("E2E Suite 2: Phase 2 Full Flow (binary mode)", () => {
  let home: string;
  let vaultDir: string;
  let passphrase: string;
  let config: VaultConfig;
  let binaryPath: string;
  const GUMROAD_KEY = "gum_test1234567890abcdef";

  beforeAll(async () => {
    // 1. Setup
    binaryPath = findBinary()!;
    ({ home, vaultDir } = makeTempVault());
    config = initConfig(vaultDir, "machine");
    const meta = readMeta(vaultDir);
    passphrase = getMachinePassphrase(meta!.installTimestamp);

    // Write credential + tool config
    await writeCredentialFile(vaultDir, "gumroad", GUMROAD_KEY, passphrase);
    const toolConfig = knownToolConfig("gumroad");
    config = upsertTool(config, toolConfig);
    config.resolverMode = "binary";
    writeConfig(vaultDir, config);
  });

  afterAll(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it("should have the Rust resolver binary available", () => {
    // 2. Build check
    expect(fs.existsSync(binaryPath)).toBe(true);
  });

  it("should decrypt a credential via the Rust binary", () => {
    // 3. Binary resolution — invoke directly with fake HOME
    const response = rustDecrypt(binaryPath, home, "gumroad");
    expect(response.credential).toBe(GUMROAD_KEY);
  });

  it("should scrub binary-resolved credentials from outputs", () => {
    // 4. Injection + scrubbing
    const reloadedConfig = readConfig(vaultDir);
    const rules = compileScrubRules(reloadedConfig.tools);

    const output = `Token ${GUMROAD_KEY} is expired`;
    const scrubbed = scrubText(output, rules);
    expect(scrubbed).toBe("Token [VAULT:gumroad] is expired");
    expect(scrubbed).not.toContain(GUMROAD_KEY);
  });

  it("should handle credential rotation correctly", async () => {
    // 5. Credential rotation
    const NEW_GUMROAD_KEY = "gum_rotated99887766xyzw";

    // Write a new credential (overwrite)
    await writeCredentialFile(vaultDir, "gumroad", NEW_GUMROAD_KEY, passphrase);

    // Rust binary should decrypt the new credential
    const response = rustDecrypt(binaryPath, home, "gumroad");
    expect(response.credential).toBe(NEW_GUMROAD_KEY);

    // Scrubbing should catch both old pattern and new credential
    const reloadedConfig = readConfig(vaultDir);
    const rules = compileScrubRules(reloadedConfig.tools);

    // New key matches gum_[a-zA-Z0-9]{16,} pattern
    const outputNew = `Token ${NEW_GUMROAD_KEY} used`;
    const scrubbedNew = scrubText(outputNew, rules);
    expect(scrubbedNew).not.toContain(NEW_GUMROAD_KEY);

    // Old key also still matches the scrub pattern
    const outputOld = `Old token ${GUMROAD_KEY} leaked`;
    const scrubbedOld = scrubText(outputOld, rules);
    expect(scrubbedOld).not.toContain(GUMROAD_KEY);
  });
});

// ================================================================
// E2E Suite 3: Phase 1 → Phase 2 Migration
// ================================================================
describe.skipIf(!HAS_RESOLVER)("E2E Suite 3: Phase 1 → Phase 2 Migration", () => {
  let homeP1: string;
  let vaultDirP1: string;
  let homeP2: string;
  let vaultDirP2: string;
  let passphrase: string;
  let binaryPath: string;
  let installTimestamp: string;

  const CREDS: Record<string, string> = {
    stripe: "sk_test_migration1234567890abcdef",
    github: "ghp_migration1234567890abcdef1234567890ab",
    gumroad: "gum_migration1234567890ab",
  };

  beforeAll(async () => {
    binaryPath = findBinary()!;

    // 1. Phase 1 setup
    ({ home: homeP1, vaultDir: vaultDirP1 } = makeTempVault());
    const configP1 = initConfig(vaultDirP1, "machine");
    const meta = readMeta(vaultDirP1);
    installTimestamp = meta!.installTimestamp;
    passphrase = getMachinePassphrase(installTimestamp);

    // Add 3 credentials
    let cfg = configP1;
    for (const [name, cred] of Object.entries(CREDS)) {
      await writeCredentialFile(vaultDirP1, name, cred, passphrase);
      cfg = upsertTool(cfg, knownToolConfig(name));
    }
    writeConfig(vaultDirP1, cfg);

    // 3. Simulate migration — copy enc files + meta to new dir
    ({ home: homeP2, vaultDir: vaultDirP2 } = makeTempVault());
    // Copy .vault-meta.json
    fs.copyFileSync(
      path.join(vaultDirP1, ".vault-meta.json"),
      path.join(vaultDirP2, ".vault-meta.json")
    );
    // Copy .enc files
    for (const name of Object.keys(CREDS)) {
      fs.copyFileSync(
        path.join(vaultDirP1, `${name}.enc`),
        path.join(vaultDirP2, `${name}.enc`)
      );
    }
    // Copy tools.yaml and set resolverMode to binary
    const migratedConfig = readConfig(vaultDirP1);
    migratedConfig.resolverMode = "binary";
    writeConfig(vaultDirP2, migratedConfig);
  });

  afterAll(() => {
    fs.rmSync(homeP1, { recursive: true, force: true });
    fs.rmSync(homeP2, { recursive: true, force: true });
  });

  it("should decrypt all 3 credentials in Phase 1 (TypeScript)", async () => {
    // 2. Phase 1 verification
    for (const [name, expected] of Object.entries(CREDS)) {
      const decrypted = await readCredentialFile(vaultDirP1, name, passphrase);
      expect(decrypted).toBe(expected);
    }
  });

  it("should decrypt all 3 credentials in Phase 2 (Rust binary)", () => {
    // 4. Phase 2 verification — same files, different runtime
    for (const [name, expected] of Object.entries(CREDS)) {
      const response = rustDecrypt(binaryPath, homeP2, name);
      expect(response.credential).toBe(expected);
    }
  });

  it("should produce identical results between Phase 1 and Phase 2", async () => {
    for (const name of Object.keys(CREDS)) {
      const tsResult = await readCredentialFile(vaultDirP1, name, passphrase);
      const rustResult = rustDecrypt(binaryPath, homeP2, name);
      expect(tsResult).toBe(rustResult.credential);
    }
  });

  it("should round-trip config with resolverMode set to binary", () => {
    // 5. Config migration
    const cfg = readConfig(vaultDirP2);
    expect(cfg.resolverMode).toBe("binary");

    // Verify tools survived the migration
    expect(Object.keys(cfg.tools)).toEqual(
      expect.arrayContaining(["stripe", "github", "gumroad"])
    );

    // Write and re-read to verify round-trip
    writeConfig(vaultDirP2, cfg);
    const reloaded = readConfig(vaultDirP2);
    expect(reloaded.resolverMode).toBe("binary");
    expect(Object.keys(reloaded.tools).length).toBe(3);
  });

  it("should allow adding a 4th credential in Phase 2 mode", async () => {
    // 6. Mixed operations — encrypt with TS, decrypt with Rust
    const ACME_KEY = "acme_crm_secret_key_9876543210";
    await writeCredentialFile(vaultDirP2, "acme-crm", ACME_KEY, passphrase);

    // Rust binary can decrypt it
    const response = rustDecrypt(binaryPath, homeP2, "acme-crm");
    expect(response.credential).toBe(ACME_KEY);

    // TS can also still decrypt it
    const tsResult = await readCredentialFile(vaultDirP2, "acme-crm", passphrase);
    expect(tsResult).toBe(ACME_KEY);

    // Original 3 credentials are still intact
    for (const [name, expected] of Object.entries(CREDS)) {
      const r = rustDecrypt(binaryPath, homeP2, name);
      expect(r.credential).toBe(expected);
    }
  });
});

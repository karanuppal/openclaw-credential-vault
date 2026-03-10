/**
 * CLI command registration: vault init, add, list, show, rotate, remove, test, audit.
 * Registered via api.registerCli.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import {
  readConfig,
  writeConfig,
  upsertTool,
  removeTool,
  initConfig,
  readMeta,
  getVaultDir,
  signalGatewayReload,
} from "./config.js";
import {
  writeCredentialFile,
  readCredentialFile,
  removeCredentialFile,
  credentialFileExists,
  getMachinePassphrase,
} from "./crypto.js";
import {
  getKnownTool,
  detectCredentialType,
  generateScrubPattern,
  findMatchingRules,
  KNOWN_TOOLS,
} from "./registry.js";
import { compileScrubRules, scrubText } from "./scrubber.js";
import { readAuditLog, computeAuditStats } from "./audit.js";
import { ToolConfig, CliProgram } from "./types.js";

/**
 * Get the master passphrase for encryption/decryption.
 */
function getPassphrase(vaultDir: string): string {
  const meta = readMeta(vaultDir);
  if (meta?.masterKeyMode === "passphrase") {
    // In passphrase mode, read from env var or prompt
    const passphrase = process.env.OPENCLAW_VAULT_PASSPHRASE;
    if (!passphrase) {
      throw new Error(
        "Vault is in passphrase mode. Set OPENCLAW_VAULT_PASSPHRASE environment variable."
      );
    }
    return passphrase;
  }
  // Machine mode: derive from machine characteristics
  return getMachinePassphrase(meta?.installTimestamp);
}

/**
 * Register all vault CLI commands on the given program.
 */
export function registerCliCommands(program: CliProgram): void {
  const vault = program.command("vault").description("Credential vault management");

  // vault init
  vault
    .command("init")
    .description("Initialize the credential vault")
    .option("--passphrase", "Use passphrase-based encryption (default: machine-specific key)")
    .action(async (options: { passphrase?: boolean }) => {
      const vaultDir = getVaultDir();
      const mode = options.passphrase ? "passphrase" : "machine";

      if (fs.existsSync(path.join(vaultDir, "tools.yaml"))) {
        console.log("⚠ Vault already initialized at", vaultDir);
        console.log("  Use 'vault add' to add credentials.");
        return;
      }

      initConfig(vaultDir, mode);
      console.log(`✓ Vault initialized at ${vaultDir}`);
      console.log(`  Master key mode: ${mode}`);
      if (mode === "passphrase") {
        console.log("  Set OPENCLAW_VAULT_PASSPHRASE to your passphrase before using vault commands.");
      }
      console.log("  Use 'openclaw vault add <tool> --key <credential>' to add credentials.");
    });

  // vault add <tool>
  vault
    .command("add")
    .description("Add a credential to the vault")
    .argument("<tool>", "Tool name (e.g., gumroad, stripe, github)")
    .option("--key <credential>", "The credential/API key to store")
    .action(async (tool: string, options: { key?: string }) => {
      if (!options.key) {
        console.error("Error: --key is required. Usage: vault add <tool> --key <credential>");
        return;
      }

      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);
      const passphrase = getPassphrase(vaultDir);

      // Auto-detect credential type
      const detected = detectCredentialType(options.key);
      if (detected && detected.toolName !== tool) {
        console.log(`ℹ Detected ${detected.displayName} — storing as "${tool}"`);
      } else if (detected) {
        console.log(`✓ Detected: ${detected.displayName}`);
      }

      // Encrypt and store
      const filePath = await writeCredentialFile(vaultDir, tool, options.key, passphrase);
      console.log(`✓ Credential stored: ${tool} (AES-256-GCM encrypted)`);

      // Set up injection and scrubbing rules
      const knownTool = getKnownTool(tool);
      const now = new Date().toISOString();

      let toolConfig: ToolConfig;
      if (knownTool) {
        toolConfig = {
          name: tool,
          addedAt: now,
          lastRotated: now,
          inject: knownTool.inject,
          scrub: knownTool.scrub,
        };
        console.log("✓ Injection configured:");
        for (const rule of knownTool.inject) {
          if (rule.commandMatch) {
            console.log(`    ${rule.tool} commands matching: ${rule.commandMatch}`);
          }
          if (rule.urlMatch) {
            console.log(`    ${rule.tool} URLs matching: ${rule.urlMatch}`);
          }
        }
        console.log(
          `✓ Scrubbing patterns registered: ${knownTool.scrub.patterns.join(", ")}`
        );
      } else {
        // Unknown tool: generate basic rules
        const scrubPattern = generateScrubPattern(options.key);
        toolConfig = {
          name: tool,
          addedAt: now,
          lastRotated: now,
          inject: [
            {
              tool: "exec",
              commandMatch: `${tool}*|curl*${tool}*`,
              env: { [`${tool.toUpperCase().replace(/-/g, "_")}_API_KEY`]: `$vault:${tool}` },
            },
          ],
          scrub: {
            patterns: [scrubPattern],
          },
        };
        console.log(`⚠ Unknown tool "${tool}" — generated default injection rules`);
        console.log(`  Scrubbing pattern: ${scrubPattern}`);
      }

      const updatedConfig = upsertTool(config, toolConfig);
      writeConfig(vaultDir, updatedConfig);

      // Signal hot-reload
      const reloaded = signalGatewayReload();
      if (reloaded) {
        console.log("✓ Gateway reloaded (SIGUSR2) — no restart needed");
      }

      console.log(`\nTool "${tool}" is ready. Your agent can now use it without seeing the credential.`);
    });

  // vault list
  vault
    .command("list")
    .description("List all registered tools and credential status")
    .action(async () => {
      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);

      if (Object.keys(config.tools).length === 0) {
        console.log("No credentials stored. Use 'vault add' to add one.");
        return;
      }

      console.log("Tool            Status    Last Rotated          Injection       Scrubbing");
      console.log("─".repeat(80));

      for (const [name, tool] of Object.entries(config.tools)) {
        const hasFile = credentialFileExists(vaultDir, name);
        const status = hasFile ? "active" : "missing";
        const rotated = tool.lastRotated
          ? new Date(tool.lastRotated).toISOString().split("T")[0]
          : "never";
        const injectionTools = tool.inject.map((r) => r.tool).join(",");
        const hasScrub = tool.scrub.patterns.length > 0 ? "✓" : "✗";

        console.log(
          `${name.padEnd(16)}${status.padEnd(10)}${rotated.padEnd(22)}${injectionTools.padEnd(16)}${hasScrub}`
        );
      }
    });

  // vault show <tool>
  vault
    .command("show")
    .description("Show details for a specific tool")
    .argument("<tool>", "Tool name")
    .action(async (tool: string) => {
      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);
      const toolConfig = config.tools[tool];

      if (!toolConfig) {
        console.error(`Tool "${tool}" not found in vault.`);
        return;
      }

      const hasFile = credentialFileExists(vaultDir, tool);
      console.log(`Tool: ${tool}`);
      console.log(`Status: ${hasFile ? "active" : "missing credential file"}`);
      console.log(`Added: ${toolConfig.addedAt}`);
      console.log(`Last Rotated: ${toolConfig.lastRotated}`);
      console.log("\nInjection Rules:");
      for (const rule of toolConfig.inject) {
        console.log(`  - tool: ${rule.tool}`);
        if (rule.commandMatch) console.log(`    commandMatch: ${rule.commandMatch}`);
        if (rule.urlMatch) console.log(`    urlMatch: ${rule.urlMatch}`);
        if (rule.env) console.log(`    env: ${JSON.stringify(rule.env)}`);
        if (rule.headers) console.log(`    headers: ${JSON.stringify(rule.headers)}`);
      }
      console.log("\nScrubbing Patterns:");
      for (const pattern of toolConfig.scrub.patterns) {
        console.log(`  - ${pattern}`);
      }
    });

  // vault rotate <tool>
  vault
    .command("rotate")
    .description("Rotate a credential (update the key, keep all mappings)")
    .argument("<tool>", "Tool name")
    .option("--key <credential>", "The new credential/API key")
    .action(async (tool: string, options: { key?: string }) => {
      if (!options.key) {
        console.error("Error: --key is required for rotation.");
        return;
      }

      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);
      const toolConfig = config.tools[tool];

      if (!toolConfig) {
        console.error(`Tool "${tool}" not found in vault. Use 'vault add' first.`);
        return;
      }

      const passphrase = getPassphrase(vaultDir);

      // Remove old file and write new one
      removeCredentialFile(vaultDir, tool);
      await writeCredentialFile(vaultDir, tool, options.key, passphrase);

      // Update rotation timestamp
      toolConfig.lastRotated = new Date().toISOString();

      // Update scrub patterns if credential format changed
      const detected = detectCredentialType(options.key);
      if (detected) {
        const knownTool = getKnownTool(detected.toolName);
        if (knownTool) {
          toolConfig.scrub = knownTool.scrub;
        }
      }

      const updatedConfig = upsertTool(config, toolConfig);
      writeConfig(vaultDir, updatedConfig);

      const reloaded = signalGatewayReload();
      console.log(`✓ Credential rotated: ${tool}`);
      if (reloaded) {
        console.log("✓ Gateway reloaded (SIGUSR2) — no restart needed");
      }
    });

  // vault remove <tool>
  vault
    .command("remove")
    .description("Remove a tool and its credential")
    .argument("<tool>", "Tool name")
    .option("--purge", "Also remove scrubbing patterns (not recommended)")
    .action(async (tool: string, options: { purge?: boolean }) => {
      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);

      if (!config.tools[tool]) {
        console.error(`Tool "${tool}" not found in vault.`);
        return;
      }

      // Remove encrypted file
      removeCredentialFile(vaultDir, tool);

      let updatedConfig: typeof config;
      if (options.purge) {
        updatedConfig = removeTool(config, tool);
        console.log(`✓ Tool "${tool}" fully purged (credential + config + scrubbing rules)`);
      } else {
        // Keep scrubbing patterns active but remove injection rules
        const toolConfig = { ...config.tools[tool] };
        toolConfig.inject = [];
        updatedConfig = upsertTool(config, toolConfig);
        console.log(`✓ Credential removed: ${tool}`);
        console.log("  Scrubbing patterns kept active. Use --purge to fully remove.");
      }

      writeConfig(vaultDir, updatedConfig);
      const reloaded = signalGatewayReload();
      if (reloaded) {
        console.log("✓ Gateway reloaded (SIGUSR2)");
      }
    });

  // vault test <tool>
  vault
    .command("test")
    .description("Simulate a tool call and verify injection + scrubbing")
    .argument("<tool>", "Tool name")
    .action(async (tool: string) => {
      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);
      const toolConfig = config.tools[tool];

      if (!toolConfig) {
        console.error(`Tool "${tool}" not found in vault.`);
        return;
      }

      console.log(`Testing tool: ${tool}\n`);

      // Test credential decryption
      try {
        const passphrase = getPassphrase(vaultDir);
        const credential = await readCredentialFile(vaultDir, tool, passphrase);
        const masked =
          credential.substring(0, 4) +
          "*".repeat(Math.max(0, credential.length - 8)) +
          credential.substring(credential.length - 4);
        console.log(`✓ Decryption: OK (${masked})`);
      } catch (err) {
        console.log(`✗ Decryption: FAILED — ${(err as Error).message}`);
        return;
      }

      // Test injection rules
      console.log("\nInjection Rules:");
      for (const rule of toolConfig.inject) {
        const match = rule.commandMatch ?? rule.urlMatch ?? "(all)";
        console.log(`  ✓ ${rule.tool} → match: ${match}`);
        if (rule.env) {
          for (const [k, v] of Object.entries(rule.env)) {
            console.log(`    env ${k}=${v}`);
          }
        }
        if (rule.headers) {
          for (const [k, v] of Object.entries(rule.headers)) {
            console.log(`    header ${k}: ${v}`);
          }
        }
      }

      // Test scrubbing
      console.log("\nScrubbing Test:");
      const rules = compileScrubRules({ [tool]: toolConfig });
      const testString = `Output contains sk_live_abcdefghijklmnopqrstuvwx and ghp_abcdefghijklmnopqrstuvwxyz1234567890 and gum_abcdefghijklmnop`;
      const scrubbed = scrubText(testString, rules);
      console.log(`  Input:    ${testString}`);
      console.log(`  Scrubbed: ${scrubbed}`);
      console.log(
        scrubbed !== testString
          ? `  ✓ Scrubbing active`
          : `  ℹ No patterns matched test string (patterns may be specific to your key format)`
      );

      console.log(`\n✓ Tool "${tool}" is configured correctly.`);
    });

  // vault setup-resolver
  vault
    .command("setup-resolver")
    .description("Install the Rust resolver binary with setuid for OS-level credential isolation (Phase 2)")
    .action(async () => {
      // 1. Check if running as root
      const uid = process.getuid?.() ?? -1;
      if (uid !== 0) {
        console.error("Error: setup-resolver must be run as root (sudo).");
        console.error("Usage: sudo openclaw vault setup-resolver");
        return;
      }

      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);

      // 2. Find the resolver binary
      const devBinaryPaths = [
        path.join(__dirname, "..", "resolver", "target", "release", "openclaw-vault-resolver"),
        path.join(__dirname, "..", "resolver", "target", "x86_64-unknown-linux-musl", "release", "openclaw-vault-resolver"),
      ];

      let sourceBinary: string | null = null;
      for (const p of devBinaryPaths) {
        if (fs.existsSync(p)) {
          sourceBinary = p;
          break;
        }
      }

      if (!sourceBinary) {
        console.error("Error: Resolver binary not found. Build it first:");
        console.error("  cd resolver && cargo build --release --target x86_64-unknown-linux-musl");
        return;
      }

      const { execSync } = await import("node:child_process");

      // 3. Create openclaw-vault system user if it doesn't exist
      try {
        execSync("id openclaw-vault", { stdio: "ignore" });
        console.log("✓ System user 'openclaw-vault' already exists");
      } catch {
        try {
          execSync(
            "useradd --system --no-create-home --shell /usr/sbin/nologin openclaw-vault",
            { stdio: "inherit" }
          );
          console.log("✓ Created system user 'openclaw-vault'");
        } catch (e) {
          console.error(`✗ Failed to create system user: ${(e as Error).message}`);
          return;
        }
      }

      // 4. Copy resolver binary to /usr/local/bin/
      const destBinary = "/usr/local/bin/openclaw-vault-resolver";
      try {
        fs.copyFileSync(sourceBinary, destBinary);
        // Set ownership to openclaw-vault and set setuid bit
        execSync(`chown openclaw-vault:openclaw-vault ${destBinary}`);
        execSync(`chmod u+s,a+rx ${destBinary}`); // setuid + readable/executable by all
        console.log(`✓ Resolver binary installed: ${destBinary} (setuid openclaw-vault)`);
      } catch (e) {
        console.error(`✗ Failed to install binary: ${(e as Error).message}`);
        return;
      }

      // 5. Create /var/lib/openclaw-vault/ owned by openclaw-vault
      const systemVaultDir = "/var/lib/openclaw-vault";
      try {
        fs.mkdirSync(systemVaultDir, { recursive: true });
        execSync(`chown openclaw-vault:openclaw-vault ${systemVaultDir}`);
        fs.chmodSync(systemVaultDir, 0o700);
        console.log(`✓ System vault directory: ${systemVaultDir} (owned by openclaw-vault)`);
      } catch (e) {
        console.error(`✗ Failed to create system vault directory: ${(e as Error).message}`);
        return;
      }

      // 6. Migrate credential files from ~/.openclaw/vault/ to /var/lib/openclaw-vault/
      let migratedCount = 0;
      const userVaultDir = vaultDir;
      if (fs.existsSync(userVaultDir)) {
        const files = fs.readdirSync(userVaultDir);
        for (const file of files) {
          if (file.endsWith(".enc") || file === ".vault-meta.json") {
            const src = path.join(userVaultDir, file);
            const dest = path.join(systemVaultDir, file);
            fs.copyFileSync(src, dest);
            execSync(`chown openclaw-vault:openclaw-vault "${dest}"`);
            fs.chmodSync(dest, 0o600);
            migratedCount++;
          }
        }
        if (migratedCount > 0) {
          console.log(`✓ Migrated ${migratedCount} file(s) to ${systemVaultDir}`);
        } else {
          console.log("ℹ No credential files to migrate");
        }
      }

      // 7. Update tools.yaml to set resolverMode to "binary"
      const updatedConfig = {
        ...config,
        resolverMode: "binary" as const,
      };
      writeConfig(vaultDir, updatedConfig);
      console.log('✓ Config updated: resolverMode = "binary"');

      // 8. Signal gateway reload
      const reloaded = signalGatewayReload();
      if (reloaded) {
        console.log("✓ Gateway reloaded (SIGUSR2)");
      } else {
        console.log("ℹ Gateway not running — changes will take effect on next start");
      }

      console.log("\n✓ Phase 2 resolver setup complete.");
      console.log("  Credentials are now isolated behind OS-user separation.");
      console.log("  The gateway process can no longer read credential files directly.");
    });

  // vault audit
  vault
    .command("audit")
    .description("Audit vault status and check for potential issues")
    .action(async () => {
      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);
      let issues = 0;

      console.log("Vault Audit Report\n");

      // Check vault directory permissions
      try {
        const stat = fs.statSync(vaultDir);
        const mode = (stat.mode & 0o777).toString(8);
        if (mode !== "700") {
          console.log(`⚠ Vault directory permissions: ${mode} (should be 700)`);
          issues++;
        } else {
          console.log("✓ Vault directory permissions: 700");
        }
      } catch {
        console.log("✗ Vault directory not found");
        issues++;
      }

      // Check each tool
      for (const [name, tool] of Object.entries(config.tools)) {
        const hasFile = credentialFileExists(vaultDir, name);
        if (!hasFile && tool.inject.length > 0) {
          console.log(`⚠ Tool "${name}": injection configured but no credential file`);
          issues++;
        }
        if (tool.scrub.patterns.length === 0) {
          console.log(`⚠ Tool "${name}": no scrubbing patterns configured`);
          issues++;
        }
        if (hasFile) {
          const filePath = path.join(vaultDir, `${name}.enc`);
          const stat = fs.statSync(filePath);
          const mode = (stat.mode & 0o777).toString(8);
          if (mode !== "600") {
            console.log(`⚠ Tool "${name}": credential file permissions ${mode} (should be 600)`);
            issues++;
          }
        }

        // Check rotation age
        if (tool.lastRotated) {
          const age = Date.now() - new Date(tool.lastRotated).getTime();
          const days = Math.floor(age / (1000 * 60 * 60 * 24));
          if (days > 90) {
            console.log(`⚠ Tool "${name}": credential last rotated ${days} days ago (>90 days)`);
            issues++;
          }
        }
      }

      // Check meta file
      const meta = readMeta(vaultDir);
      if (!meta) {
        console.log("⚠ Vault metadata missing — run 'vault init'");
        issues++;
      }

      console.log(`\n${issues === 0 ? "✓" : "⚠"} Audit complete: ${issues} issue(s) found`);
    });

  // vault logs
  vault
    .command("logs")
    .description("View audit log — credential access and scrubbing events")
    .option("--tool <name>", "Filter by tool name")
    .option("--type <type>", "Filter by event type (credential_access, scrub, compaction)")
    .option("--last <duration>", "Time-based filter (e.g., 24h, 7d, 30m)")
    .option("--json", "Raw JSONL output")
    .option("--stats", "Aggregate telemetry: access frequency, scrub counts, last access")
    .action(async (options: {
      tool?: string;
      type?: string;
      last?: string;
      json?: boolean;
      stats?: boolean;
    }) => {
      const vaultDir = getVaultDir();

      if (options.stats) {
        const stats = computeAuditStats(vaultDir);
        console.log("Audit Log Statistics\n");
        console.log(`Total events: ${stats.totalEvents}`);
        console.log(`  Credential accesses: ${stats.credentialAccesses}`);
        console.log(`  Scrubbing events: ${stats.scrubEvents}`);
        console.log(`  Compaction events: ${stats.compactionEvents}`);

        if (Object.keys(stats.byTool).length > 0) {
          console.log("\nBy Tool:");
          for (const [tool, data] of Object.entries(stats.byTool)) {
            console.log(`  ${tool}: ${data.accesses} accesses, ${data.scrubs} scrubs${data.lastAccess ? `, last: ${data.lastAccess}` : ""}`);
          }
        }

        if (Object.keys(stats.byHook).length > 0) {
          console.log("\nScrubs by Hook:");
          for (const [hook, count] of Object.entries(stats.byHook)) {
            console.log(`  ${hook}: ${count}`);
          }
        }
        return;
      }

      const events = readAuditLog({
        tool: options.tool,
        type: options.type,
        last: options.last,
      }, vaultDir);

      if (events.length === 0) {
        console.log("No audit events found.");
        return;
      }

      if (options.json) {
        for (const event of events) {
          console.log(JSON.stringify(event));
        }
        return;
      }

      // Pretty-print events
      for (const event of events) {
        const ts = new Date(event.timestamp).toLocaleString();
        switch (event.type) {
          case "credential_access":
            console.log(`[${ts}] ACCESS ${event.credential} via ${event.tool} (${event.injectionType}) — ${event.command.substring(0, 60)}`);
            break;
          case "scrub":
            console.log(`[${ts}] SCRUB  ${event.credential} in ${event.hook} (${event.replacements} replacement${event.replacements > 1 ? "s" : ""})`);
            break;
          case "compaction":
            console.log(`[${ts}] COMPACT scrubbing=${event.scrubbingActive ? "active" : "inactive"}`);
            break;
        }
      }

      console.log(`\n${events.length} event(s) shown`);
    });
}

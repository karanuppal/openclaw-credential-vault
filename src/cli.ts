/**
 * CLI command registration: vault init, add, list, show, rotate, remove, test, audit.
 * Registered via api.registerCli.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import {
  readConfig,
  writeConfig,
  upsertTool,
  removeTool,
  initConfig,
  readMeta,
  getVaultDir,
  signalGatewayReload,
  getOverdueCredentials,
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
import {
  guessCredentialFormat,
  formatGuessDisplay,
  buildToolConfigFromGuess,
} from "./guesser.js";
import {
  parseCookieJson,
  parseNetscapeCookies,
  getEarliestExpiry,
} from "./browser.js";
import { ToolConfig, CliProgram, PlaywrightCookie } from "./types.js";

/**
 * Validate a tool name for safety and filesystem compatibility.
 * Rejects path traversal, slashes, and other dangerous characters.
 * Returns an error message if invalid, or null if valid.
 */
function validateToolName(tool: string): string | null {
  if (!tool || tool.trim().length === 0) {
    return "Tool name cannot be empty.";
  }
  if (tool.includes("/") || tool.includes("\\")) {
    return `Invalid tool name "${tool}": slashes are not allowed (path traversal risk).`;
  }
  if (tool.startsWith(".")) {
    return `Invalid tool name "${tool}": cannot start with a dot (path traversal risk).`;
  }
  if (tool.includes("..")) {
    return `Invalid tool name "${tool}": cannot contain ".." (path traversal risk).`;
  }
  if (/[<>:"|?*\x00-\x1f]/.test(tool)) {
    return `Invalid tool name "${tool}": contains disallowed characters.`;
  }
  if (tool.length > 64) {
    return `Invalid tool name "${tool}": too long (max 64 characters).`;
  }
  // Allow: alphanumeric, hyphens, underscores
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(tool)) {
    return `Invalid tool name "${tool}": must start with alphanumeric and contain only letters, numbers, hyphens, underscores, and dots.`;
  }
  return null;
}

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

let _promptUserOverride: ((question: string) => Promise<string>) | null = null;

/**
 * Replace the promptUser function for testing.
 */
export function setPromptUser(fn: (question: string) => Promise<string>): void {
  _promptUserOverride = fn;
}

/**
 * Reset promptUser to default implementation.
 */
export function resetPromptUser(): void {
  _promptUserOverride = null;
}

/**
 * Prompt the user for a line of input via stdin/stdout.
 * Returns the trimmed response. Exported for testing.
 */
export function promptUser(question: string): Promise<string> {
  if (_promptUserOverride) {
    return _promptUserOverride(question);
  }
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Read multiline input from stdin until an empty line or EOF.
 * Exported for testing (can be overridden via setStdinReader).
 */
let _stdinReaderOverride: ((prompt: string) => Promise<string>) | null = null;

/**
 * Replace the stdin reader for testing.
 */
export function setStdinReader(reader: (prompt: string) => Promise<string>): void {
  _stdinReaderOverride = reader;
}

/**
 * Reset stdin reader to default implementation.
 */
export function resetStdinReader(): void {
  _stdinReaderOverride = null;
}

export async function readStdinInput(prompt: string): Promise<string> {
  if (_stdinReaderOverride) {
    return _stdinReaderOverride(prompt);
  }
  const readline = await import("node:readline");
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise<string>((resolve) => {
    const lines: string[] = [];
    rl.question(prompt, (firstLine) => {
      lines.push(firstLine);
      // If the first line looks like complete JSON array, return immediately
      const trimmed = lines.join("\n").trim();
      if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
        rl.close();
        resolve(trimmed);
        return;
      }
      // Otherwise read more lines until empty line
      rl.on("line", (line) => {
        if (line.trim() === "") {
          rl.close();
          resolve(lines.join("\n").trim());
        } else {
          lines.push(line);
        }
      });
      rl.on("close", () => {
        resolve(lines.join("\n").trim());
      });
    });
  });
}

/**
 * Handle `vault add <tool> --type browser-cookie --domain <domain>`.
 * Prompts for cookie paste (JSON array or Netscape format).
 */
async function handleBrowserCookieAdd(tool: string, domain?: string): Promise<void> {
  if (!domain) {
    console.error("Error: --domain is required for --type browser-cookie");
    console.error("Usage: vault add <tool> --type browser-cookie --domain .example.com");
    return;
  }

  const vaultDir = getVaultDir();
  const config = readConfig(vaultDir);
  const passphrase = getPassphrase(vaultDir);

  // Prompt for cookie input
  const input = await readStdinInput("Paste cookies (JSON array or Netscape format):\n> ");

  if (!input) {
    console.error("Error: No cookie data provided.");
    return;
  }

  // Parse cookies — try JSON first, then Netscape
  let cookies: import("./types.js").PlaywrightCookie[];
  try {
    const trimmed = input.trim();
    if (trimmed.startsWith("[")) {
      cookies = parseCookieJson(trimmed);
    } else {
      cookies = parseNetscapeCookies(trimmed);
    }
  } catch (err) {
    console.error(`Error parsing cookies: ${(err as Error).message}`);
    return;
  }

  if (cookies.length === 0) {
    console.error("Error: No valid cookies found in input.");
    return;
  }

  // Find earliest expiry
  const earliestExpiry = getEarliestExpiry(cookies);

  // Build credential payload (JSON with cookies + metadata)
  const credentialPayload: import("./types.js").BrowserCookieCredential = {
    cookies,
    domain,
    capturedAt: new Date().toISOString(),
  };
  const credentialJson = JSON.stringify(credentialPayload);

  // Encrypt and store
  await writeCredentialFile(vaultDir, tool, credentialJson, passphrase);
  console.log(`✓ Stored ${cookies.length} cookies for ${domain} (AES-256-GCM encrypted)`);
  if (earliestExpiry) {
    console.log(`✓ Expires: ${earliestExpiry} (earliest cookie expiry)`);
  }

  // Configure injection rule
  const now = new Date().toISOString();
  const toolConfig: ToolConfig = {
    name: tool,
    addedAt: now,
    lastRotated: now,
    inject: [
      {
        tool: "browser",
        type: "browser-cookie",
        method: "cookie-jar",
        domainPin: [domain],
      },
    ],
    scrub: { patterns: [] },
  };

  const updatedConfig = upsertTool(config, toolConfig);
  writeConfig(vaultDir, updatedConfig);

  const reloaded = signalGatewayReload();
  if (reloaded) {
    console.log("✓ Gateway reloaded (SIGUSR2) — no restart needed");
  }

  console.log(`\nTool "${tool}" is ready. Cookies will be injected on ${domain} navigation.`);
}

/**
 * Handle `vault add <tool> --type browser-password --domain <domain> --key <password>`.
 */
async function handleBrowserPasswordAdd(tool: string, key?: string, domain?: string): Promise<void> {
  if (!domain) {
    console.error("Error: --domain is required for --type browser-password");
    console.error("Usage: vault add <tool> --type browser-password --domain .example.com --key <password>");
    return;
  }
  if (!key) {
    console.error("Error: --key is required for --type browser-password");
    console.error("Usage: vault add <tool> --type browser-password --domain .example.com --key <password>");
    return;
  }

  const vaultDir = getVaultDir();
  const config = readConfig(vaultDir);
  const passphrase = getPassphrase(vaultDir);

  // Encrypt and store
  await writeCredentialFile(vaultDir, tool, key, passphrase);
  console.log(`✓ Credential stored: ${tool} (AES-256-GCM encrypted)`);

  // Configure injection rule
  const now = new Date().toISOString();
  const toolConfig: ToolConfig = {
    name: tool,
    addedAt: now,
    lastRotated: now,
    inject: [
      {
        tool: "browser",
        type: "browser-password",
        method: "fill",
        domainPin: [domain],
      },
    ],
    scrub: { patterns: [] },
  };

  const updatedConfig = upsertTool(config, toolConfig);
  writeConfig(vaultDir, updatedConfig);

  const reloaded = signalGatewayReload();
  if (reloaded) {
    console.log("✓ Gateway reloaded (SIGUSR2) — no restart needed");
  }

  console.log(`\nTool "${tool}" is ready. Password will be injected on ${domain} via browser fill.`);
}

/**
 * Register all vault CLI commands on the given program.
 */
export function registerCliCommands(program: CliProgram): void {
  const vault = program.command("vault").description("Credential vault management");

  // vault init
  vault
    .command("init")
    .description("Initialize the credential vault (includes resolver setup when run as root)")
    .action(async () => {
      const vaultDir = getVaultDir();

      const alreadyInitialized = fs.existsSync(path.join(vaultDir, "tools.yaml"));
      const config = alreadyInitialized ? readConfig(vaultDir) : null;
      const setupScript = path.resolve(path.join(__dirname, "..", "bin", "vault-setup.sh"));
      const hasSetupScript = fs.existsSync(setupScript);

      // Already fully set up
      if (alreadyInitialized && config?.resolverMode === "binary") {
        console.log(`✓ Vault already initialized at ${vaultDir}`);
        console.log("  Mode: binary resolver (OS-level isolation active)");
        console.log("\nUse 'openclaw vault add <tool> --key <credential>' to add credentials.");
        return;
      }

      // Not initialized or inline mode — show the recommended setup path
      if (!alreadyInitialized) {
        // Initialize inline mode as immediate baseline
        initConfig(vaultDir, "machine");
        console.log(`✓ Vault initialized at ${vaultDir}`);
        console.log(`  Encryption: AES-256-GCM + Argon2id\n`);
      } else {
        console.log(`✓ Vault already initialized at ${vaultDir}\n`);
      }

      if (hasSetupScript) {
        console.log("To complete setup with full security (recommended):\n");
        console.log(`  sudo bash ${setupScript}`);
        console.log("  openclaw doctor fix\n");
        console.log("This creates a dedicated system user so the AI agent cannot read");
        console.log("credential files directly. Without this, credentials are encrypted");
        console.log("but the agent runs as the same OS user.\n");
      }

      console.log("Use 'openclaw vault add <tool> --key <credential>' to add credentials.");
    });

  // vault add <tool>
  vault
    .command("add")
    .description("Add a credential to the vault")
    .argument("<tool>", "Tool name (e.g., gumroad, stripe, github)")
    .option("--key <credential>", "The credential/API key to store")
    .option("--type <type>", "Credential type: browser-cookie, browser-password, or omit for default")
    .option("--domain <domain>", "Domain pin (required for browser-cookie/browser-password, e.g. .amazon.com)")
    .option("--yes", "Skip confirmation prompt (accept defaults)")
    .action(async (tool: string, options: { key?: string; type?: string; domain?: string; yes?: boolean }) => {
      // Validate tool name
      const nameError = validateToolName(tool);
      if (nameError) {
        console.error(`Error: ${nameError}`);
        return;
      }

      // Route to browser-cookie handler
      if (options.type === "browser-cookie") {
        await handleBrowserCookieAdd(tool, options.domain);
        return;
      }

      // Route to browser-password handler
      if (options.type === "browser-password") {
        await handleBrowserPasswordAdd(tool, options.key, options.domain);
        return;
      }

      if (!options.key) {
        console.error("Error: --key is required. Usage: vault add <tool> --key <credential>");
        return;
      }

      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);
      const passphrase = getPassphrase(vaultDir);

      // Check for existing credential
      if (config.tools[tool]) {
        if (!options.yes) {
          const answer = await promptUser(`⚠ Tool "${tool}" already exists. Overwrite? [y/N] `);
          if (answer.toLowerCase() !== "y" && answer.toLowerCase() !== "yes") {
            console.log("Aborted. Use 'vault rotate' to update an existing credential.");
            return;
          }
        } else {
          console.log(`⚠ Overwriting existing credential: ${tool}`);
        }
      }

      // ── Phase 3A: Credential Format Guessing ──
      const guess = guessCredentialFormat(options.key, tool);

      // Display detection result
      console.log("");
      console.log(formatGuessDisplay(guess, tool));

      // If known tool was detected with a different name, inform user
      if (guess.knownToolName && guess.knownToolName !== tool) {
        console.log(`\n  ℹ This looks like a ${guess.knownToolName} credential — storing as "${tool}"`);
      }

      // ── Confirmation prompt: Does this look right? [Y/n/edit] ──
      const confirmation = options.yes ? "Y" : await promptUser("\n  Does this look right? [Y/n/edit] ");
      const confirmLower = confirmation.toLowerCase();

      if (confirmLower === "n" || confirmLower === "no") {
        console.log("\n✗ Aborted — credential not stored.");
        return;
      }

      // Collect overrides for buildToolConfigFromGuess
      const overrides: { apiUrl?: string; cliTool?: string; serviceName?: string } = {};

      if (confirmLower === "edit" || confirmLower === "e") {
        // Edit mode: prompt for all overridable fields
        const svcAnswer = await promptUser("  What service is this for? ");
        if (svcAnswer) overrides.serviceName = svcAnswer;
        const urlAnswer = await promptUser("  API base URL? ");
        if (urlAnswer) overrides.apiUrl = urlAnswer;
        const cliAnswer = await promptUser("  CLI tool name (if any, press Enter to skip)? ");
        if (cliAnswer) overrides.cliTool = cliAnswer;
      } else if (guess.needsPrompt && !options.yes) {
        // Unknown/generic format: prompt for missing context
        if (guess.promptHints.askServiceName) {
          const svcAnswer = await promptUser("\n  What service is this for? ");
          if (svcAnswer) overrides.serviceName = svcAnswer;
        }
        if (guess.promptHints.askApiUrl) {
          const urlAnswer = await promptUser("  API base URL? ");
          if (urlAnswer) overrides.apiUrl = urlAnswer;
        }
        if (guess.promptHints.askCliTool) {
          const cliAnswer = await promptUser("  CLI tool name (if any, press Enter to skip)? ");
          if (cliAnswer) overrides.cliTool = cliAnswer;
        }
      }

      // Encrypt and store
      const filePath = await writeCredentialFile(vaultDir, tool, options.key, passphrase);
      console.log(`\n✓ Credential stored: ${tool} (AES-256-GCM encrypted)`);

      // Build tool config from guess (with any overrides)
      const { inject, scrub } = buildToolConfigFromGuess(tool, guess, overrides);
      const now = new Date().toISOString();

      // Build rotation metadata from CLI options
      const rotation: import("./types.js").RotationMetadata = {};
      if ((options as any).label) rotation.label = (options as any).label;
      if ((options as any).rotationInterval) rotation.rotationIntervalDays = parseInt((options as any).rotationInterval, 10);
      if ((options as any).scopes) rotation.scopes = (options as any).scopes.split(",").map((s: string) => s.trim());
      if ((options as any).rotationProcedure) rotation.rotationProcedure = (options as any).rotationProcedure;
      if ((options as any).revokeUrl) rotation.revokeUrl = (options as any).revokeUrl;
      if ((options as any).rotationSupport) rotation.rotationSupport = (options as any).rotationSupport as any;

      const toolConfig: ToolConfig = {
        name: tool,
        addedAt: now,
        lastRotated: now,
        inject,
        scrub,
        rotation: Object.keys(rotation).length > 0 ? rotation : undefined,
      };

      // Display what was configured
      if (inject.length > 0) {
        console.log("✓ Injection configured:");
        for (const rule of inject) {
          if (rule.commandMatch) {
            console.log(`    ${rule.tool} commands matching: ${rule.commandMatch}`);
          }
          if (rule.urlMatch) {
            console.log(`    ${rule.tool} URLs matching: ${rule.urlMatch}`);
          }
        }
      }
      if (scrub.patterns.length > 0) {
        console.log(`✓ Scrubbing patterns registered: ${scrub.patterns.join(", ")}`);
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
      const nameErr = validateToolName(tool);
      if (nameErr) { console.error(`Error: ${nameErr}`); return; }
      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);
      const toolConfig = config.tools[tool];

      if (!toolConfig) {
        console.error(`Tool "${tool}" not found in vault.`);
        return;
      }

      const hasFile = credentialFileExists(vaultDir, tool);
      console.log(`Tool: ${tool}`);
      if (toolConfig.rotation?.label) {
        console.log(`Label: ${toolConfig.rotation.label}`);
      }
      console.log(`Status: ${hasFile ? "active" : "missing credential file"}`);
      console.log(`Added: ${toolConfig.addedAt}`);
      console.log(`Last Rotated: ${toolConfig.lastRotated}`);

      // Rotation metadata
      if (toolConfig.rotation) {
        const r = toolConfig.rotation;
        if (r.rotationIntervalDays !== undefined) {
          console.log(`Rotation Interval: ${r.rotationIntervalDays} days`);
        }
        if (r.rotationSupport) {
          console.log(`Rotation Support: ${r.rotationSupport}`);
        }
        if (r.scopes && r.scopes.length > 0) {
          console.log(`Scopes: ${r.scopes.join(", ")}`);
        }
        if (r.rotationProcedure) {
          console.log(`Rotation Procedure: ${r.rotationProcedure}`);
        }
        if (r.revokeUrl) {
          console.log(`Revoke URL: ${r.revokeUrl}`);
        }
      }
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
    .argument("[tool]", "Tool name (omit with --check or --all)")
    .option("--key <credential>", "The new credential/API key")
    .option("--yes", "Skip confirmation prompt")
    .option("--check", "Show all overdue rotations without rotating")
    .option("--all", "Emergency mass rotation: guided walkthrough of all credentials")
    .action(async (tool: string | undefined, options: { key?: string; check?: boolean; all?: boolean }) => {
      const vaultDir = getVaultDir();
      const config = readConfig(vaultDir);

      // --- rotate --check: show overdue rotations ---
      if (options.check) {
        const overdue = getOverdueCredentials(config);

        if (overdue.length === 0) {
          console.log("✓ All credentials are within their rotation interval.");
          return;
        }

        console.log(`⚠ ${overdue.length} credential(s) overdue for rotation:\n`);
        for (const cred of overdue) {
          const label = cred.label ? ` (${cred.label})` : "";
          console.log(`  ${cred.name}${label}`);
          console.log(`    Last rotated: ${new Date(cred.lastRotated).toISOString().split("T")[0]} (${cred.daysSinceRotation} days ago)`);
          console.log(`    Rotation interval: ${cred.rotationIntervalDays} days (${cred.daysOverdue} days overdue)`);
          if (cred.rotationSupport) {
            console.log(`    Rotation support: ${cred.rotationSupport}`);
          }
          if (cred.rotationProcedure) {
            console.log(`    Procedure: ${cred.rotationProcedure}`);
          }
          if (cred.revokeUrl) {
            console.log(`    Revoke URL: ${cred.revokeUrl}`);
          }
          if (cred.scopes && cred.scopes.length > 0) {
            console.log(`    Scopes: ${cred.scopes.join(", ")}`);
          }
          console.log("");
        }
        return;
      }

      // --- rotate --all: emergency mass rotation ---
      if (options.all) {
        const toolNames = Object.keys(config.tools);
        if (toolNames.length === 0) {
          console.log("No credentials in vault.");
          return;
        }

        console.log(`Emergency mass rotation: ${toolNames.length} credential(s) to rotate\n`);

        const passphrase = getPassphrase(vaultDir);
        let rotatedCount = 0;

        // Read from stdin for interactive prompts
        const readline = await import("node:readline");
        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout,
        });

        const question = (prompt: string): Promise<string> => {
          return new Promise((resolve) => {
            rl.question(prompt, (answer) => {
              resolve(answer);
            });
          });
        };

        for (const name of toolNames) {
          const toolConfig = config.tools[name];
          const rotation = toolConfig.rotation ?? {};
          const label = rotation.label ? ` (${rotation.label})` : "";

          console.log(`─── ${name}${label} ───`);

          // Show rotation metadata
          if (toolConfig.lastRotated) {
            const age = Math.floor((Date.now() - new Date(toolConfig.lastRotated).getTime()) / (1000 * 60 * 60 * 24));
            console.log(`  Last rotated: ${new Date(toolConfig.lastRotated).toISOString().split("T")[0]} (${age} days ago)`);
          }
          if (rotation.rotationProcedure) {
            console.log(`  Procedure: ${rotation.rotationProcedure}`);
          }
          if (rotation.revokeUrl) {
            console.log(`  Revoke URL: ${rotation.revokeUrl}`);
          }
          if (rotation.scopes && rotation.scopes.length > 0) {
            console.log(`  Scopes: ${rotation.scopes.join(", ")}`);
          }

          const answer = await question(`  Enter new credential for "${name}" (or press Enter to skip): `);

          if (answer.trim()) {
            // Remove old file and write new one
            removeCredentialFile(vaultDir, name);
            await writeCredentialFile(vaultDir, name, answer.trim(), passphrase);

            // Update rotation timestamp
            toolConfig.lastRotated = new Date().toISOString();

            // Update scrub patterns if credential format changed
            const detected = detectCredentialType(answer.trim());
            if (detected) {
              const knownTool = getKnownTool(detected.toolName);
              if (knownTool) {
                toolConfig.scrub = knownTool.scrub;
              }
            }

            const updatedConfig = upsertTool(config, toolConfig);
            writeConfig(vaultDir, updatedConfig);
            console.log(`  ✓ Rotated: ${name}\n`);
            rotatedCount++;
          } else {
            console.log(`  ⏭ Skipped: ${name}\n`);
          }
        }

        rl.close();

        if (rotatedCount > 0) {
          const reloaded = signalGatewayReload();
          console.log(`\n✓ Mass rotation complete: ${rotatedCount}/${toolNames.length} credential(s) rotated`);
          if (reloaded) {
            console.log("✓ Gateway reloaded (SIGUSR2) — no restart needed");
          }
        } else {
          console.log("\nNo credentials were rotated.");
        }
        return;
      }

      // --- Single tool rotation (existing behavior) ---
      if (!tool) {
        console.error("Error: tool name is required. Usage: vault rotate <tool> --key <credential>");
        console.error("  Or use: vault rotate --check | vault rotate --all");
        return;
      }

      const nameErr = validateToolName(tool);
      if (nameErr) { console.error(`Error: ${nameErr}`); return; }

      if (!options.key) {
        console.error("Error: --key is required for rotation.");
        return;
      }

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

      // Post-rotation security checklist
      const rotatedToolConfig = updatedConfig.tools[tool];
      const revokeUrl = rotatedToolConfig?.rotation?.revokeUrl;
      console.log("");
      console.log("⚠ Post-rotation checklist:");
      console.log("  1. Revoke the old token in the service dashboard");
      if (revokeUrl) {
        console.log(`     → ${revokeUrl}`);
      }
      console.log("  2. Check for plaintext copies (.env files, CLI configs, etc.)");
      console.log("  3. If the old token was ever passed through an AI agent, treat it as compromised");
    });

  // vault remove <tool>
  vault
    .command("remove")
    .description("Remove a tool and its credential")
    .argument("<tool>", "Tool name")
    .option("--purge", "Also remove scrubbing patterns (not recommended)")
    .action(async (tool: string, options: { purge?: boolean }) => {
      const nameErr = validateToolName(tool);
      if (nameErr) { console.error(`Error: ${nameErr}`); return; }
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
      const nameErr = validateToolName(tool);
      if (nameErr) { console.error(`Error: ${nameErr}`); return; }
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

  // Note: OS-level isolation setup is handled by bin/vault-setup.sh (run with sudo)
  // The setupResolverInternal function has been replaced by the standalone script
  // to avoid PATH issues with sudo + user-installed npm packages.

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

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
  syncToSystemVault,
  removeFromSystemVault,
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
  buildToolConfig,
} from "./guesser.js";
import {
  parseCookieJson,
  parseNetscapeCookies,
  parseRawCookieString,
  getEarliestExpiry,
} from "./browser.js";
import { ToolConfig, CliProgram, PlaywrightCookie, UsageSelection, InjectionRule, ScrubConfig } from "./types.js";

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
 * Securely delete a file by overwriting with zeros then unlinking.
 */
async function secureDeleteFile(filePath: string): Promise<void> {
  try {
    const stat = fs.statSync(filePath);
    const size = stat.size;
    if (size > 0) {
      const fd = fs.openSync(filePath, "w");
      const chunkSize = 65536;
      const zeros = Buffer.alloc(chunkSize);
      let remaining = size;
      while (remaining > 0) {
        const chunk = Math.min(remaining, chunkSize);
        fs.writeSync(fd, zeros, 0, chunk);
        remaining -= chunk;
      }
      fs.closeSync(fd);
    }
    fs.unlinkSync(filePath);
  } catch (err) {
    console.error(`Warning: Could not securely delete file: ${(err as Error).message}`);
  }
}

/**
 * Write tool config to tools.yaml and signal gateway reload.
 */
async function writeToolConfigEntry(
  tool: string,
  inject: InjectionRule[],
  scrub: ScrubConfig,
  options: Record<string, unknown>,
  config: import("./types.js").VaultConfig,
  vaultDir: string
): Promise<void> {
  const now = new Date().toISOString();

  const rotation: import("./types.js").RotationMetadata = {};
  if (options["label"]) rotation.label = options["label"] as string;
  if (options["rotationInterval"]) rotation.rotationIntervalDays = parseInt(options["rotationInterval"] as string, 10);
  if (options["scopes"]) rotation.scopes = (options["scopes"] as string).split(",").map((s) => s.trim());
  if (options["rotationProcedure"]) rotation.rotationProcedure = options["rotationProcedure"] as string;
  if (options["revokeUrl"]) rotation.revokeUrl = options["revokeUrl"] as string;
  if (options["rotationSupport"]) rotation.rotationSupport = options["rotationSupport"] as any;

  const toolConfig: ToolConfig = {
    name: tool,
    addedAt: now,
    lastRotated: now,
    inject,
    scrub,
    rotation: Object.keys(rotation).length > 0 ? rotation : undefined,
  };

  const updatedConfig = upsertTool(config, toolConfig);
  writeConfig(vaultDir, updatedConfig);

  const reloaded = signalGatewayReload();
  if (reloaded) {
    console.log("✓ Gateway reloaded (SIGUSR2) — no restart needed");
  }

  console.log(`\nTool "${tool}" is ready. Your agent can now use it without seeing the credential.`);
}

/**
 * Non-interactive path for vault add when --use flags are provided.
 */
async function handleVaultAddWithUse(
  tool: string,
  options: {
    key?: string;
    use?: string;
    url?: string;
    header?: string;
    bearer?: boolean;
    command?: string;
    env?: string;
    domain?: string;
    scrubPattern?: string;
    yes?: boolean;
    [key: string]: unknown;
  },
  config: import("./types.js").VaultConfig,
  vaultDir: string,
  passphrase: string
): Promise<void> {
  const usageTypes = (options.use ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const hasBrowserSession = usageTypes.includes("browser-session");

  // Validate --yes requirements: all required flags must be present
  if (options.yes) {
    for (const type of usageTypes) {
      if (type === "api" && !options.url) {
        console.error("Error: --yes requires either a known credential format or --use with all required flags.");
        return;
      }
      if (type === "cli" && (!options.command || !options.env)) {
        console.error("Error: --yes requires either a known credential format or --use with all required flags.");
        return;
      }
      if (type === "browser-login" && !options.domain) {
        console.error("Error: --yes requires either a known credential format or --use with all required flags.");
        return;
      }
      if (type === "browser-session") {
        const hasCookieData =
          (options.key && (options.key.startsWith("[") || options.key.startsWith("{"))) ||
          (options.key && fs.existsSync(options.key)) ||
          (options.key && options.key.includes("="));
        if (!options.domain || !hasCookieData) {
          console.error("Error: --yes requires either a known credential format or --use with all required flags.");
          return;
        }
      }
    }
  }

  const usage: UsageSelection = { scrubPatterns: [] };
  if (options.scrubPattern) {
    usage.scrubPatterns = [options.scrubPattern];
  }

  // Handle browser-session: read cookie file and encrypt
  if (hasBrowserSession) {
    if (!options.domain) {
      console.error("Error: --domain is required for --use browser-session");
      return;
    }

    // Determine cookie source from --key (inline JSON or file path)
    let fileContent: string;
    let cookieSourcePath: string | null = null;
    let cookieIsInline = false;

    if (options.key && (options.key.startsWith("[") || options.key.startsWith("{"))) {
      // Inline cookie JSON provided via --key
      fileContent = options.key;
      cookieIsInline = true;
    } else if (options.key && !fs.existsSync(options.key) && options.key.includes("=")) {
      // Raw cookie string: "name=value" or "name=value; name2=value2"
      fileContent = options.key;
      cookieIsInline = true;
    } else if (options.key && fs.existsSync(options.key)) {
      // --key is a file path
      cookieSourcePath = options.key;
      try {
        fileContent = fs.readFileSync(options.key, "utf-8");
      } catch (err) {
        console.error(`Error reading cookie file: ${(err as Error).message}`);
        return;
      }
    } else {
      console.error("Error: --key is required for --use browser-session (provide cookie JSON, name=value string, or path to cookie file). For a plain cookie value, use the interactive flow (omit --use) and select option 4.");
      return;
    }

    let cookies: PlaywrightCookie[];
    try {
      const trimmed = fileContent.trim();
      if (cookieIsInline && !trimmed.startsWith("[") && !trimmed.startsWith("{") && trimmed.includes("=")) {
        cookies = parseRawCookieString(fileContent, options.domain!);
      } else if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
        cookies = parseCookieJson(fileContent);
      } else {
        cookies = parseNetscapeCookies(fileContent);
      }
    } catch (err) {
      console.error(`Error parsing cookie data: ${(err as Error).message}`);
      return;
    }

    if (cookies.length === 0) {
      console.error("Error: No valid cookies found in file.");
      return;
    }

    const credentialPayload = JSON.stringify({
      cookies,
      domain: options.domain,
      capturedAt: new Date().toISOString(),
    });

    await writeCredentialFile(vaultDir, tool, credentialPayload, passphrase);
    if (config.resolverMode === "binary") {
      syncToSystemVault(vaultDir, tool);
    }
    console.log(`✓ Stored ${cookies.length} cookies for ${options.domain} (AES-256-GCM encrypted)`);

    // Source file/history warnings
    if (cookieSourcePath) {
      if (!options.yes) {
        const deleteAnswer = await promptUser(`  Delete source file ${cookieSourcePath}? [Y/n]: `);
        if (deleteAnswer.toLowerCase() !== "n" && deleteAnswer.toLowerCase() !== "no") {
          await secureDeleteFile(cookieSourcePath);
          console.log("  ✓ Source file securely deleted.");
        } else {
          console.log(`  ⚠ Source file still exists at ${cookieSourcePath}`);
        }
      } else {
        // --yes: auto-delete for security (plaintext cookies on disk are a risk)
        await secureDeleteFile(cookieSourcePath);
        console.log("  ✓ Source file securely deleted (--yes default).");
      }
    } else if (cookieIsInline) {
      console.log("  ⚠ Cookie JSON was passed via --key — it may be visible in shell history.");
    }

    usage.browserSession = {
      domain: options.domain,
      cookieFilePath: cookieSourcePath ?? "inline",
    };
  } else {
    // Non-browser-session types need --key
    if (!options.key) {
      console.error("Error: --key is required. Usage: vault add <tool> --key <credential>");
      return;
    }

    await writeCredentialFile(vaultDir, tool, options.key, passphrase);
    if (config.resolverMode === "binary") {
      const syncOk = syncToSystemVault(vaultDir, tool);
      if (!syncOk) {
        console.log(`\n⚠ Warning: Credential stored locally but NOT synced to system vault.`);
      }
    }
    console.log(`\n✓ Credential encrypted and stored (AES-256-GCM)`);

    // Show detection
    const guess = guessCredentialFormat(options.key, tool);
    console.log(`  Detected: ${guess.displayName}`);
  }

  // Build UsageSelection from flags
  for (const type of usageTypes) {
    if (type === "api") {
      const urlPattern = options.url ?? `*${tool}*`;
      const headerName = options.header ?? "Authorization";
      const headerFormat = options.bearer !== false ? "Bearer $token" : "$token";
      usage.apiCalls = { urlPattern, headerName, headerFormat };

    } else if (type === "cli") {
      const commandName = options.command;
      const commandMatch = commandName ? `${commandName}*` : `${tool}*`;
      const defaultEnvVar = `${tool.toUpperCase().replace(/-/g, "_")}_API_KEY`;
      const envVar = options.env ?? defaultEnvVar;
      usage.cliTool = {
        commandName: commandName || undefined,
        commandMatch,
        envVar,
      };

    } else if (type === "browser-login") {
      if (!options.domain) {
        console.error("Error: --domain is required for --use browser-login");
        return;
      }
      usage.browserLogin = { domain: options.domain };

    } else if (type === "browser-session") {
      // Already handled above — just set the usage field
      // (usage.browserSession is already set)
    } else {
      console.error(`Error: Unknown usage type "${type}". Valid types: api, cli, browser-login, browser-session`);
      return;
    }
  }

  const { inject, scrub } = buildToolConfig(tool, usage);
  await writeToolConfigEntry(tool, inject, scrub, options, config, vaultDir);
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

      // Check for Perl (required for real-time stdout scrubbing)
      const hasPerl = (() => {
        try {
          require("node:child_process").execFileSync("perl", ["-v"], { stdio: "ignore" });
          return true;
        } catch { return false; }
      })();

      if (!hasPerl) {
        console.log("⚠ Perl is not installed.");
        console.log("  Without Perl, credentials may briefly appear in raw subprocess output");
        console.log("  before being scrubbed. The after-call scrubber still catches everything,");
        console.log("  but real-time pipe scrubbing requires Perl.\n");
        console.log("  To fix, either:");
        console.log("    • Install Perl:  sudo apt-get install -y perl");
        console.log("    • Run full setup (installs Perl automatically):");
        console.log(`      sudo bash ${hasSetupScript ? setupScript : "<path-to>/vault-setup.sh"}`);
        console.log("");
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
    .option("--key <credential>", "Credential value (API key, password, cookie JSON, or path to cookie file)")
    .option("--use <types>", "Usage types (comma-separated): api,cli,browser-login,browser-session")
    .option("--url <pattern>", "URL match pattern for API header injection")
    .option("--header <name>", "HTTP header name for API injection (default: Authorization)")
    .option("--no-bearer", "Don't prepend 'Bearer ' to value (for API injection)")
    .option("--command <name>", "CLI command name for command matching")
    .option("--env <name>", "Environment variable name for CLI injection")
    .option("--domain <domain>", "Domain for browser-login or browser-session")

    .option("--scrub-pattern <regex>", "Add a regex pattern for output scrubbing")
    .option("--yes", "Skip confirmation prompt (requires known format or --use with all required flags)")
    .action(async (tool: string, options: {
      key?: string;
      use?: string;
      url?: string;
      header?: string;
      bearer?: boolean; // Commander sets false when --no-bearer is passed
      command?: string;
      env?: string;
      domain?: string;
      scrubPattern?: string;
      yes?: boolean;
      // Legacy/passthrough fields
      type?: string;
    }) => {
      // Validate tool name
      const nameError = validateToolName(tool);
      if (nameError) {
        console.error(`Error: ${nameError}`);
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

      // ── Non-interactive path: --use flags provided ──
      if (options.use) {
        await handleVaultAddWithUse(tool, options, config, vaultDir, passphrase);
        return;
      }

      if (!options.key) {
        console.error("Error: --key is required. Usage: vault add <tool> --key <credential>");
        return;
      }

      // ── Detect format ──
      const guess = guessCredentialFormat(options.key, tool);
      const toolNameTemplate = KNOWN_TOOLS[tool];

      // ── Known-prefix auto-config path (high confidence) ──
      if (guess.knownToolName && guess.confidence === "high") {
        if (!options.key) {
          console.error("Error: --key is required. Usage: vault add <tool> --key <credential>");
          return;
        }

        // Encrypt first
        console.log("");
        await writeCredentialFile(vaultDir, tool, options.key, passphrase);
        if (config.resolverMode === "binary") {
          const syncOk = syncToSystemVault(vaultDir, tool);
          if (!syncOk) {
            console.log(`\n⚠ Warning: Credential stored locally but NOT synced to system vault.`);
          }
        }
        console.log(`✓ Credential encrypted and stored (AES-256-GCM)`);
        console.log(formatGuessDisplay(guess, tool));

        if (guess.knownToolName !== tool) {
          console.log(`\n  ℹ This looks like a ${guess.knownToolName} credential — storing as "${tool}"`);
        }

        if (!options.yes) {
          const confirm = await promptUser("\nSave? [Y/n] ");
          if (confirm.toLowerCase() === "n" || confirm.toLowerCase() === "no") {
            console.log("\n✗ Aborted.");
            return;
          }
        }

        const inject = [...guess.suggestedInject];
        const scrub = { patterns: [...guess.suggestedScrub.patterns] };
        if (options.scrubPattern) scrub.patterns.push(options.scrubPattern);

        await writeToolConfigEntry(tool, inject, scrub, options as any, config, vaultDir);
        return;
      }

      // ── Known-name template path (tool name matches registry template) ──
      if (toolNameTemplate) {
        console.log("");
        await writeCredentialFile(vaultDir, tool, options.key, passphrase);
        if (config.resolverMode === "binary") {
          const syncOk = syncToSystemVault(vaultDir, tool);
          if (!syncOk) {
            console.log(`\n⚠ Warning: Credential stored locally but NOT synced to system vault.`);
          }
        }
        console.log(`✓ Credential encrypted and stored (AES-256-GCM)`);
        console.log(`  Detected: ${guess.displayName}`);
        console.log(`  Using known template for tool: ${tool}`);

        if (!options.yes) {
          console.log("\n  Template config:");
          for (const rule of toolNameTemplate.inject) {
            if (rule.tool === "web_fetch") {
              const headerPreview = rule.headers
                ? Object.entries(rule.headers).map(([k, v]) => `${k}: ${v}`).join(", ")
                : "(none)";
              console.log(`    - API header injection: ${headerPreview} @ ${rule.urlMatch ?? "*"}`);
            } else if (rule.tool === "exec") {
              const envPreview = rule.env ? Object.keys(rule.env).join(", ") : "(none)";
              console.log(`    - CLI env injection: ${envPreview} @ ${rule.commandMatch ?? "*"}`);
            } else if (rule.tool === "browser" && rule.type === "browser-password") {
              console.log(`    - Browser login on ${rule.domainPin?.join(", ") ?? "(any domain)"}`);
            } else if (rule.tool === "browser" && rule.type === "browser-cookie") {
              console.log(`    - Browser session on ${rule.domainPin?.join(", ") ?? "(any domain)"}`);
            }
          }

          const confirm = await promptUser("\nSave using this template? [Y/n] ");
          if (confirm.toLowerCase() === "n" || confirm.toLowerCase() === "no") {
            console.log("\n✗ Aborted.");
            return;
          }
        }

        const inject = [...toolNameTemplate.inject];
        const scrub = { patterns: [...toolNameTemplate.scrub.patterns] };
        if (options.scrubPattern) scrub.patterns.push(options.scrubPattern);

        await writeToolConfigEntry(tool, inject, scrub, options as any, config, vaultDir);
        return;
      }

      // ── Interactive flow (no --use, no known prefix/template) ──
      if (options.yes) {
        console.error("Error: --yes requires either a known credential format or --use with all required flags.");
        return;
      }

      // Encrypt key first if provided
      console.log("");
      if (options.key) {
        await writeCredentialFile(vaultDir, tool, options.key, passphrase);
        if (config.resolverMode === "binary") {
          syncToSystemVault(vaultDir, tool);
        }
        console.log(`✓ Credential encrypted and stored (AES-256-GCM)`);
      }
      console.log(`  Detected: ${guess.displayName}`);
      console.log("");

      // Show usage menu
      console.log("How will your agent use this credential?\n");
      console.log("  1. API calls      — HTTP requests to a web service");
      console.log("  2. CLI tool       — command-line programs (gh, aws, curl)");
      console.log("  3. Browser login  — fill a password on a website");
      console.log("  4. Browser session — use cookies from a logged-in session");
      console.log("");

      const defaultUsage = guess.suggestedUsage.join(",");
      const defaultDisplay = defaultUsage ? ` [${defaultUsage}]` : "";
      const usageAnswer = await promptUser(`Choose one or more (comma-separated)${defaultDisplay}: `);
      const chosenStr = usageAnswer.trim() || defaultUsage;
      const chosenNums = chosenStr
        .split(",")
        .map((s) => parseInt(s.trim(), 10))
        .filter((n) => !isNaN(n) && n >= 1 && n <= 4);

      if (chosenNums.length === 0) {
        console.log("No valid usage selected. Aborting.");
        return;
      }

      const usage: UsageSelection = { scrubPatterns: [] };
      let credentialEncryptedAsCookies = false;

      // Collect usage-specific details
      for (const num of chosenNums) {
        if (num === 1) {
          // API calls
          const domainAnswer = await promptUser("  API domain or URL: ");
          const urlPattern = domainAnswer.trim() ? `*${domainAnswer.trim()}/*` : "*";
          const headerAnswer = await promptUser("  Header name [Authorization]: ");
          const headerName = headerAnswer.trim() || "Authorization";
          const formatAnswer = await promptUser("  Value format [Bearer $token]: ");
          const headerFormat = formatAnswer.trim() || "Bearer $token";
          usage.apiCalls = { urlPattern, headerName, headerFormat };

        } else if (num === 2) {
          // CLI tool
          const commandAnswer = await promptUser("  CLI command name (or Enter for general scripts): ");
          let commandMatch: string;
          if (commandAnswer.trim()) {
            commandMatch = `${commandAnswer.trim()}*`;
          } else {
            const patternAnswer = await promptUser("  Command pattern (glob, e.g. myservice*): ");
            commandMatch = patternAnswer.trim() || `${tool}*`;
          }
          const defaultEnvVar = `${tool.toUpperCase().replace(/-/g, "_")}_API_KEY`;
          const envAnswer = await promptUser(`  Environment variable [${defaultEnvVar}]: `);
          const envVar = envAnswer.trim() || defaultEnvVar;
          usage.cliTool = {
            commandName: commandAnswer.trim() || undefined,
            commandMatch,
            envVar,
          };

        } else if (num === 3) {
          // Browser login
          const domainAnswer = await promptUser("  Website domain: ");
          usage.browserLogin = { domain: domainAnswer.trim() };

        } else if (num === 4) {
          // Browser session — need cookie data
          const domainAnswer = await promptUser("  Cookie domain: ");
          const domain = domainAnswer.trim();

          // Re-prompt until valid cookie data is provided
          let cookieContent: string | null = null;
          let cookieFilePath: string | null = null;
          let cookieIsInline = false;
          let cookieIsRaw = false;

          // Check if --key already contains cookie data (inline JSON or file path)
          if (options.key) {
            const keyTrimmed = options.key.trim();
            if (keyTrimmed.startsWith("[") || keyTrimmed.startsWith("{")) {
              cookieContent = keyTrimmed;
              cookieIsInline = true;
            } else if (fs.existsSync(keyTrimmed)) {
              try {
                cookieContent = fs.readFileSync(keyTrimmed, "utf-8");
                cookieFilePath = keyTrimmed;
              } catch (err) {
                console.log(`  Could not read file from --key: ${(err as Error).message}`);
              }
            } else if (keyTrimmed.includes("=")) {
              // Raw cookie string: "name=value" or "name=value; name2=value2"
              cookieContent = keyTrimmed;
              cookieIsInline = true;
              cookieIsRaw = true;
            } else if (keyTrimmed.length > 0) {
              // Plain cookie value — ask for the cookie name
              const cookieName = await promptUser("  Cookie name: ");
              const name = cookieName.trim();
              if (name) {
                cookieContent = `${name}=${keyTrimmed}`;
                cookieIsInline = true;
                cookieIsRaw = true;
              }
            }
          }

          while (!cookieContent) {
            const input = await promptUser("  Paste cookie JSON or enter file path: ");
            const trimmed = input.trim();

            if (!trimmed) {
              console.log("  Please enter cookie JSON or a valid file path.");
              continue;
            }

            if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
              // Inline JSON
              cookieContent = trimmed;
              cookieIsInline = true;
              break;
            }

            if (fs.existsSync(trimmed)) {
              // File path
              try {
                cookieContent = fs.readFileSync(trimmed, "utf-8");
                cookieFilePath = trimmed;
                break;
              } catch (err) {
                console.log(`  Could not read file: ${(err as Error).message}. Try again.`);
                continue;
              }
            }

            // Neither valid JSON nor existing file
            console.log(`  File not found: "${trimmed}". Enter cookie JSON or a valid file path.`);
          }

          // Read and encrypt cookie data
          let cookies: PlaywrightCookie[];
          try {
            const trimmed = cookieContent!.trim();
            if (cookieIsRaw || (!trimmed.startsWith("[") && !trimmed.startsWith("{") && trimmed.includes("="))) {
              cookies = parseRawCookieString(cookieContent!, domain);
            } else if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
              cookies = parseCookieJson(cookieContent!);
            } else {
              cookies = parseNetscapeCookies(cookieContent!);
            }
          } catch (err) {
            console.error(`Error parsing cookie data: ${(err as Error).message}`);
            return;
          }

          if (cookies.length === 0) {
            console.error("Error: No valid cookies found.");
            return;
          }

          const credentialPayload = JSON.stringify({
            cookies,
            domain,
            capturedAt: new Date().toISOString(),
          });

          // Encrypt cookie data (may overwrite key encrypted above)
          await writeCredentialFile(vaultDir, tool, credentialPayload, passphrase);
          if (config.resolverMode === "binary") {
            syncToSystemVault(vaultDir, tool);
          }
          console.log(`  ✓ Cookies encrypted and stored.`);
          credentialEncryptedAsCookies = true;

          if (cookieIsInline) {
            console.log("  ⚠ Cookie JSON was provided inline — it may be visible in shell history.");
          } else if (cookieFilePath) {
            // Prompt to delete source file
            const deleteAnswer = await promptUser(`  Delete source file ${cookieFilePath}? [Y/n]: `);
            if (deleteAnswer.toLowerCase() !== "n" && deleteAnswer.toLowerCase() !== "no") {
              await secureDeleteFile(cookieFilePath);
              console.log("  ✓ Source file securely deleted.");
            } else {
              console.log(`  ⚠ Source file still exists at ${cookieFilePath}`);
            }
          }

          usage.browserSession = { domain, cookieFilePath: cookieFilePath ?? "inline" };
        }
      }

      // Ask about additional scrub patterns
      console.log("\nOutput scrubbing (protects against credential leakage):");
      console.log("  ✓ Literal match: always active — your exact credential value will be");
      console.log("    redacted from all agent output, messages, and transcripts.");
      console.log("    (Stored in memory only — never written to config files.)");
      console.log("");

      // Offer suggested scrub patterns from format guesser
      let acceptedDetectedPattern = false;
      if (guess.suggestedScrub.patterns.length > 0) {
        for (const pattern of guess.suggestedScrub.patterns) {
          const includeAnswer = await promptUser(`  Detected pattern: \`${pattern}\` — include? [Y/n]: `);
          if (includeAnswer.toLowerCase() !== "n" && includeAnswer.toLowerCase() !== "no") {
            usage.scrubPatterns.push(pattern);
            acceptedDetectedPattern = true;
          }
        }
      }

      // Skip manual prompt if user accepted a detected pattern; offer it if they declined or none existed
      if (!acceptedDetectedPattern) {
        const addScrub = await promptUser("  Add a regex pattern to also catch similar credentials? [N/y]: ");
        if (addScrub.toLowerCase() === "y" || addScrub.toLowerCase() === "yes") {
          const pattern = await promptUser("  Regex pattern: ");
          if (pattern.trim()) {
            usage.scrubPatterns.push(pattern.trim());
          }
        }
      }
      if (options.scrubPattern) {
        usage.scrubPatterns.push(options.scrubPattern);
      }

      // Build config
      const { inject, scrub } = buildToolConfig(tool, usage);

      // Show summary
      console.log(`\nSummary for "${tool}":`);
      console.log(`  ✓ Encrypted:  AES-256-GCM`);
      for (const rule of inject) {
        if (rule.type === "browser-password") {
          console.log(`  ✓ Injection:  browser login on ${rule.domainPin?.[0]}`);
        } else if (rule.type === "browser-cookie") {
          console.log(`  ✓ Injection:  browser session on ${rule.domainPin?.[0]}`);
        } else if (rule.tool === "web_fetch") {
          console.log(`  ✓ Injection:  API calls to ${rule.urlMatch}`);
        } else if (rule.tool === "exec") {
          console.log(`  ✓ Injection:  CLI commands matching ${rule.commandMatch}`);
        }
      }
      const scrubNote = scrub.patterns.length > 0 ? ` + ${scrub.patterns.length} regex pattern(s)` : "";
      console.log(`  ✓ Scrubbing:  literal match (always active)${scrubNote}`);

      // Confirm
      const confirm = await promptUser("\nSave? [Y/n] ");
      if (confirm.toLowerCase() === "n" || confirm.toLowerCase() === "no") {
        console.log("\n✗ Aborted.");
        return;
      }

      await writeToolConfigEntry(tool, inject, scrub, options as any, config, vaultDir);
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
      if (toolConfig.inject.some((r) => r.env)) {
        console.log("\nℹ Credentials are injected via environment variables, not command string tokens.");
        console.log("  Use $ENVVAR_NAME in your commands (e.g., curl -H \"Authorization: Bearer $GITHUB_TOKEN\" ...)");
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

          const answer = await promptUser(`  Enter new credential for "${name}" (or press Enter to skip): `);

          if (answer.trim()) {
            // Remove old file and write new one
            removeCredentialFile(vaultDir, name);
            await writeCredentialFile(vaultDir, name, answer.trim(), passphrase);
            if (config.resolverMode === "binary") {
              removeFromSystemVault(name);
              syncToSystemVault(vaultDir, name);
            }

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
      if (config.resolverMode === "binary") {
        removeFromSystemVault(tool);
        syncToSystemVault(vaultDir, tool);
      }

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
      if (config.resolverMode === "binary") {
        removeFromSystemVault(tool);
      }

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

      // Test binary resolver if in binary mode
      if (config.resolverMode === "binary") {
        const { resolveViaRustBinary } = await import("./resolver.js");
        const resolverResult = await resolveViaRustBinary(tool, "exec", "test-command");
        if (resolverResult.ok) {
          console.log(`\n✓ Binary resolver: OK (credential accessible)`);
        } else {
          console.log(`\n✗ Binary resolver: FAILED — ${resolverResult.message}`);
          if (resolverResult.error === "CREDENTIAL_MISSING") {
            console.log(`  The resolver cannot find ${tool}.enc in the system vault.`);
            console.log(`  Fix: Run 'sudo bash vault-setup.sh' to sync credentials.`);
          } else if (resolverResult.error === "PROTOCOL_MISMATCH") {
            console.log(`  Plugin/resolver version mismatch. Run 'sudo bash vault-setup.sh' to update.`);
          }
        }
      }

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
            console.log(`[${ts}] ACCESS ${event.credential} via ${event.tool} (${event.injectionType}) — ${event.command}`);
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

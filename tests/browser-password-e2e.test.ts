/**
 * Browser Password E2E Tests
 *
 * Tests the full flow: navigate (cache URL) → act/type with $vault: → domain-pin check → credential injection.
 * This validates the browserTabUrls cache workaround for missing URL in act/type params.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import {
  writeCredentialFile,
  getMachinePassphrase,
  readCredentialFile,
} from "../src/crypto.js";
import {
  initConfig,
  readConfig,
  writeConfig,
  upsertTool,
  readMeta,
} from "../src/config.js";
import { resolveBrowserPassword } from "../src/browser.js";
import { ToolConfig } from "../src/types.js";

describe("browser-password E2E — tab URL cache flow", () => {
  let tmpDir: string;
  let passphrase: string;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-browser-pw-e2e-"));
    initConfig(tmpDir, "machine");
    const meta = readMeta(tmpDir);
    passphrase = getMachinePassphrase(meta?.installTimestamp);

    // Store a credential
    await writeCredentialFile(tmpDir, "gumroad-login", "MySecretPassword123", passphrase);

    // Configure browser-password injection with domain pin
    const config = readConfig(tmpDir);
    upsertTool(config, "gumroad-login", {
      name: "gumroad-login",
      inject: [
        {
          tool: "browser",
          type: "browser-password",
          domainPin: [".gumroad.com"],
          method: "fill",
        },
      ],
      scrub: { patterns: [] },
    });
    writeConfig(tmpDir, config);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("resolves $vault: placeholder when URL matches domain pin", async () => {
    const credential = await readCredentialFile(tmpDir, "gumroad-login", passphrase);
    const result = resolveBrowserPassword(
      "$vault:gumroad-login",
      "https://gumroad.com/login",
      credential,
      [".gumroad.com"]
    );

    expect(result.allowed).toBe(true);
    expect(result.resolvedValue).toBe("MySecretPassword123");
  });

  it("blocks $vault: placeholder when URL does not match domain pin", async () => {
    const credential = await readCredentialFile(tmpDir, "gumroad-login", passphrase);
    const result = resolveBrowserPassword(
      "$vault:gumroad-login",
      "https://evil.com/fake-gumroad",
      credential,
      [".gumroad.com"]
    );

    expect(result.allowed).toBe(false);
    expect(result.error).toContain("Domain mismatch");
  });

  it("blocks $vault: placeholder when URL is empty (no cache, no params)", async () => {
    const credential = await readCredentialFile(tmpDir, "gumroad-login", passphrase);
    const result = resolveBrowserPassword(
      "$vault:gumroad-login",
      "",
      credential,
      [".gumroad.com"]
    );

    expect(result.allowed).toBe(false);
    expect(result.error).toContain("Cannot resolve domain");
  });

  it("allows subdomain when domain pin has leading dot", async () => {
    const credential = await readCredentialFile(tmpDir, "gumroad-login", passphrase);
    const result = resolveBrowserPassword(
      "$vault:gumroad-login",
      "https://app.gumroad.com/login",
      credential,
      [".gumroad.com"]
    );

    expect(result.allowed).toBe(true);
    expect(result.resolvedValue).toBe("MySecretPassword123");
  });

  it("passes through non-vault text unchanged", () => {
    const result = resolveBrowserPassword(
      "just-some-text",
      "https://evil.com",
      "ignored",
      [".gumroad.com"]
    );

    expect(result.allowed).toBe(true);
    expect(result.resolvedValue).toBe("just-some-text");
  });

  it("simulates full navigate → act flow using tab URL cache", async () => {
    // Simulate the browserTabUrls cache that the hook maintains
    const tabUrlCache = new Map<string, string>();

    // Step 1: navigate action — cache the URL
    const navigateParams = {
      action: "navigate",
      url: "https://gumroad.com/login",
      targetId: "TAB_123",
    };
    tabUrlCache.set(navigateParams.targetId, navigateParams.url);

    // Step 2: act/type action — no URL in params, use cache
    const actParams = {
      action: "act",
      kind: "type",
      ref: "e41",
      text: "$vault:gumroad-login",
      targetId: "TAB_123",
    };
    const cachedUrl = tabUrlCache.get(actParams.targetId) ?? "";

    // Step 3: resolve with cached URL
    const credential = await readCredentialFile(tmpDir, "gumroad-login", passphrase);
    const result = resolveBrowserPassword(
      actParams.text,
      cachedUrl,
      credential,
      [".gumroad.com"]
    );

    expect(result.allowed).toBe(true);
    expect(result.resolvedValue).toBe("MySecretPassword123");
  });

  it("blocks when tab navigates to different domain after cache", async () => {
    const tabUrlCache = new Map<string, string>();

    // Navigate to gumroad
    tabUrlCache.set("TAB_456", "https://gumroad.com/login");

    // Simulate redirect to different domain (cache updated)
    tabUrlCache.set("TAB_456", "https://evil.com/phishing");

    // Act on same tab — should block because cache now has evil.com
    const cachedUrl = tabUrlCache.get("TAB_456") ?? "";
    const credential = await readCredentialFile(tmpDir, "gumroad-login", passphrase);
    const result = resolveBrowserPassword(
      "$vault:gumroad-login",
      cachedUrl,
      credential,
      [".gumroad.com"]
    );

    expect(result.allowed).toBe(false);
    expect(result.error).toContain("Domain mismatch");
  });

  it("handles multiple tabs independently", async () => {
    const tabUrlCache = new Map<string, string>();

    tabUrlCache.set("TAB_A", "https://gumroad.com/login");
    tabUrlCache.set("TAB_B", "https://evil.com/login");

    const credential = await readCredentialFile(tmpDir, "gumroad-login", passphrase);

    // Tab A should work
    const resultA = resolveBrowserPassword(
      "$vault:gumroad-login",
      tabUrlCache.get("TAB_A")!,
      credential,
      [".gumroad.com"]
    );
    expect(resultA.allowed).toBe(true);

    // Tab B should block
    const resultB = resolveBrowserPassword(
      "$vault:gumroad-login",
      tabUrlCache.get("TAB_B")!,
      credential,
      [".gumroad.com"]
    );
    expect(resultB.allowed).toBe(false);
  });
});

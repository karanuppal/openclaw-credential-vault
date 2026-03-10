/**
 * Phase 5: Audit Logging Tests
 *
 * Validates spec section "Audit Logging" (Phase 3C):
 * - credential_access events logged in after_tool_call
 * - scrub events logged when scrubber fires and replaces content
 * - JSONL format (one event per line)
 * - Events match spec JSON examples exactly
 *
 * Spec ref: "Audit Logging" section with credential_access + scrub event schemas
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// --- Mock types for audit logging (NOT BUILT yet) ---
// TODO: Replace with actual imports once audit logging is implemented in src/index.ts

interface CredentialAccessEvent {
  type: "credential_access";
  timestamp: string; // ISO 8601
  tool: string;
  credential: string;
  injectionType: "exec-env" | "http-header" | "browser-password" | "browser-cookie";
  command: string;
  sessionKey: string;
  durationMs: number;
  success: boolean;
}

interface ScrubEvent {
  type: "scrub";
  timestamp: string;
  hook: string;
  credential: string;
  pattern: string;
  replacements: number;
  sessionKey: string;
}

type AuditEvent = CredentialAccessEvent | ScrubEvent;

/**
 * Simulates the audit logger that appends events to JSONL file.
 * TODO: Replace with actual AuditLogger class when implemented.
 */
class MockAuditLogger {
  private logPath: string;

  constructor(logPath: string) {
    this.logPath = logPath;
  }

  logCredentialAccess(event: Omit<CredentialAccessEvent, "type">): void {
    const entry: CredentialAccessEvent = { type: "credential_access", ...event };
    fs.appendFileSync(this.logPath, JSON.stringify(entry) + "\n");
  }

  logScrub(event: Omit<ScrubEvent, "type">): void {
    const entry: ScrubEvent = { type: "scrub", ...event };
    fs.appendFileSync(this.logPath, JSON.stringify(entry) + "\n");
  }

  readEvents(): AuditEvent[] {
    if (!fs.existsSync(this.logPath)) return [];
    const content = fs.readFileSync(this.logPath, "utf-8").trim();
    if (!content) return [];
    return content.split("\n").map((line) => JSON.parse(line));
  }
}

describe("Audit Logging — credential_access events", () => {
  let tmpDir: string;
  let logPath: string;
  let logger: MockAuditLogger;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-audit-"));
    logPath = path.join(tmpDir, "audit.log");
    logger = new MockAuditLogger(logPath);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should log credential_access event matching spec schema", () => {
    logger.logCredentialAccess({
      timestamp: "2026-03-09T18:30:00Z",
      tool: "gh",
      credential: "github",
      injectionType: "exec-env",
      command: "gh pr list --repo openclaw/openclaw",
      sessionKey: "main:telegram:8603305068",
      durationMs: 1200,
      success: true,
    });

    const events = logger.readEvents();
    expect(events).toHaveLength(1);

    const event = events[0] as CredentialAccessEvent;
    expect(event.type).toBe("credential_access");
    expect(event.timestamp).toBe("2026-03-09T18:30:00Z");
    expect(event.tool).toBe("gh");
    expect(event.credential).toBe("github");
    expect(event.injectionType).toBe("exec-env");
    expect(event.command).toBe("gh pr list --repo openclaw/openclaw");
    expect(event.sessionKey).toBe("main:telegram:8603305068");
    expect(event.durationMs).toBe(1200);
    expect(event.success).toBe(true);
  });

  it("should log failed credential access", () => {
    logger.logCredentialAccess({
      timestamp: "2026-03-09T18:31:00Z",
      tool: "curl",
      credential: "stripe",
      injectionType: "exec-env",
      command: "curl https://api.stripe.com/v1/charges",
      sessionKey: "main:telegram:8603305068",
      durationMs: 50,
      success: false,
    });

    const events = logger.readEvents();
    expect(events).toHaveLength(1);
    expect((events[0] as CredentialAccessEvent).success).toBe(false);
  });

  it("should log http-header injection type", () => {
    logger.logCredentialAccess({
      timestamp: "2026-03-09T18:32:00Z",
      tool: "web_fetch",
      credential: "gumroad",
      injectionType: "http-header",
      command: "https://api.gumroad.com/v2/products",
      sessionKey: "main:telegram:8603305068",
      durationMs: 300,
      success: true,
    });

    const events = logger.readEvents();
    expect((events[0] as CredentialAccessEvent).injectionType).toBe("http-header");
  });
});

describe("Audit Logging — scrub events", () => {
  let tmpDir: string;
  let logPath: string;
  let logger: MockAuditLogger;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-audit-"));
    logPath = path.join(tmpDir, "audit.log");
    logger = new MockAuditLogger(logPath);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should log scrub event matching spec schema", () => {
    logger.logScrub({
      timestamp: "2026-03-09T18:30:01Z",
      hook: "after_tool_call",
      credential: "github",
      pattern: "ghp_[a-zA-Z0-9]{36}",
      replacements: 1,
      sessionKey: "main:telegram:8603305068",
    });

    const events = logger.readEvents();
    expect(events).toHaveLength(1);

    const event = events[0] as ScrubEvent;
    expect(event.type).toBe("scrub");
    expect(event.timestamp).toBe("2026-03-09T18:30:01Z");
    expect(event.hook).toBe("after_tool_call");
    expect(event.credential).toBe("github");
    expect(event.pattern).toBe("ghp_[a-zA-Z0-9]{36}");
    expect(event.replacements).toBe(1);
    expect(event.sessionKey).toBe("main:telegram:8603305068");
  });

  it("should log scrub events from different hooks", () => {
    const hooks = ["after_tool_call", "tool_result_persist", "message_sending"];
    for (const hook of hooks) {
      logger.logScrub({
        timestamp: new Date().toISOString(),
        hook,
        credential: "stripe",
        pattern: "sk_live_[a-zA-Z0-9]{24,}",
        replacements: 1,
        sessionKey: "main:telegram:8603305068",
      });
    }

    const events = logger.readEvents();
    expect(events).toHaveLength(3);
    expect(events.map((e) => (e as ScrubEvent).hook)).toEqual(hooks);
  });

  it("should track multiple replacements in a single scrub", () => {
    logger.logScrub({
      timestamp: "2026-03-09T18:30:02Z",
      hook: "after_tool_call",
      credential: "stripe",
      pattern: "sk_live_[a-zA-Z0-9]{24,}",
      replacements: 3,
      sessionKey: "main:telegram:8603305068",
    });

    const events = logger.readEvents();
    expect((events[0] as ScrubEvent).replacements).toBe(3);
  });
});

describe("Audit Logging — JSONL format", () => {
  let tmpDir: string;
  let logPath: string;
  let logger: MockAuditLogger;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-audit-"));
    logPath = path.join(tmpDir, "audit.log");
    logger = new MockAuditLogger(logPath);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should write one JSON object per line", () => {
    logger.logCredentialAccess({
      timestamp: "2026-03-09T18:30:00Z",
      tool: "gh",
      credential: "github",
      injectionType: "exec-env",
      command: "gh pr list",
      sessionKey: "main:telegram:8603305068",
      durationMs: 100,
      success: true,
    });

    logger.logScrub({
      timestamp: "2026-03-09T18:30:01Z",
      hook: "after_tool_call",
      credential: "github",
      pattern: "ghp_[a-zA-Z0-9]{36}",
      replacements: 1,
      sessionKey: "main:telegram:8603305068",
    });

    const raw = fs.readFileSync(logPath, "utf-8");
    const lines = raw.trim().split("\n");
    expect(lines).toHaveLength(2);

    // Each line should be valid JSON
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  it("should preserve event order (append-only)", () => {
    for (let i = 0; i < 5; i++) {
      logger.logCredentialAccess({
        timestamp: `2026-03-09T18:30:0${i}Z`,
        tool: "gh",
        credential: "github",
        injectionType: "exec-env",
        command: `command_${i}`,
        sessionKey: "main:telegram:8603305068",
        durationMs: i * 100,
        success: true,
      });
    }

    const events = logger.readEvents();
    expect(events).toHaveLength(5);
    for (let i = 0; i < 5; i++) {
      expect((events[i] as CredentialAccessEvent).command).toBe(`command_${i}`);
    }
  });

  it("should interleave credential_access and scrub events", () => {
    logger.logCredentialAccess({
      timestamp: "2026-03-09T18:30:00Z",
      tool: "gh",
      credential: "github",
      injectionType: "exec-env",
      command: "gh pr list",
      sessionKey: "main:telegram:8603305068",
      durationMs: 100,
      success: true,
    });

    logger.logScrub({
      timestamp: "2026-03-09T18:30:01Z",
      hook: "after_tool_call",
      credential: "github",
      pattern: "ghp_[a-zA-Z0-9]{36}",
      replacements: 2,
      sessionKey: "main:telegram:8603305068",
    });

    logger.logCredentialAccess({
      timestamp: "2026-03-09T18:30:02Z",
      tool: "curl",
      credential: "stripe",
      injectionType: "exec-env",
      command: "curl https://api.stripe.com/v1/charges",
      sessionKey: "main:telegram:8603305068",
      durationMs: 200,
      success: true,
    });

    const events = logger.readEvents();
    expect(events).toHaveLength(3);
    expect(events[0].type).toBe("credential_access");
    expect(events[1].type).toBe("scrub");
    expect(events[2].type).toBe("credential_access");
  });
});

/**
 * Tests for Phase 3C: Audit logging module.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import {
  writeAuditEvent,
  logCredentialAccess,
  logScrubEvent,
  logCompactionEvent,
  readAuditLog,
  computeAuditStats,
  parseDuration,
  getAuditLogPath,
} from "../src/audit.js";
import { AuditEvent } from "../src/types.js";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vault-audit-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("parseDuration", () => {
  it("should parse minutes", () => {
    expect(parseDuration("30m")).toBe(30 * 60 * 1000);
  });

  it("should parse hours", () => {
    expect(parseDuration("24h")).toBe(24 * 60 * 60 * 1000);
  });

  it("should parse days", () => {
    expect(parseDuration("7d")).toBe(7 * 24 * 60 * 60 * 1000);
  });

  it("should throw on invalid format", () => {
    expect(() => parseDuration("invalid")).toThrow();
    expect(() => parseDuration("24x")).toThrow();
  });
});

describe("writeAuditEvent", () => {
  it("should write a JSONL event to audit.log", () => {
    const event: AuditEvent = {
      type: "credential_access",
      timestamp: "2026-03-09T18:30:00Z",
      tool: "gh",
      credential: "github",
      injectionType: "exec-env",
      command: "gh pr list",
      sessionKey: "main:telegram:8603305068",
      durationMs: 1200,
      success: true,
    };

    writeAuditEvent(event, tmpDir);

    const logPath = getAuditLogPath(tmpDir);
    expect(fs.existsSync(logPath)).toBe(true);

    const content = fs.readFileSync(logPath, "utf8");
    const parsed = JSON.parse(content.trim());
    expect(parsed.type).toBe("credential_access");
    expect(parsed.tool).toBe("gh");
    expect(parsed.credential).toBe("github");
  });

  it("should append multiple events (not overwrite)", () => {
    logCredentialAccess({
      tool: "gh", credential: "github", injectionType: "exec-env",
      command: "gh pr list", durationMs: 100, success: true,
    }, tmpDir);

    logScrubEvent({
      hook: "after_tool_call", credential: "github",
      pattern: "ghp_[a-zA-Z0-9]{36}", replacements: 1,
    }, tmpDir);

    const events = readAuditLog({}, tmpDir);
    expect(events.length).toBe(2);
    expect(events[0].type).toBe("credential_access");
    expect(events[1].type).toBe("scrub");
  });

  it("should set file permissions to 0600", () => {
    logCredentialAccess({
      tool: "gh", credential: "github", injectionType: "exec-env",
      command: "test", durationMs: 0, success: true,
    }, tmpDir);

    const logPath = getAuditLogPath(tmpDir);
    const stat = fs.statSync(logPath);
    expect((stat.mode & 0o777).toString(8)).toBe("600");
  });
});

describe("logCredentialAccess", () => {
  it("should write a credential_access event with correct format", () => {
    logCredentialAccess({
      tool: "gh",
      credential: "github",
      injectionType: "exec-env",
      command: "gh pr list --repo test/test",
      sessionKey: "main:telegram:123",
      durationMs: 500,
      success: true,
    }, tmpDir);

    const events = readAuditLog({}, tmpDir);
    expect(events.length).toBe(1);
    const e = events[0];
    expect(e.type).toBe("credential_access");
    if (e.type === "credential_access") {
      expect(e.tool).toBe("gh");
      expect(e.credential).toBe("github");
      expect(e.injectionType).toBe("exec-env");
      expect(e.command).toBe("gh pr list --repo test/test");
      expect(e.sessionKey).toBe("main:telegram:123");
      expect(e.durationMs).toBe(500);
      expect(e.success).toBe(true);
      expect(e.timestamp).toBeTruthy();
    }
  });
});

describe("logScrubEvent", () => {
  it("should write a scrub event with correct format", () => {
    logScrubEvent({
      hook: "after_tool_call",
      credential: "github",
      pattern: "ghp_[a-zA-Z0-9]{36}",
      replacements: 2,
      sessionKey: "main:telegram:123",
    }, tmpDir);

    const events = readAuditLog({}, tmpDir);
    expect(events.length).toBe(1);
    const e = events[0];
    expect(e.type).toBe("scrub");
    if (e.type === "scrub") {
      expect(e.hook).toBe("after_tool_call");
      expect(e.credential).toBe("github");
      expect(e.pattern).toBe("ghp_[a-zA-Z0-9]{36}");
      expect(e.replacements).toBe(2);
    }
  });
});

describe("logCompactionEvent", () => {
  it("should write a compaction event", () => {
    logCompactionEvent({ scrubbingActive: true, sessionKey: "test" }, tmpDir);

    const events = readAuditLog({}, tmpDir);
    expect(events.length).toBe(1);
    const e = events[0];
    expect(e.type).toBe("compaction");
    if (e.type === "compaction") {
      expect(e.scrubbingActive).toBe(true);
    }
  });
});

describe("readAuditLog", () => {
  beforeEach(() => {
    // Write some events
    logCredentialAccess({
      tool: "gh", credential: "github", injectionType: "exec-env",
      command: "gh pr list", durationMs: 100, success: true,
    }, tmpDir);
    logScrubEvent({
      hook: "after_tool_call", credential: "github",
      pattern: "ghp_pattern", replacements: 1,
    }, tmpDir);
    logCredentialAccess({
      tool: "curl", credential: "stripe", injectionType: "http-header",
      command: "curl api.stripe.com", durationMs: 200, success: true,
    }, tmpDir);
    logCompactionEvent({ scrubbingActive: true }, tmpDir);
  });

  it("should return all events without filters", () => {
    const events = readAuditLog({ limit: 100 }, tmpDir);
    expect(events.length).toBe(4);
  });

  it("should filter by type", () => {
    const events = readAuditLog({ type: "credential_access", limit: 100 }, tmpDir);
    expect(events.length).toBe(2);
    expect(events.every(e => e.type === "credential_access")).toBe(true);
  });

  it("should filter by tool", () => {
    const events = readAuditLog({ tool: "github", limit: 100 }, tmpDir);
    expect(events.length).toBe(2); // 1 access + 1 scrub for github
  });

  it("should apply default limit of 50", () => {
    const events = readAuditLog({}, tmpDir);
    expect(events.length).toBeLessThanOrEqual(50);
  });

  it("should return empty array for non-existent log", () => {
    const events = readAuditLog({}, "/tmp/nonexistent-vault-dir");
    expect(events).toEqual([]);
  });
});

describe("computeAuditStats", () => {
  beforeEach(() => {
    logCredentialAccess({
      tool: "gh", credential: "github", injectionType: "exec-env",
      command: "gh pr list", durationMs: 100, success: true,
    }, tmpDir);
    logCredentialAccess({
      tool: "gh", credential: "github", injectionType: "exec-env",
      command: "gh issue list", durationMs: 150, success: true,
    }, tmpDir);
    logScrubEvent({
      hook: "after_tool_call", credential: "github",
      pattern: "ghp_pattern", replacements: 1,
    }, tmpDir);
    logScrubEvent({
      hook: "before_message_write", credential: "stripe",
      pattern: "sk_live_pattern", replacements: 2,
    }, tmpDir);
    logCompactionEvent({ scrubbingActive: true }, tmpDir);
  });

  it("should compute correct totals", () => {
    const stats = computeAuditStats(tmpDir);
    expect(stats.totalEvents).toBe(5);
    expect(stats.credentialAccesses).toBe(2);
    expect(stats.scrubEvents).toBe(2);
    expect(stats.compactionEvents).toBe(1);
  });

  it("should compute per-tool stats", () => {
    const stats = computeAuditStats(tmpDir);
    expect(stats.byTool.github.accesses).toBe(2);
    expect(stats.byTool.github.scrubs).toBe(1);
    expect(stats.byTool.github.lastAccess).toBeTruthy();
    expect(stats.byTool.stripe.scrubs).toBe(1);
  });

  it("should compute per-hook scrub stats", () => {
    const stats = computeAuditStats(tmpDir);
    expect(stats.byHook["after_tool_call"]).toBe(1);
    expect(stats.byHook["before_message_write"]).toBe(1);
  });
});
